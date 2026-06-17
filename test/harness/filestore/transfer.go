// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// uploadParams mirrors the "params" JSON form field the guest writes for a
// fileUpload: the scope handle, the destination path, the declared total size,
// an optional overwrite flag, and the stamped authorization metadata.
type uploadParams struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	DeclaredSizeBytes     int64                 `json:"declared_size_bytes"`
	OverwriteExisting     bool                  `json:"overwrite_existing"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// downloadBody mirrors the guest's fileDownload JSON request: the scope handle,
// the broker-minted uuid (not a path), an optional byte range, and the stamped
// authorization metadata.
type downloadBody struct {
	FilesystemID          string                `json:"filesystem_id"`
	UUID                  string                `json:"uuid"`
	Range                 *rangeWindow          `json:"range,omitempty"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
}

// rangeWindow mirrors the guest's optional {offset, length} download window.
type rangeWindow struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// maxUploadBytes bounds the streamed file part so a malformed multipart body
// cannot exhaust the peer's memory. It is generous relative to any e2e fixture.
const maxUploadBytes int64 = 1 << 30 // 1 GiB

// handleFileUpload accepts the guest's multipart/form-data upload: a "params"
// JSON field carrying the scope handle and destination path, followed by a
// "file" part streaming the object bytes. It runs authentication and scope
// authorisation itself because the filesystem_id lives in the params field
// rather than a JSON body the router could pre-decode.
//
// When throttling is configured, every Nth upload is refused with 429 and a
// Retry-After header before the file is written, so the guest's backoff path can
// be exercised without corrupting the destination.
func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	subjectFSID, err := s.credentials.Validate(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing or unknown credential")
		return
	}

	// The parse is bounded: 1 MiB of in-memory form parts; the file part itself
	// is separately capped by maxUploadBytes when copied below.
	if err := r.ParseMultipartForm(1 << 20); err != nil { //nolint:gosec // G120: the in-memory budget is bounded and the file copy is LimitReader-capped
		writeError(w, http.StatusBadRequest, "malformed multipart body")
		return
	}

	rawParams := r.FormValue("params")
	if rawParams == "" {
		writeError(w, http.StatusBadRequest, "missing params field")
		return
	}
	var params uploadParams
	if err := json.Unmarshal([]byte(rawParams), &params); err != nil {
		writeError(w, http.StatusBadRequest, "malformed params field")
		return
	}

	scope, status, msg := s.authorize(opFileUpload, subjectFSID, params.FilesystemID)
	if status != 0 {
		writeError(w, status, msg)
		return
	}

	// Stage-0 per-op ceiling: an upload to the throttled scope costs one token
	// like any other op. An over-budget upload is refused with the unmapped
	// throttle status (the guest surfaces it as a non-retryable EIO) before the
	// destination is touched.
	if !s.chargePerOp(params.FilesystemID) {
		writeError(w, throttleRefusalStatus, "per-op ceiling exceeded; back off and retry")
		return
	}

	// Throttle decision happens after auth so an unauthorised caller is never
	// told to back off, and before the write so a throttled upload leaves the
	// destination untouched.
	if s.throttled() {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "throttled; retry after backoff")
		return
	}

	abs, err := resolveUnder(scope.Root, params.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "path escapes scope")
		return
	}

	part, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file part")
		return
	}
	defer func() { _ = part.Close() }()

	if !params.OverwriteExisting {
		if _, statErr := os.Stat(abs); statErr == nil {
			writeError(w, http.StatusConflict, "destination exists")
			return
		}
	}
	if mkErr := os.MkdirAll(filepath.Dir(abs), 0o750); mkErr != nil {
		writeError(w, http.StatusInternalServerError, "mkdir parent failed")
		return
	}

	f, err := os.OpenFile(abs, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: abs is traversal-guarded by resolveUnder, confined to the scope volume
	if err != nil {
		writeMetaError(w, err)
		return
	}
	written, copyErr := io.Copy(f, io.LimitReader(part, maxUploadBytes))
	closeErr := f.Close()
	if copyErr != nil {
		writeError(w, http.StatusInternalServerError, "write failed")
		return
	}
	if closeErr != nil {
		writeError(w, http.StatusInternalServerError, "close failed")
		return
	}

	// The broker assembles the object only when the streamed total matches the
	// declared size; a mismatch is a permanent (non-retryable) client fault.
	if params.DeclaredSizeBytes != 0 && written != params.DeclaredSizeBytes {
		_ = os.Remove(abs)
		writeError(w, http.StatusUnprocessableEntity, "streamed size does not match declared size")
		return
	}

	size, mtime, mode, uuid, statErr := fileMeta(scope, params.Path, abs)
	if statErr != nil {
		writeMetaError(w, statErr)
		return
	}
	writeJSON(w, struct {
		File wireFile `json:"file"`
	}{File: wireFile{Path: params.Path, Size: size, Mtime: mtime, Mode: mode, UUID: uuid}})
}

// throttled advances the write counter under the lock and reports whether this
// write should be refused with 429. When ThrottleEvery is 0 it never throttles.
func (s *Server) throttled() bool {
	if s.throttleEvery <= 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeCount++
	return s.writeCount%s.throttleEvery == 0
}

// handleFileDownload serves the object addressed by the request uuid as a
// chunked application/octet-stream body. The uuid is resolved back to a
// scope-relative path by scanning the scope volume; an optional {offset, length}
// window streams just that slice. The guest never derives scope from the uuid —
// the scope is fixed by the authorised filesystem_id.
func (s *Server) handleFileDownload(w http.ResponseWriter, scope Scope, body commonBody) {
	var db downloadBody
	if err := json.Unmarshal(body.raw, &db); err != nil {
		writeError(w, http.StatusBadRequest, "malformed body")
		return
	}
	if db.UUID == "" {
		writeError(w, http.StatusBadRequest, "uuid is required")
		return
	}

	rel, ok := relPathForUUID(scope, db.UUID)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		writeError(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	data, readErr := os.ReadFile(abs) //nolint:gosec // G304: abs is traversal-guarded by resolveUnder, confined to the scope volume
	if readErr != nil {
		writeMetaError(w, readErr)
		return
	}

	// Apply the optional byte window. An out-of-range offset yields an empty
	// body rather than an error, matching a broker that seeks past EOF.
	if db.Range != nil {
		if db.Range.Offset < 0 || db.Range.Length < 0 {
			writeError(w, http.StatusBadRequest, "negative range")
			return
		}
		start := db.Range.Offset
		if start > int64(len(data)) {
			start = int64(len(data))
		}
		end := start + db.Range.Length
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		data = data[start:end]
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
