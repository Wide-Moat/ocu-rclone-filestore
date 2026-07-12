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

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/httpjson"
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
		httpjson.Error(w, http.StatusUnauthorized, "missing or unknown credential")
		return
	}

	// The parse is bounded: 1 MiB of in-memory form parts; the file part itself
	// is separately capped by maxUploadBytes when copied below.
	if err := r.ParseMultipartForm(1 << 20); err != nil { //nolint:gosec // G120: the in-memory budget is bounded and the file copy is LimitReader-capped
		httpjson.Error(w, http.StatusBadRequest, "malformed multipart body")
		return
	}

	rawParams := r.FormValue("params")
	if rawParams == "" {
		httpjson.Error(w, http.StatusBadRequest, "missing params field")
		return
	}
	var params uploadParams
	if err := json.Unmarshal([]byte(rawParams), &params); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed params field")
		return
	}

	scope, status, msg := s.authorize(opFileUpload, subjectFSID, params.FilesystemID)
	if status != 0 {
		httpjson.Error(w, status, msg)
		return
	}

	// Stage-0 per-op ceiling: an upload to the throttled scope costs one token
	// like any other op. An over-budget upload is refused with the unmapped
	// throttle status (the guest surfaces it as a non-retryable EIO) before the
	// destination is touched.
	if !s.chargePerOp(params.FilesystemID) {
		httpjson.Error(w, throttleRefusalStatus, "per-op ceiling exceeded; back off and retry")
		return
	}

	// Throttle decision happens after auth so an unauthorised caller is never
	// told to back off, and before the write so a throttled upload leaves the
	// destination untouched.
	if s.throttled() {
		w.Header().Set("Retry-After", "1")
		httpjson.Error(w, http.StatusTooManyRequests, "throttled; retry after backoff")
		return
	}

	abs, err := resolveUnder(scope.Root, params.Path)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}

	part, _, err := r.FormFile("file")
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "missing file part")
		return
	}
	defer func() { _ = part.Close() }()

	if !params.OverwriteExisting {
		if _, statErr := os.Stat(abs); statErr == nil {
			httpjson.Error(w, http.StatusConflict, "destination exists")
			return
		}
	}
	if mkErr := os.MkdirAll(filepath.Dir(abs), 0o750); mkErr != nil {
		httpjson.Error(w, http.StatusInternalServerError, "mkdir parent failed")
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
		httpjson.Error(w, http.StatusInternalServerError, "write failed")
		return
	}
	if closeErr != nil {
		httpjson.Error(w, http.StatusInternalServerError, "close failed")
		return
	}

	// The broker assembles the object only when the streamed total matches the
	// declared size; a mismatch is a permanent (non-retryable) client fault. The
	// check is unconditional: a declared 0 must match an ACTUAL 0-byte stream, so
	// a non-empty body sent against declared_size_bytes=0 (or an omitted field
	// defaulting to 0) is rejected rather than silently accepted.
	if written != params.DeclaredSizeBytes {
		_ = os.Remove(abs)
		httpjson.Error(w, http.StatusUnprocessableEntity, "streamed size does not match declared size")
		return
	}

	size, mtime, mode, uuid, statErr := fileMeta(scope, params.Path, abs)
	if statErr != nil {
		writeMetaError(w, statErr)
		return
	}
	httpjson.OK(w, struct {
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
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	if db.UUID == "" {
		httpjson.Error(w, http.StatusBadRequest, "uuid is required")
		return
	}

	rel, ok := relPathForUUID(scope, db.UUID)
	if !ok {
		httpjson.Error(w, http.StatusNotFound, "not found")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}

	f, openErr := os.Open(abs) //nolint:gosec // G304: abs is traversal-guarded by resolveUnder, confined to the scope volume
	if openErr != nil {
		writeMetaError(w, openErr)
		return
	}
	defer func() { _ = f.Close() }()
	info, statErr := f.Stat()
	if statErr != nil {
		writeMetaError(w, statErr)
		return
	}
	total := info.Size()

	// Resolve the optional byte window against the file size WITHOUT reading the
	// file. An out-of-range offset yields an empty body rather than an error,
	// matching a broker that seeks past EOF. Streaming the window (rather than
	// os.ReadFile + slice) keeps a large object off the heap.
	start, length := int64(0), total
	if db.Range != nil {
		if db.Range.Offset < 0 || db.Range.Length < 0 {
			httpjson.Error(w, http.StatusBadRequest, "negative range")
			return
		}
		start = db.Range.Offset
		if start > total {
			start = total
		}
		// The offset/length window is caller-supplied and schema-legal at the
		// extreme, but start+length must be representable. Both start and Length are
		// non-negative here (start clamped to [0,total], Length guarded >= 0 above),
		// so a sum that wraps below start is an int64 overflow: an unsatisfiable
		// range, mapped to 400 like the negative-range arm rather than a 200 with a
		// negative Content-Length and an empty body.
		end := start + db.Range.Length
		if end < start {
			httpjson.Error(w, http.StatusBadRequest, "range overflows")
			return
		}
		if end > total {
			end = total
		}
		length = end - start
	}

	if start > 0 {
		if _, seekErr := f.Seek(start, io.SeekStart); seekErr != nil {
			writeMetaError(w, seekErr)
			return
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(http.StatusOK)
	// Stream exactly length bytes from the seek point. A short copy (file
	// truncated mid-stream) just ends the body; the client's own bounded reader
	// governs its side.
	_, _ = io.CopyN(w, f, length)
}
