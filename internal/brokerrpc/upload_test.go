// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/rclone/rclone/fs/fserrors"
)

// TestIsPipeClosure pins the pipe-closure classifier: io.ErrClosedPipe (and any
// error wrapping it) is the broker-ended-the-request-early symptom that must be
// swallowed when the HTTP status already carried the verdict, while every other
// error is a real local fault the upload path must surface.
func TestIsPipeClosure(t *testing.T) {
	if !isPipeClosure(io.ErrClosedPipe) {
		t.Fatal("isPipeClosure(io.ErrClosedPipe) = false; want true")
	}
	if !isPipeClosure(fmt.Errorf("write file part: %w", io.ErrClosedPipe)) {
		t.Fatal("isPipeClosure of a wrapped ErrClosedPipe = false; want true")
	}
	if isPipeClosure(io.EOF) {
		t.Fatal("isPipeClosure(io.EOF) = true; want false (EOF is not a pipe closure)")
	}
	if isPipeClosure(nil) {
		t.Fatal("isPipeClosure(nil) = true; want false")
	}
}

// parsedUpload holds the multipart fields a test handler reassembled from an
// upload request: the params JSON and the file bytes.
type parsedUpload struct {
	params   []byte
	fileData []byte
}

// parseMultipartUpload reads the multipart body of an upload request and returns
// the "params" field bytes and the reassembled file part. It tolerates the
// part ordering produced by the client (params first, then file).
func parseMultipartUpload(t *testing.T, r *http.Request) parsedUpload {
	t.Helper()
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type: %v", err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatal("multipart upload has no boundary")
	}
	mr := multipart.NewReader(r.Body, boundary)
	var out parsedUpload
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		data, _ := io.ReadAll(part)
		switch part.FormName() {
		case "params":
			out.params = data
		case "file":
			out.fileData = data
		}
	}
	return out
}

// TestUploadRouteHeadersAndParams verifies the upload POSTs to the REST route
// with the Bearer header, carries a multipart 'params' field with the correct
// fsID/path/declared_size/intent, and round-trips the file bytes.
func TestUploadRouteHeadersAndParams(t *testing.T) {
	var gotPath, gotAuth string
	var parsed parsedUpload
	content := []byte("hello world") // 11 bytes

	c, _ := newTLSTestClient(t, "fs-up-01", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		parsed = parseMultipartUpload(t, r)
		w.WriteHeader(http.StatusOK)
	})

	if err := c.Upload(context.Background(), "/b.txt", bytes.NewReader(content), int64(len(content)), false); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if gotPath != "/v1/filestore/fs/fileUpload" {
		t.Errorf("path = %q, want /v1/filestore/fs/fileUpload", gotPath)
	}
	if gotAuth != "Bearer "+testAuthToken {
		t.Errorf("Authorization = %q, want Bearer %s", gotAuth, testAuthToken)
	}
	if !bytes.Equal(parsed.fileData, content) {
		t.Errorf("file part = %q, want %q", parsed.fileData, content)
	}

	var p struct {
		FilesystemID      string                `json:"filesystem_id"`
		Path              string                `json:"path"`
		DeclaredSizeBytes int64                 `json:"declared_size_bytes"`
		OverwriteExisting bool                  `json:"overwrite_existing"`
		AuthMeta          AuthorizationMetadata `json:"authorization_metadata"`
	}
	if err := json.Unmarshal(parsed.params, &p); err != nil {
		t.Fatalf("parse params: %v", err)
	}
	if p.FilesystemID != "fs-up-01" {
		t.Errorf("params fsID = %q, want fs-up-01", p.FilesystemID)
	}
	if p.Path != "/b.txt" {
		t.Errorf("params path = %q, want /b.txt", p.Path)
	}
	if p.DeclaredSizeBytes != int64(len(content)) {
		t.Errorf("declared_size_bytes = %d, want %d", p.DeclaredSizeBytes, len(content))
	}
	if p.OverwriteExisting {
		t.Error("overwrite_existing = true, want false for a create-new upload")
	}
	if p.AuthMeta.Intent != "write" {
		t.Errorf("intent = %q, want write", p.AuthMeta.Intent)
	}
	if p.AuthMeta.Downloadable {
		t.Error("downloadable = true, must be false")
	}
}

// TestUploadLargeSourceRoundTrips verifies that a source larger than the message
// ceiling still round-trips byte-identical (chunked file-part writes reassemble
// to the exact source).
func TestUploadLargeSourceRoundTrips(t *testing.T) {
	const ceiling = 64
	content := bytes.Repeat([]byte("ab"), ceiling*4+9) // definitely >1 chunk
	var got []byte

	c := newTLSTestClientOpts(t, "fs-up-big", ClientOptions{MessageCeiling: ceiling}, func(w http.ResponseWriter, r *http.Request) {
		got = parseMultipartUpload(t, r).fileData
		w.WriteHeader(http.StatusOK)
	})

	if err := c.Upload(context.Background(), "/d.bin", bytes.NewReader(content), int64(len(content)), false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("large source did not round-trip byte-identical: got %d bytes, want %d", len(got), len(content))
	}
}

// TestUploadZeroByteRoundTrips verifies the empty-file boundary: a zero-length
// source with declared size 0 succeeds and the file part is empty.
func TestUploadZeroByteRoundTrips(t *testing.T) {
	var parsed parsedUpload
	c, _ := newTLSTestClient(t, "fs-up-zero", func(w http.ResponseWriter, r *http.Request) {
		parsed = parseMultipartUpload(t, r)
		w.WriteHeader(http.StatusOK)
	})
	if err := c.Upload(context.Background(), "/empty.txt", bytes.NewReader(nil), 0, false); err != nil {
		t.Fatalf("zero-byte upload must succeed: %v", err)
	}
	if len(parsed.fileData) != 0 {
		t.Errorf("file part = %d bytes, want 0", len(parsed.fileData))
	}
	var p struct {
		DeclaredSizeBytes int64 `json:"declared_size_bytes"`
	}
	_ = json.Unmarshal(parsed.params, &p)
	if p.DeclaredSizeBytes != 0 {
		t.Errorf("declared_size_bytes = %d, want 0", p.DeclaredSizeBytes)
	}
}

// TestUploadOverwriteTrueRoundTrips verifies an overwrite-in-place upload sets
// overwrite_existing=true on the params field.
func TestUploadOverwriteTrueRoundTrips(t *testing.T) {
	var parsed parsedUpload
	c, _ := newTLSTestClient(t, "fs-up-ow", func(w http.ResponseWriter, r *http.Request) {
		parsed = parseMultipartUpload(t, r)
		w.WriteHeader(http.StatusOK)
	})
	if err := c.Upload(context.Background(), "/ow.txt", bytes.NewReader([]byte("y")), 1, true); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	var p struct {
		OverwriteExisting bool `json:"overwrite_existing"`
	}
	if err := json.Unmarshal(parsed.params, &p); err != nil {
		t.Fatalf("parse params: %v", err)
	}
	if !p.OverwriteExisting {
		t.Error("overwrite_existing = false, want true for an overwrite-in-place upload")
	}
}

// TestUploadThrottledIsRetryable verifies that a 429 from the broker maps to a
// retryable error (SEC-46 backpressure), and that a re-driven upload after the
// throttle sends byte-identical content (SC2).
func TestUploadThrottledIsRetryable(t *testing.T) {
	var attempt int
	var firstBody, secondBody []byte
	content := bytes.Repeat([]byte("Z"), 4096)

	c, _ := newTLSTestClient(t, "fs-up-429", func(w http.ResponseWriter, r *http.Request) {
		data := parseMultipartUpload(t, r).fileData
		attempt++
		if attempt == 1 {
			firstBody = data
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("throttled"))
			return
		}
		secondBody = data
		w.WriteHeader(http.StatusOK)
	})

	err := c.Upload(context.Background(), "/e.bin", bytes.NewReader(content), int64(len(content)), false)
	if err == nil {
		t.Fatal("expected retryable throttle error on first attempt, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Errorf("429 from upload must be retryable: %v", err)
	}

	// The pacer would re-drive the upload; simulate the retry with a fresh source.
	if err := c.Upload(context.Background(), "/e.bin", bytes.NewReader(content), int64(len(content)), false); err != nil {
		t.Fatalf("retried upload: %v", err)
	}
	if !bytes.Equal(firstBody, content) || !bytes.Equal(secondBody, content) {
		t.Error("upload content was not byte-identical across the throttle retry (SC2)")
	}
}

// TestUploadSizeMismatchIsPermanent verifies a broker 400 (size policy) maps to
// a permanent no-retry error.
func TestUploadSizeMismatchIsPermanent(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-up-400", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("size_exceeded"))
	})
	err := c.Upload(context.Background(), "/f.txt", bytes.NewReader([]byte("x")), 99, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if fserrors.IsRetryError(err) {
		t.Errorf("size policy 400 must NOT be retryable: %v", err)
	}
}

// TestUploadForbiddenMapsToPermissionDenied drives the upload non-2xx arm with a
// 403 and asserts the typed permission-denied sentinel (not just non-nil).
func TestUploadForbiddenMapsToPermissionDenied(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-up-403", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("foreign scope"))
	})
	err := c.Upload(context.Background(), "/f.txt", bytes.NewReader([]byte("data")), 4, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("403 upload must map to ErrPermissionDenied; got %v", err)
	}
}

// TestUploadResponseBodyReadErrorSurfacesOn2xx drives the readErr != nil arm of
// Upload: the broker returns 2xx but the response body read fails (the handler
// promises a long Content-Length then hangs up), which surfaces as a
// read-response-body error rather than a silent success.
func TestUploadResponseBodyReadErrorSurfacesOn2xx(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-up-readerr", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, herr := hj.Hijack()
			if herr == nil {
				_ = conn.Close()
			}
		}
	})
	err := c.Upload(context.Background(), "/f.txt", bytes.NewReader([]byte("data")), 4, false)
	if err == nil {
		t.Fatal("expected a 2xx-with-body-read-failure error, got nil")
	}
	if !strings.Contains(err.Error(), "fileUpload") {
		t.Errorf("error %q does not name fileUpload", err.Error())
	}
}

// TestUploadMidStreamSourceFaultSurfaces drives the file-part write branch in
// writeUploadMultipart: a source reader that yields some bytes then errors makes
// the streamed file part fail mid-write, and on a 2xx that genuine (non-pipe)
// write fault surfaces. midErrReader is distinct from errReader (which fails on
// the first read) so the file-chunk write path actually executes before failing.
func TestUploadMidStreamSourceFaultSurfaces(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-up-midfault", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	src := &midErrReader{prefix: bytes.Repeat([]byte("a"), 16)}
	err := c.Upload(context.Background(), "/f.txt", src, 16, false)
	if err == nil {
		t.Fatal("expected a mid-stream source fault to surface, got nil")
	}
	if !strings.Contains(err.Error(), "write body") && !strings.Contains(err.Error(), "read source") {
		t.Errorf("error %q does not mention the write/read fault", err.Error())
	}
}

// midErrReader yields its prefix once, then returns a forced error on the next
// read so the file part is partly written before the source faults.
type midErrReader struct {
	prefix []byte
	sent   bool
}

func (m *midErrReader) Read(p []byte) (int, error) {
	if !m.sent {
		m.sent = true
		n := copy(p, m.prefix)
		return n, nil
	}
	return 0, errors.New("midErrReader: forced mid-stream failure")
}
