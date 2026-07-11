// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — REST fileUpload transport.
//
// The fileUpload op is a multipart/form-data POST to
// <service_url>/v1/filestore/fs/fileUpload:
//
//  1. One form field named "params" carrying the JSON params object:
//     declared_size_bytes (required, = total source size), filesystem_id, path,
//     optional overwrite_existing, and authorization_metadata{intent:write,
//     downloadable:false}.
//
//  2. One file part streaming the source bytes. The source is read in
//     ceiling-bounded chunks so a single read never exceeds the message
//     ceiling; the SC2 invariant (byte-identical content under a 429 retry)
//     holds because the multipart body is rebuilt from the same source on each
//     attempt.
//
// Success or failure is the HTTP status: a non-2xx response maps through
// MapHTTPStatus (429 → retryable, honouring Retry-After); a 2xx is success.

package brokerrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

// Upload performs the fileUpload op. It reads all bytes from src and sends them
// as the file part of a multipart/form-data body, preceded by a "params" field
// carrying the total source size as declared_size_bytes. The broker assembles
// the object only when the streamed total matches declared_size_bytes; a
// mismatch in either direction results in a 400/422 from the broker, which the
// mapper returns as a permanent no-retry error. path is the filesystem-relative
// destination path. overwrite selects whether an existing destination is
// replaced in place (true, the overwrite-in-place write) or the upload fails on
// a present path (false, the create-new write).
func (c *Client) Upload(ctx context.Context, path string, src io.Reader, totalBytes int64, overwrite bool) error {
	fsID, am, err := c.stamp(OpFileUpload)
	if err != nil {
		return err
	}

	// Build the multipart body as a pipe so the writer and the HTTP sender run
	// concurrently without buffering the full payload.
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	// errCh carries the body-writing error so the goroutine result is
	// propagated back to the caller.
	errCh := make(chan error, 1)
	go func() {
		err := writeUploadMultipart(mw, fsID, path, totalBytes, overwrite, am, src, c.messageCeiling)
		// Close the multipart writer (emits the closing boundary) before closing
		// the pipe so a well-formed body is flushed on the success path.
		if cerr := mw.Close(); err == nil {
			err = cerr
		}
		// CloseWithError(nil) is equivalent to Close: it surfaces io.EOF to the
		// reader, ending the request body cleanly.
		_ = pw.CloseWithError(err)
		errCh <- err
	}()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opURL(OpFileUpload), pr)
	if err != nil {
		// Nothing will read pr on this path, so the writer goroutine would block
		// forever on mw.Write. Close the read end (unblocking the writer with
		// io.ErrClosedPipe) and drain errCh so the goroutine exits cleanly.
		_ = pr.CloseWithError(err)
		<-errCh
		return fmt.Errorf("brokerrpc: build upload request: %w", err)
	}
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())
	c.setAuthHeader(httpReq)

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		// The transport failed (dial/TLS/etc.). Drain the writer goroutine so it
		// does not leak, then surface the transport error.
		<-errCh
		return fmt.Errorf("brokerrpc: fileUpload: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Bounded read: only a diagnostics-sized prefix of the body is ever kept
	// (the shared maxErrorBodyBytes budget — the body is diagnostics on both
	// branches; the HTTP status is authoritative). Consequence on the 2xx
	// branch: a transport failure occurring PAST the cap is invisible here —
	// the LimitReader ends the read cleanly at the cap — so the call reports
	// success on the strength of the 2xx status alone. That is the intended
	// semantics: the broker committed the upload when it issued the 2xx, and
	// the remainder of the body carries no data the guest acts on.
	respBody, readErr := io.ReadAll(io.LimitReader(httpResp.Body, maxErrorBodyBytes))

	// Collect the body-writing result (blocks until the goroutine finishes).
	writeErr := <-errCh

	// Success/failure is the HTTP status. A non-2xx is authoritative and must be
	// preferred over a writer-pipe error: when the broker terminates early — the
	// SEC-46 429 throttle case, a permission failure — it replies without
	// draining the request body, the transport closes the pipe, and the writer
	// goroutine fails with io.ErrClosedPipe. That pipe-closure error must never
	// mask the retryable backpressure verdict the status carries.
	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		return MapHTTPStatus(httpResp.StatusCode, respBody, httpResp.Header.Get("Retry-After"))
	}

	// 2xx but the body read failed: surface it.
	if readErr != nil {
		return fmt.Errorf("brokerrpc: fileUpload read response body: %w", readErr)
	}

	// 2xx with a genuine write fault that is NOT a pipe closure surfaces as a
	// local error (the broker accepted, but the source could not be read).
	if writeErr != nil && !isPipeClosure(writeErr) {
		return fmt.Errorf("brokerrpc: fileUpload write body: %w", writeErr)
	}

	return nil
}

// isPipeClosure reports whether err is the io.ErrClosedPipe symptom of the
// broker ending the request early, which must not be treated as a real local
// fault when the HTTP status already carried the verdict.
func isPipeClosure(err error) bool {
	return errors.Is(err, io.ErrClosedPipe)
}

// sourceChunkSize returns the number of raw source bytes to read per file-part
// write so a single write stays under the message ceiling. The file part now
// streams raw bytes (no base64 expansion, no per-chunk JSON envelope), so the
// buffer is just the ceiling bounded below to guarantee forward progress even
// for a tiny ceiling.
func sourceChunkSize(ceiling int) int {
	if ceiling < 3 {
		return 3
	}
	return ceiling
}

// writeUploadMultipart writes the "params" form field followed by the file part
// streamed from src in ceiling-bounded reads. It writes exactly totalBytes
// bytes across the file part (the caller supplies a src that yields exactly that
// many bytes; a mismatch is detected broker-side).
func writeUploadMultipart(
	mw *multipart.Writer,
	fsID, path string,
	totalBytes int64,
	overwrite bool,
	am AuthorizationMetadata,
	src io.Reader,
	ceiling int,
) error {
	// Field 1: params (JSON). FileUploadRequest is the single wire declaration
	// for this body (messages.go); see its doc for the overwrite semantics.
	params := FileUploadRequest{
		FilesystemID:          fsID,
		Path:                  path,
		DeclaredSizeBytes:     totalBytes,
		OverwriteExisting:     overwrite,
		AuthorizationMetadata: am,
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	pf, err := mw.CreateFormField("params")
	if err != nil {
		return fmt.Errorf("create params field: %w", err)
	}
	if _, err := pf.Write(payload); err != nil {
		return fmt.Errorf("write params field: %w", err)
	}

	// Field 2: the file part, streamed in ceiling-bounded chunks. Sizing each
	// read keeps a single Write bounded so the message ceiling still governs the
	// per-write payload; the file part as a whole carries the exact source bytes.
	fp, err := mw.CreateFormFile("file", "upload")
	if err != nil {
		return fmt.Errorf("create file part: %w", err)
	}
	srcChunk := sourceChunkSize(ceiling)
	buf := make([]byte, srcChunk)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, werr := fp.Write(buf[:n]); werr != nil {
				return fmt.Errorf("write file chunk: %w", werr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read source: %w", readErr)
		}
	}
	return nil
}
