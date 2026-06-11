// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — client-streaming fileUpload transport.
//
// The fileUpload op follows the Connect client-streaming protocol:
//
//  1. POST /ocu.filestore.v1alpha.FilesystemService/fileUpload
//     Content-Type: application/connect+json
//     Connect-Protocol-Version: 1
//
//  2. Frame 1 (data flag 0x00): the params JSON object including
//     declared_size_bytes (required, = total source size), filesystem_id,
//     and authorization_metadata{intent:write, downloadable:false}.
//
//  3. Frames 2…N (data flag 0x00): {chunk: <base64 bytes>} frames, each sized
//     so the ENCODED frame payload stays strictly under MessageCeiling.
//
//  4. Half-close (EOF on the request body) signals completion.
//
//  5. The broker replies with HTTP 200 and an EndStreamResponse trailer frame
//     (flag 0x02). The caller must read this trailer for success/failure.

package brokerrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// uploadParamsFrame is the JSON body for the first frame in a fileUpload
// client-streaming request.
type uploadParamsFrame struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	DeclaredSizeBytes     int64                 `json:"declared_size_bytes"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// uploadChunkFrame is the JSON body for subsequent data frames.
type uploadChunkFrame struct {
	Chunk []byte `json:"chunk"`
}

// Upload performs the fileUpload client-streaming op. It reads all bytes from
// src and sends them as ceiling-sized chunk frames preceded by a params frame
// that carries the total source size as declared_size_bytes. The broker
// assembles the object only when the streamed total matches declared_size_bytes;
// a mismatch in either direction (over- or under-send) results in an
// invalid_argument error from the broker, which the mapper returns as a
// permanent no-retry error. path is the filesystem-relative destination path.
func (c *Client) Upload(ctx context.Context, path string, src io.Reader, totalBytes int64) error {
	fsID, am, err := c.stamp(OpFileUpload)
	if err != nil {
		return err
	}

	// Build the streaming request body as a pipe so the frame writer and the
	// HTTP sender run concurrently without buffering the full payload.
	pr, pw := io.Pipe()

	// errCh carries the frame-writing error so the goroutine result is
	// propagated back to the caller.
	errCh := make(chan error, 1)
	go func() {
		defer pw.Close() //nolint:errcheck
		errCh <- writeUploadFrames(pw, fsID, path, totalBytes, am, src, c.messageCeiling)
	}()

	url := streamingURL(OpFileUpload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		return fmt.Errorf("brokerrpc: build upload request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/connect+json")
	httpReq.Header.Set("Connect-Protocol-Version", "1")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("brokerrpc: fileUpload: %w", err)
	}
	defer httpResp.Body.Close() //nolint:errcheck

	// Collect the frame-writing result (blocks until the goroutine finishes).
	writeErr := <-errCh

	// Success/failure for streaming ops lives ONLY in the EndStreamResponse
	// trailer (the HTTP status is always 200 for streams). The trailer verdict
	// is authoritative and MUST be read and preferred before the writer-pipe
	// error is considered. When the broker terminates the stream early — the
	// SEC-46 resource_exhausted throttle case, a frame over the ceiling, or a
	// permission failure — it replies without draining the request body, the
	// transport closes the pipe, and the writer goroutine fails with
	// io.ErrClosedPipe. A parseable error trailer must never be masked by that
	// pipe-closure error, or the contractually retryable backpressure posture
	// (D4/SEC-46) is destroyed.
	// readUploadResult tolerates an optional response message frame (flag 0x00)
	// before the trailer, the standard Connect client-streaming success shape;
	// reading readEndStream directly would hard-fail on that leading frame.
	esr, trailerErr := readUploadResult(httpResp.Body)
	if trailerErr == nil && esr.Error != nil {
		retryAfterRaw := httpResp.Header.Get("Retry-After")
		return MapConnectError(esr.Error, retryAfterRaw)
	}

	// No authoritative error trailer. A genuine frame-writing failure now
	// surfaces — except a pipe closure, which is the expected symptom of the
	// broker ending the stream early rather than a real local write fault.
	if writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) {
		return fmt.Errorf("brokerrpc: fileUpload write frames: %w", writeErr)
	}

	// Trailer read failed and there is no clear write fault to report.
	if trailerErr != nil {
		return fmt.Errorf("brokerrpc: fileUpload read EndStreamResponse: %w", trailerErr)
	}

	// Parseable success trailer ({}); the upload completed.
	return nil
}

// jsonEnvelopeOverhead is the byte cost of the {"chunk":""} JSON wrapper around
// the base64 chunk payload, plus one byte of safety margin so the encoded frame
// payload stays strictly below the ceiling rather than equal to it.
const jsonEnvelopeOverhead = len(`{"chunk":""}`) + 1

// sourceChunkSize returns the number of raw source bytes to read per chunk so
// that the encoded {"chunk":"<base64>"} frame payload stays strictly under
// ceiling. Base64 encodes N source bytes (a multiple of 3) into 4*N/3
// characters with no padding, so the frame payload is
// jsonEnvelopeOverhead + 4*N/3. Solving 4*N/3 < ceiling-jsonEnvelopeOverhead
// and rounding N down to a multiple of 3 yields the value below. The result is
// always at least 3 so progress is guaranteed even for a tiny ceiling.
func sourceChunkSize(ceiling int) int {
	budget := ceiling - jsonEnvelopeOverhead
	n := 3 * (budget / 4)
	if n < 3 {
		n = 3
	}
	return n
}

// writeUploadFrames sends the params frame followed by ceiling-sized chunk
// frames to w, reading from src until EOF. It sends exactly totalBytes bytes
// across the chunk frames (the caller is responsible for supplying a src that
// yields exactly that many bytes; a mismatch will be detected broker-side).
func writeUploadFrames(
	w io.Writer,
	fsID, path string,
	totalBytes int64,
	am AuthorizationMetadata,
	src io.Reader,
	ceiling int,
) error {
	// Frame 1: params.
	params := uploadParamsFrame{
		FilesystemID:          fsID,
		Path:                  path,
		DeclaredSizeBytes:     totalBytes,
		AuthorizationMetadata: am,
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal params frame: %w", err)
	}
	if err := writeFrame(w, 0x00, payload); err != nil {
		return err
	}

	// Subsequent frames: read source in chunks sized so the ENCODED frame
	// payload stays strictly under the message ceiling. The chunk bytes are
	// JSON-encoded as base64 via Go's standard []byte marshalling: N source
	// bytes (a multiple of 3, so no base64 padding) become 4*N/3 base64
	// characters wrapped in the {"chunk":"..."} envelope. Sizing the read by
	// raw source bytes would push every full frame to ~4/3 of the ceiling and
	// deterministically draw resource_exhausted from the broker (D4).
	srcChunk := sourceChunkSize(ceiling)
	buf := make([]byte, srcChunk)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			chunk := uploadChunkFrame{Chunk: buf[:n]}
			payload, err = json.Marshal(chunk)
			if err != nil {
				return fmt.Errorf("marshal chunk frame: %w", err)
			}
			if err := writeFrame(w, 0x00, payload); err != nil {
				return err
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
