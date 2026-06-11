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
//  3. Frames 2…N (data flag 0x00): {chunk: <base64 bytes>} frames, each
//     containing at most MessageCeiling bytes of source data.
//
//  4. Half-close (EOF on the request body) signals completion.
//
//  5. The broker replies with HTTP 200 and an EndStreamResponse trailer frame
//     (flag 0x02). The caller must read this trailer for success/failure.

package brokerrpc

import (
	"context"
	"encoding/json"
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
	if writeErr := <-errCh; writeErr != nil {
		return fmt.Errorf("brokerrpc: fileUpload write frames: %w", writeErr)
	}

	// Success/failure for streaming ops lives ONLY in the EndStreamResponse
	// trailer. The HTTP status is always 200 for streams.
	esr, err := readEndStream(httpResp.Body)
	if err != nil {
		return fmt.Errorf("brokerrpc: fileUpload read EndStreamResponse: %w", err)
	}
	if esr.Error != nil {
		retryAfterRaw := httpResp.Header.Get("Retry-After")
		return MapConnectError(esr.Error, retryAfterRaw)
	}
	return nil
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

	// Subsequent frames: read chunks of at most ceiling bytes and send each
	// as a {chunk} frame. The chunk bytes are JSON-encoded as base64 via
	// Go's standard []byte marshalling.
	buf := make([]byte, ceiling)
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
