// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — server-streaming fileDownload transport.
//
// The fileDownload op follows the Connect server-streaming protocol:
//
//  1. POST /ocu.filestore.v1alpha.FilesystemService/fileDownload
//     Content-Type: application/connect+json
//     Connect-Protocol-Version: 1
//     Request body: a single framed JSON object (params frame) carrying
//     filesystem_id, uuid (NOT path — broker-minted handle, D7), and
//     authorization_metadata{intent:read, downloadable:false}.
//
//  2. The broker replies with HTTP 200 (always, for streams). Content frames
//     (flag 0x00) carry {data: <base64 bytes>}. The final frame (flag 0x02)
//     is the EndStreamResponse trailer. The caller must read the trailer to
//     determine success or failure — the HTTP status is never the signal.
//
// Download reassembles the full object; DownloadRange is a distinctly-named
// helper that consumes the same fileDownload stream and returns the requested
// {offset, length} slice. Neither is related to the unary readFile op (which
// is shipped in 02-01 and operates on a path with a nested Range in the unary
// request body).

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// downloadContentFrame is the JSON payload for a content frame in a
// fileDownload server-streaming response.
type downloadContentFrame struct {
	Data []byte `json:"data"`
}

// Download performs the fileDownload server-streaming op and returns the full
// reassembled object content. The object is addressed by its broker-minted
// uuid handle (D7); the guest never derives scope from the uuid.
//
// Success/failure comes exclusively from the EndStreamResponse trailer
// (HTTP status is always 200 for streaming responses).
func (c *Client) Download(ctx context.Context, uuid string) ([]byte, error) {
	fsID, am, err := c.stamp(OpFileDownload)
	if err != nil {
		return nil, err
	}

	respBody, respHeader, err := c.doDownloadRequest(ctx, fsID, uuid, am, nil)
	if err != nil {
		return nil, err
	}
	defer respBody.Close() //nolint:errcheck

	return reassembleDownloadStream(respBody, respHeader)
}

// DownloadRange is a distinctly-named helper that consumes the fileDownload
// server-streaming response and returns the requested {offset, length} byte
// slice. It sends the {offset, length} window in the request so the broker
// streams only those bytes — a ranged read transfers just the requested
// window rather than the whole object. The local slice that follows is a
// defensive clamp: a broker that honours the range returns exactly the window
// and the slice is a no-op; a broker that ignores it (returning more) is still
// trimmed to the contract, so the caller never sees over-delivery. This helper
// is the server-streaming ranged-read path (D5); it is NOT a second readFile
// method (the unary readFile op is in client.go, shipped in 02-01).
func (c *Client) DownloadRange(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
	if offset < 0 {
		return nil, fmt.Errorf("brokerrpc: DownloadRange: negative offset %d", offset)
	}
	if length < 0 {
		return nil, fmt.Errorf("brokerrpc: DownloadRange: negative length %d", length)
	}

	fsID, am, err := c.stamp(OpFileDownload)
	if err != nil {
		return nil, err
	}

	rng := &Range{Offset: offset, Length: length}
	respBody, respHeader, err := c.doDownloadRequest(ctx, fsID, uuid, am, rng)
	if err != nil {
		return nil, err
	}
	defer respBody.Close() //nolint:errcheck

	content, err := reassembleDownloadStream(respBody, respHeader)
	if err != nil {
		return nil, err
	}

	// Defensive clamp against a broker that streamed more than the requested
	// window. When the range was honoured, len(content) <= length and this is
	// a no-op. Offset is NOT re-applied here: the broker already seeked to it,
	// so the returned stream begins at offset.
	if int64(len(content)) > length {
		content = content[:length]
	}
	return content, nil
}

// doDownloadRequest builds and executes the fileDownload POST. rng is the
// optional byte window: nil streams the whole object, non-nil streams only the
// window. It returns the response body (caller must close) and the response
// headers.
func (c *Client) doDownloadRequest(
	ctx context.Context,
	fsID, uuid string,
	am AuthorizationMetadata,
	rng *Range,
) (io.ReadCloser, http.Header, error) {
	req := FileDownloadRequest{
		FilesystemID:          fsID,
		UUID:                  uuid,
		Range:                 rng,
		AuthorizationMetadata: am,
	}
	reqPayload, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("brokerrpc: marshal fileDownload request: %w", err)
	}

	// The request is sent as a single framed message (params frame) per
	// the Connect streaming protocol.
	var frameBuf bytes.Buffer
	if err := writeFrame(&frameBuf, 0x00, reqPayload); err != nil {
		return nil, nil, fmt.Errorf("brokerrpc: frame fileDownload request: %w", err)
	}

	url := streamingURL(OpFileDownload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &frameBuf)
	if err != nil {
		return nil, nil, fmt.Errorf("brokerrpc: build fileDownload request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/connect+json")
	httpReq.Header.Set("Connect-Protocol-Version", "1")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("brokerrpc: fileDownload: %w", err)
	}

	// Streaming responses always return HTTP 200; do not inspect the status.
	return httpResp.Body, httpResp.Header, nil
}

// reassembleDownloadStream reads content frames from r until the
// EndStreamResponse trailer and concatenates the data payloads.
// Success or failure is determined from the trailer.
func reassembleDownloadStream(r io.Reader, header http.Header) ([]byte, error) {
	var result []byte

	for {
		flag, payload, err := readFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// readFrame wraps the underlying EOF with %w, so equality on
				// io.EOF would never match; use errors.Is. A truncated stream
				// that ends before the EndStreamResponse trailer is an error.
				return nil, fmt.Errorf("brokerrpc: fileDownload: stream ended before EndStreamResponse")
			}
			return nil, fmt.Errorf("brokerrpc: fileDownload: read frame: %w", err)
		}

		if flag == endStreamFlag {
			// Parse the EndStreamResponse trailer.
			var esr EndStreamResponse
			if jsonErr := json.Unmarshal(payload, &esr); jsonErr != nil {
				return nil, fmt.Errorf("brokerrpc: fileDownload: parse EndStreamResponse: %w", jsonErr)
			}
			if esr.Error != nil {
				retryAfterRaw := header.Get("Retry-After")
				return nil, MapConnectError(esr.Error, retryAfterRaw)
			}
			// Success.
			return result, nil
		}

		// Data frame: extract the content bytes. An undecodable frame is a
		// HARD error — never return truncated content as success. For a
		// FUSE-backed mount, silently dropping a frame would surface as silent
		// file corruption, the worst possible failure mode. A zero-length data
		// frame appends nothing and is harmless.
		var frame downloadContentFrame
		if jsonErr := json.Unmarshal(payload, &frame); jsonErr != nil {
			return nil, fmt.Errorf("brokerrpc: fileDownload: malformed data frame: %w", jsonErr)
		}
		result = append(result, frame.Data...)
	}
}
