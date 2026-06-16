// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — REST fileDownload transport.
//
// The fileDownload op is a JSON POST to
// <service_url>/v1/filestore/fs/fileDownload carrying filesystem_id, uuid (NOT
// path — broker-minted handle), an optional {offset, length} range, and
// authorization_metadata{intent:read, downloadable:false}. On a 2xx the broker
// streams the object bytes as a chunked application/octet-stream body, read
// directly to completion. A non-2xx maps through MapHTTPStatus.
//
// Download reassembles the full object; DownloadRange is a distinctly-named
// helper that consumes the same op and returns the requested {offset, length}
// slice. Neither is related to the unary readFile op (which operates on a path
// with a nested Range in the unary request body).

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxDownloadBytes caps how many bytes a single download body may deliver
// before the reader aborts. The guest is the least-provisioned party in the
// architecture and must never let a broker bug or a desynced stream size an
// unbounded read into guest OOM. The cap is far above any expected single
// object yet rejects absurd lengths.
const maxDownloadBytes int64 = 1 << 34 // 16 GiB

// Download performs the fileDownload op and returns the full reassembled object
// content. The object is addressed by its broker-minted uuid handle; the guest
// never derives scope from the uuid.
func (c *Client) Download(ctx context.Context, uuid string) ([]byte, error) {
	fsID, am, err := c.stamp(OpFileDownload)
	if err != nil {
		return nil, err
	}
	return c.doDownload(ctx, fsID, uuid, am, nil)
}

// DownloadRange is a distinctly-named helper that consumes the fileDownload
// response and returns the requested {offset, length} byte slice. It sends the
// {offset, length} window in the request so the broker streams only those bytes
// — a ranged read transfers just the requested window rather than the whole
// object. The local slice that follows is a defensive clamp: a broker that
// honours the range returns exactly the window and the slice is a no-op; a
// broker that ignores it (returning more) is still trimmed to the contract, so
// the caller never sees over-delivery.
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
	content, err := c.doDownload(ctx, fsID, uuid, am, rng)
	if err != nil {
		return nil, err
	}

	// Defensive clamp against a broker that streamed more than the requested
	// window. When the range was honoured, len(content) <= length and this is a
	// no-op. Offset is NOT re-applied here: the broker already seeked to it, so
	// the returned stream begins at offset.
	if int64(len(content)) > length {
		content = content[:length]
	}
	return content, nil
}

// doDownload builds and executes the fileDownload POST and reads the chunked
// octet-stream body. rng is the optional byte window: nil streams the whole
// object, non-nil streams only the window.
func (c *Client) doDownload(
	ctx context.Context,
	fsID, uuid string,
	am AuthorizationMetadata,
	rng *Range,
) ([]byte, error) {
	req := FileDownloadRequest{
		FilesystemID:          fsID,
		UUID:                  uuid,
		Range:                 rng,
		AuthorizationMetadata: am,
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("brokerrpc: marshal fileDownload request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opURL(OpFileDownload), bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("brokerrpc: build fileDownload request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.setAuthHeader(httpReq)

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("brokerrpc: fileDownload: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		// Read the error body for diagnostics, then map by status.
		errBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
		return nil, MapHTTPStatus(httpResp.StatusCode, errBody, httpResp.Header.Get("Retry-After"))
	}

	// 2xx: read the chunked octet-stream body to completion, bounded by the
	// download cap so a runaway stream cannot OOM the guest.
	content, err := io.ReadAll(io.LimitReader(httpResp.Body, maxDownloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("brokerrpc: fileDownload: read body: %w", err)
	}
	if int64(len(content)) > maxDownloadBytes {
		return nil, fmt.Errorf("brokerrpc: fileDownload: response exceeds %d bytes", maxDownloadBytes)
	}
	return content, nil
}
