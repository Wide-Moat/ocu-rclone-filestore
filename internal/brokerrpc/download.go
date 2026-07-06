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

// defaultMaxDownloadBytes is the DEFAULT cap on how many bytes a single download
// body may deliver before the streaming reader aborts, used when the mount
// config supplies no MaxDownloadBytes. The guest is the least-provisioned party
// in the architecture and must never let a broker bug or a desynced stream size
// an unbounded read into guest OOM. The default is far above any expected single
// object yet rejects absurd lengths; a deployment overrides it via
// ClientOptions.MaxDownloadBytes so the binary ships no fixed policy value.
//
// The cap bounds the STREAM, not a pre-read buffer: Download returns a reader
// that yields bytes as they arrive and only fails once cumulative reads would
// exceed the cap, so a legitimate large object streams through VFS without ever
// being held whole in guest memory.
const defaultMaxDownloadBytes int64 = 1 << 34 // 16 GiB

// Download performs the fileDownload op and returns the full object content as
// a streaming io.ReadCloser. The object is addressed by its broker-minted uuid
// handle; the guest never derives scope from the uuid. The caller MUST Close
// the returned reader; closing it releases the underlying HTTP response.
//
// The returned reader is bounded by the client's maxDownloadBytes: it streams
// normally and returns an error on the read that would carry the stream past the
// cap, so a runaway or desynced body cannot grow guest memory without limit.
func (c *Client) Download(ctx context.Context, uuid string) (io.ReadCloser, error) {
	fsID, am, err := c.stamp(OpFileDownload)
	if err != nil {
		return nil, err
	}
	return c.doDownload(ctx, fsID, uuid, am, nil, c.maxDownloadBytes)
}

// DownloadRange is a distinctly-named helper that consumes the fileDownload
// response and returns a streaming io.ReadCloser over the requested
// {offset, length} window. It sends the {offset, length} window in the request
// so the broker streams only those bytes — a ranged read transfers just the
// requested window rather than the whole object. The returned reader is bounded
// to length as a defensive clamp: a broker that honours the range delivers
// exactly the window and the clamp is a no-op; a broker that ignores it
// (returning more) is truncated to the contract, so the caller never sees
// over-delivery. Offset is NOT re-applied locally: the broker already seeked to
// it, so the returned stream begins at offset. The caller MUST Close the reader.
func (c *Client) DownloadRange(ctx context.Context, uuid string, offset, length int64) (io.ReadCloser, error) {
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
	// Bound the returned stream to exactly the requested window. A broker that
	// honours the range delivers <= length bytes and the bound never trips; a
	// broker that over-delivers is truncated silently at length (a ranged read
	// asked for a fixed window, so trailing bytes past it are simply not the
	// caller's data — unlike the whole-object path, which errors on over-cap).
	return c.doDownload(ctx, fsID, uuid, am, rng, length)
}

// doDownload builds and executes the fileDownload POST and returns the chunked
// octet-stream body as a bounded streaming reader. rng is the optional byte
// window: nil streams the whole object, non-nil streams only the window. limit
// bounds how many bytes the returned reader will deliver before it aborts.
func (c *Client) doDownload(
	ctx context.Context,
	fsID, uuid string,
	am AuthorizationMetadata,
	rng *Range,
	limit int64,
) (io.ReadCloser, error) {
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

	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		// Read the error body for diagnostics, then map by status. This path
		// owns the body fully, so close it here — success returns the body to
		// the caller instead, who closes it via the returned ReadCloser.
		errBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
		_ = httpResp.Body.Close()
		return nil, MapHTTPStatus(httpResp.StatusCode, errBody, httpResp.Header.Get("Retry-After"))
	}

	// 2xx: hand the caller a bounded stream over the chunked octet-stream body.
	// Nothing is read into guest memory here; bytes flow as the caller reads.
	return newBoundedBody(httpResp.Body, rng == nil, limit), nil
}

// boundedBody wraps an HTTP response body as an io.ReadCloser that delivers at
// most limit bytes. On the whole-object path (strict=true) a stream that tries
// to carry more than the cap is a broker bug or a desync, so Read returns an
// error rather than silently truncating. On the ranged path (strict=false) the
// caller asked for a fixed window, so over-delivery past the window is simply
// truncated. Closing releases the underlying body.
type boundedBody struct {
	body      io.ReadCloser
	remaining int64
	limit     int64 // original cap, for the over-cap error message
	strict    bool
}

func newBoundedBody(body io.ReadCloser, strict bool, limit int64) *boundedBody {
	return &boundedBody{body: body, remaining: limit, limit: limit, strict: strict}
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		if b.strict {
			// The stream still has bytes past the cap: reject rather than OOM.
			var probe [1]byte
			if n, _ := b.body.Read(probe[:]); n > 0 {
				return 0, fmt.Errorf("brokerrpc: fileDownload: response exceeds %d bytes", b.limit)
			}
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *boundedBody) Close() error { return b.body.Close() }
