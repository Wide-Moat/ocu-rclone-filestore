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
// slice. fileDownload is the only content-read path this client implements.

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
// requested window rather than the whole object. A length-0 window returns an
// empty reader without any wire call. Offset is NOT re-applied locally: the
// broker already seeked to it, so the returned stream begins at offset. The
// caller MUST Close the reader.
//
// Offset honour is not directly verifiable on this wire: the fileDownload
// response is pinned only as a chunked octet-stream (its field set is TBD in
// the frozen contract), so there is no range echo to check and none may be
// invented. What IS verifiable is the byte count: a broker that ignores the
// range and streams from byte 0 delivers more than the window whenever the
// window ends before EOF, so over-delivery — declared via Content-Length or
// observed while streaming — surfaces as an ERROR rather than a truncation
// (truncating would silently relabel the object's head as the requested
// window and hand wrong bytes to the VFS as a successful read). Honest
// residual: a broker that honours length but not offset delivers exactly
// length wrong bytes and is undetectable on this wire; closing that needs a
// contract-level pin and is out of scope while the contracts are frozen.
func (c *Client) DownloadRange(ctx context.Context, uuid string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, fmt.Errorf("brokerrpc: DownloadRange: negative offset %d", offset)
	}
	if length < 0 {
		return nil, fmt.Errorf("brokerrpc: DownloadRange: negative length %d", length)
	}
	// A zero-length window is trivially the empty read: answer it locally,
	// with no RPC. This is the POSIX at-EOF answer (Object.Open clamps at/past-
	// EOF windows to length 0), and it deliberately sidesteps fileDownload's
	// length-0 wire semantics — this broker family reads length 0 as "full
	// file", so issuing the RPC would stream the whole object only to be
	// discarded, and the strict window bound below would misread that stream
	// as over-delivery.
	if length == 0 {
		return http.NoBody, nil
	}

	fsID, am, err := c.stamp(OpFileDownload)
	if err != nil {
		return nil, err
	}

	rng := &Range{Offset: offset, Length: length}
	// Bound the returned stream strictly to the requested window: a broker
	// that honours the range delivers <= length bytes and the bound never
	// trips; one that over-delivers is failed, never truncated (see the doc
	// comment above).
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

	// Fast-fail on declared over-delivery: when the response declares a length
	// up front (Content-Length >= 0; a chunked body declares none and is
	// caught by the streaming bound instead), a declaration past the limit
	// already proves the response cannot fit the request — reject it before
	// handing out a reader.
	if httpResp.ContentLength >= 0 && httpResp.ContentLength > limit {
		_ = httpResp.Body.Close()
		if rng != nil {
			return nil, fmt.Errorf("brokerrpc: fileDownload: response declares %d bytes for the requested %d-byte window — broker did not honour the range", httpResp.ContentLength, limit)
		}
		return nil, fmt.Errorf("brokerrpc: fileDownload: response declares %d bytes, exceeding the %d-byte cap", httpResp.ContentLength, limit)
	}

	// 2xx: hand the caller a bounded stream over the chunked octet-stream body.
	// Nothing is read into guest memory here; bytes flow as the caller reads.
	return newBoundedBody(httpResp.Body, rng != nil, limit), nil
}

// boundedBody wraps an HTTP response body as an io.ReadCloser that delivers at
// most limit bytes and treats over-delivery as an ERROR on both paths. On the
// whole-object path a stream carrying more than the cap is a broker bug or a
// desync that must not size an unbounded read into guest memory. On the ranged
// path over-delivery is the observable signature of a broker that did not
// honour the requested window (the wire carries no range echo, so the byte
// count is the only verifiable signal — see DownloadRange); truncating it
// would relabel the object's head as the requested window, so it fails
// instead. ranged selects the over-cap error text. Closing releases the
// underlying body.
type boundedBody struct {
	body      io.ReadCloser
	remaining int64
	limit     int64 // original cap, for the over-cap error message
	ranged    bool
}

func newBoundedBody(body io.ReadCloser, ranged bool, limit int64) *boundedBody {
	return &boundedBody{body: body, remaining: limit, limit: limit, ranged: ranged}
}

// overCapErr is the error for a stream that carried bytes past the cap.
func (b *boundedBody) overCapErr() error {
	if b.ranged {
		return fmt.Errorf("brokerrpc: fileDownload: broker over-delivered the requested %d-byte window (offset dishonour suspected)", b.limit)
	}
	return fmt.Errorf("brokerrpc: fileDownload: response exceeds %d bytes", b.limit)
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// Probe one byte past the cap and reject over-delivery rather than
		// truncating (ranged) or OOM-ing (whole object). The probe must be
		// DECISIVE: a (0, nil) result is "try again" per the io.Reader
		// contract, and a boundary error is a real transport fault that must
		// surface — never be relabelled as clean end-of-stream (that would
		// pass a truncated prefix off as the complete content).
		var probe [1]byte
		for {
			n, perr := b.body.Read(probe[:])
			if n > 0 {
				return 0, b.overCapErr()
			}
			if perr != nil {
				if perr == io.EOF {
					return 0, io.EOF
				}
				return 0, perr
			}
			// (0, nil): not decisive — try again. The underlying body here
			// is always a net/http response body, which terminates every
			// read sequence with n > 0 or an error, so this loop cannot
			// spin in production.
		}
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *boundedBody) Close() error { return b.body.Close() }
