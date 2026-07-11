// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// restBase is the REST path prefix for the file-operations service. Each op
// routes to <service_url>/v1/filestore/fs/<operation>.
const restBase = "v1/filestore/fs/"

// maxJSONResponseBytes bounds how many bytes a unary JSON response body may
// deliver before decoding aborts. Metadata and single listing-page responses
// are small; the bound is far above any legitimate response yet stops a runaway
// or desynced body from growing guest memory during decode. Content bytes never
// travel this path — fileDownload streams through the octet-stream body instead.
const maxJSONResponseBytes int64 = 64 << 20 // 64 MiB

// defaultMessageCeiling is the default maximum payload size for a single
// streaming chunk frame, measured on the ENCODED frame payload. The chunker
// sizes each source read so the base64-plus-JSON-envelope frame payload stays
// strictly below this value, so the broker never receives a frame at or above
// the ceiling (D4: a transport frame over the ceiling draws resource_exhausted).
const defaultMessageCeiling = 256 * 1024 // 256 KiB

// ClientOptions carries construction-time tunables for Client.
type ClientOptions struct {
	// MessageCeiling is the maximum number of bytes per ENCODED chunk frame
	// payload (the base64-plus-JSON-envelope on-wire frame). The chunker keeps
	// every frame strictly below this value. A value of 0 uses the default
	// (256 KiB).
	MessageCeiling int

	// MaxDownloadBytes caps how many bytes a single whole-object download may
	// deliver before the streaming reader aborts. It is a safety ceiling against
	// a broker bug or desynced stream, not a policy value tied to any object. A
	// value of 0 uses the default (defaultMaxDownloadBytes). The value flows in
	// from the parsed mount config, so the binary ships no hard-coded ceiling.
	MaxDownloadBytes int64
}

// Client is the guest-side REST client for the broker's file-operations
// service. It is bound at construction to an HTTPS service_url (the only egress
// path, reached over TLS that trusts the inspecting edge's CA), a filesystem_id
// (the sole scope handle), and a static session credential read once at
// construction. It has no code path that sets downloadable to true and no
// credential-refresh path.
type Client struct {
	http             *http.Client
	serviceURL       string
	fsID             string
	authToken        string
	messageCeiling   int
	maxDownloadBytes int64
	// maxListPages is the hard ceiling on pages a single paged listing may
	// fetch (see defaultMaxListPages in cursor.go). Unexported and defaulted at
	// construction: it is a loop-termination safety bound, not a policy knob,
	// so it is deliberately absent from ClientOptions and the mount config.
	maxListPages int
}

// New constructs a Client bound to the broker's HTTPS service_url, the
// session-scoped filesystem_id, the static session credential, and the PEM
// trust anchor for the inspecting edge. All four arrive from host-side
// provisioning; none is a shared constant.
func New(serviceURL, fsID, authToken string, caCertPEM []byte) (*Client, error) {
	return NewWithOptions(serviceURL, fsID, authToken, caCertPEM, ClientOptions{})
}

// NewWithOptions constructs a Client with explicit options.
func NewWithOptions(serviceURL, fsID, authToken string, caCertPEM []byte, opts ClientOptions) (*Client, error) {
	if serviceURL == "" {
		return nil, fmt.Errorf("brokerrpc.New: serviceURL must not be empty")
	}
	u, err := url.Parse(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("brokerrpc.New: serviceURL is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("brokerrpc.New: serviceURL must be an https:// URL, got scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("brokerrpc.New: serviceURL must include a host")
	}
	if fsID == "" {
		return nil, fmt.Errorf("brokerrpc.New: fsID must not be empty")
	}
	if authToken == "" {
		return nil, fmt.Errorf("brokerrpc.New: authToken must not be empty")
	}
	if len(caCertPEM) == 0 {
		return nil, fmt.Errorf("brokerrpc.New: caCertPEM must not be empty")
	}
	transport, err := httpsTransport(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("brokerrpc.New: build transport: %w", err)
	}
	ceiling := opts.MessageCeiling
	if ceiling <= 0 {
		ceiling = defaultMessageCeiling
	}
	maxDL := opts.MaxDownloadBytes
	if maxDL <= 0 {
		maxDL = defaultMaxDownloadBytes
	}
	return &Client{
		http:             &http.Client{Transport: transport},
		serviceURL:       serviceURL,
		fsID:             fsID,
		authToken:        authToken,
		messageCeiling:   ceiling,
		maxDownloadBytes: maxDL,
		maxListPages:     defaultMaxListPages,
	}, nil
}

// opURL builds the REST URL for an op: <service_url>/v1/filestore/fs/<op>.
func (c *Client) opURL(op Op) string {
	return strings.TrimRight(c.serviceURL, "/") + "/" + restBase + string(op)
}

// setAuthHeader stamps the static session credential on a request. The
// credential is read once at construction; there is no refresh.
func (c *Client) setAuthHeader(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.authToken)
}

// call is the unexported unary call helper. It marshals req to JSON, POSTs to
// the per-op REST route <service_url>/v1/filestore/fs/<op> over HTTPS with a
// static Authorization: Bearer header and Content-Type: application/json, then
// decodes a 2xx JSON response into resp. On non-2xx it hands the HTTP status,
// body, and Retry-After header to MapHTTPStatus.
func (c *Client) call(ctx context.Context, op Op, req, resp interface{}) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("brokerrpc: marshal %s request: %w", op, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opURL(op), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("brokerrpc: build request for %s: %w", op, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.setAuthHeader(httpReq)

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("brokerrpc: %s: %w", op, err)
	}
	// The body is consumed below (streamed on 2xx, bounded-read on error), so a
	// Close error carries no information the caller can act on; discard it.
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		// Non-2xx error: the HTTP status drives the typed mapping. The body is
		// diagnostics-only (never parsed; the Retry-After header is honoured
		// only on 429 inside MapHTTPStatus), so capture is capped at the shared
		// diagnostics budget rather than the 2xx decode ceiling.
		errBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxErrorBodyBytes))
		return MapHTTPStatus(httpResp.StatusCode, errBody, httpResp.Header.Get("Retry-After"))
	}

	if resp != nil {
		// Stream-decode the JSON body bounded by maxJSONResponseBytes rather than
		// buffering the whole response first: a unary metadata response is small,
		// and the bound stops a runaway or desynced body from growing guest memory.
		if err := json.NewDecoder(io.LimitReader(httpResp.Body, maxJSONResponseBytes)).Decode(resp); err != nil {
			return fmt.Errorf("brokerrpc: unmarshal %s response: %w", op, err)
		}
	}
	return nil
}

// stamp returns a pre-stamped request base with filesystem_id and
// authorization_metadata filled in from the client's bound fsID and the
// op-keyed intent table.
func (c *Client) stamp(op Op) (string, AuthorizationMetadata, error) {
	am, err := StampAuthMeta(op)
	if err != nil {
		return "", AuthorizationMetadata{}, err
	}
	return c.fsID, am, nil
}

// ---------------------------------------------------------------------------
// Unary op methods — 8 total (fileUpload and fileDownload have REST
// upload/download transports in upload.go/download.go; types in messages.go).
// Each routes to <service_url>/v1/filestore/fs/<op> over HTTPS. Ops whose
// bodies are TBD at the frozen contract have no client method: only their
// operation NAMES are pinned (intent.go), and a TBD body is never invented.
// ---------------------------------------------------------------------------

// ListDirectory lists a single page of the directory at path. When the
// returned response carries a non-empty Cursor the listing is paginated and
// this is only the first page; callers needing the complete listing must use
// ListDirectoryAll, which follows the cursor across pages.
func (c *Client) ListDirectory(ctx context.Context, path string) (*ListDirectoryResponse, error) {
	fsID, am, err := c.stamp(OpListDirectory)
	if err != nil {
		return nil, err
	}
	req := ListDirectoryRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp ListDirectoryResponse
	return &resp, c.call(ctx, OpListDirectory, req, &resp)
}

// MakeDirectory creates a directory at path.
func (c *Client) MakeDirectory(ctx context.Context, path string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpMakeDirectory)
	if err != nil {
		return nil, err
	}
	req := MakeDirectoryRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpMakeDirectory, req, &resp)
}

// MoveDirectory moves (renames) a directory from sourcePath to destinationPath.
func (c *Client) MoveDirectory(ctx context.Context, sourcePath, destinationPath string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpMoveDirectory)
	if err != nil {
		return nil, err
	}
	req := MoveDirectoryRequest{FilesystemID: fsID, Source: sourcePath, Destination: destinationPath, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpMoveDirectory, req, &resp)
}

// RemoveDirectory removes the directory at path.
func (c *Client) RemoveDirectory(ctx context.Context, path string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpRemoveDirectory)
	if err != nil {
		return nil, err
	}
	req := RemoveDirectoryRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpRemoveDirectory, req, &resp)
}

// ReadMetadata returns metadata for the file or directory at path.
func (c *Client) ReadMetadata(ctx context.Context, path string) (*ReadMetadataResponse, error) {
	fsID, am, err := c.stamp(OpReadMetadata)
	if err != nil {
		return nil, err
	}
	req := ReadMetadataRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp ReadMetadataResponse
	return &resp, c.call(ctx, OpReadMetadata, req, &resp)
}

// CopyFile copies the file at sourcePath to destinationPath.
func (c *Client) CopyFile(ctx context.Context, sourcePath, destinationPath string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpCopyFile)
	if err != nil {
		return nil, err
	}
	req := CopyFileRequest{FilesystemID: fsID, Source: sourcePath, Destination: destinationPath, OverwriteExisting: true, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpCopyFile, req, &resp)
}

// MoveFile moves the file at sourcePath to destinationPath.
func (c *Client) MoveFile(ctx context.Context, sourcePath, destinationPath string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpMoveFile)
	if err != nil {
		return nil, err
	}
	req := MoveFileRequest{FilesystemID: fsID, Source: sourcePath, Destination: destinationPath, OverwriteExisting: true, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpMoveFile, req, &resp)
}

// RemoveFile removes the file at path.
func (c *Client) RemoveFile(ctx context.Context, path string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpRemoveFile)
	if err != nil {
		return nil, err
	}
	req := RemoveFileRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpRemoveFile, req, &resp)
}
