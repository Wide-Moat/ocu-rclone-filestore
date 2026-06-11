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
)

// serviceBase is the Connect-RPC service path prefix for the file-operations
// service under the ocu.filestore.v1alpha namespace.
const serviceBase = "/ocu.filestore.v1alpha.FilesystemService/"

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
}

// Client is the guest-side Connect-JSON client for the broker's
// file-operations service. It is bound at construction to a per-session
// AF_UNIX socket (the only egress path) and a filesystem_id (the sole scope
// handle). It holds no credential, constructs no credential header, and
// has no code path that sets downloadable to true.
type Client struct {
	http           *http.Client
	fsID           string
	messageCeiling int
}

// New constructs a Client bound to the given per-session unix socket path and
// filesystem_id. The socket path comes from the guest mount config; it is
// never a shared constant.
func New(socketPath string, fsID string) (*Client, error) {
	return NewWithOptions(socketPath, fsID, ClientOptions{})
}

// NewWithOptions constructs a Client with explicit options.
func NewWithOptions(socketPath, fsID string, opts ClientOptions) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("brokerrpc.New: socketPath must not be empty")
	}
	if fsID == "" {
		return nil, fmt.Errorf("brokerrpc.New: fsID must not be empty")
	}
	ceiling := opts.MessageCeiling
	if ceiling <= 0 {
		ceiling = defaultMessageCeiling
	}
	return &Client{
		http: &http.Client{
			Transport: unixTransport(socketPath),
		},
		fsID:           fsID,
		messageCeiling: ceiling,
	}, nil
}

// call is the unexported unary call helper. It marshals req to JSON, POSTs
// to the per-op route /ocu.filestore.v1alpha.FilesystemService/<op> with the
// required Connect-Protocol-Version: 1 header and Content-Type:
// application/json, then decodes a 2xx JSON response into resp. On non-2xx it
// returns a plain error; full closed-code mapping is wired in a later phase.
func (c *Client) call(ctx context.Context, op Op, req, resp interface{}) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("brokerrpc: marshal %s request: %w", op, err)
	}

	// The broker lives on a unix socket; the http.Transport's DialContext
	// ignores the host portion. We use "http://broker" as a placeholder host
	// so the standard library constructs a valid HTTP/1.1 request.
	url := "http://broker" + serviceBase + string(op)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("brokerrpc: build request for %s: %w", op, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Connect-Protocol-Version", "1")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("brokerrpc: %s: %w", op, err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("brokerrpc: read %s response body: %w", op, err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		// Non-2xx unary error: decode the Connect error body and run it
		// through the closed-code mapper (D4). The Retry-After header is
		// present only on resource_exhausted per the locked contract.
		var ce ConnectError
		if jsonErr := json.Unmarshal(respBody, &ce); jsonErr != nil || ce.Code == "" {
			// Body is not a parseable Connect error: fall back to a plain
			// permanent error wrapping the raw body.
			return fmt.Errorf("%w: %s: status %d: %s",
				ErrPermanentOther, op, httpResp.StatusCode, string(respBody))
		}
		retryAfterRaw := httpResp.Header.Get("Retry-After")
		return MapConnectError(&ce, retryAfterRaw)
	}

	if resp != nil {
		if err := json.Unmarshal(respBody, resp); err != nil {
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
// Unary op methods — 16 total (fileUpload and fileDownload are streaming;
// their transport is wired in plan 02-02; types are defined in messages.go).
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
	req := MoveDirectoryRequest{FilesystemID: fsID, SourcePath: sourcePath, DestinationPath: destinationPath, AuthorizationMetadata: am}
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

// CreateFile creates a file at path and returns the new file's metadata.
func (c *Client) CreateFile(ctx context.Context, path string) (*CreateFileResponse, error) {
	fsID, am, err := c.stamp(OpCreateFile)
	if err != nil {
		return nil, err
	}
	req := CreateFileRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp CreateFileResponse
	return &resp, c.call(ctx, OpCreateFile, req, &resp)
}

// ReadFile performs the unary readFile op for the file at path. As shipped this
// op is METADATA-ONLY: the response carries no content body (the content field
// is a TBD per D6, not invented here), so rng currently selects within an absent
// body. Bulk content is delivered by the streaming Download/DownloadRange
// helpers, not this op. A zero-value rng relies on the broker reading length 0
// as "full file".
func (c *Client) ReadFile(ctx context.Context, path string, rng Range) (*ReadFileResponse, error) {
	fsID, am, err := c.stamp(OpReadFile)
	if err != nil {
		return nil, err
	}
	req := ReadFileRequest{FilesystemID: fsID, Path: path, Range: rng, AuthorizationMetadata: am}
	var resp ReadFileResponse
	return &resp, c.call(ctx, OpReadFile, req, &resp)
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

// GetFileMetadata returns metadata for the file addressed by broker-minted
// UUID handle. The guest never derives scope from the UUID (D7).
func (c *Client) GetFileMetadata(ctx context.Context, uuid string) (*GetFileMetadataResponse, error) {
	fsID, am, err := c.stamp(OpGetFileMetadata)
	if err != nil {
		return nil, err
	}
	req := GetFileMetadataRequest{FilesystemID: fsID, UUID: uuid, AuthorizationMetadata: am}
	var resp GetFileMetadataResponse
	return &resp, c.call(ctx, OpGetFileMetadata, req, &resp)
}

// ListFiles returns a single page of files addressed by broker-minted UUID
// handle (uuid axis). When the returned response carries a non-empty AfterUUID
// the listing is paginated and this is only the first page; callers needing the
// complete listing must use ListFilesAll, which follows the cursor across pages.
func (c *Client) ListFiles(ctx context.Context, uuid string) (*ListFilesResponse, error) {
	fsID, am, err := c.stamp(OpListFiles)
	if err != nil {
		return nil, err
	}
	req := ListFilesRequest{FilesystemID: fsID, UUID: uuid, AuthorizationMetadata: am}
	var resp ListFilesResponse
	return &resp, c.call(ctx, OpListFiles, req, &resp)
}

// CopyFile copies the file at sourcePath to destinationPath.
func (c *Client) CopyFile(ctx context.Context, sourcePath, destinationPath string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpCopyFile)
	if err != nil {
		return nil, err
	}
	req := CopyFileRequest{FilesystemID: fsID, SourcePath: sourcePath, DestinationPath: destinationPath, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpCopyFile, req, &resp)
}

// MoveFile moves the file at sourcePath to destinationPath.
func (c *Client) MoveFile(ctx context.Context, sourcePath, destinationPath string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpMoveFile)
	if err != nil {
		return nil, err
	}
	req := MoveFileRequest{FilesystemID: fsID, SourcePath: sourcePath, DestinationPath: destinationPath, AuthorizationMetadata: am}
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

// ImportFiles imports files into the filesystem at path.
func (c *Client) ImportFiles(ctx context.Context, path string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpImportFiles)
	if err != nil {
		return nil, err
	}
	req := ImportFilesRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpImportFiles, req, &resp)
}

// ImportZip imports a ZIP archive into the filesystem at path.
func (c *Client) ImportZip(ctx context.Context, path string) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpImportZip)
	if err != nil {
		return nil, err
	}
	req := ImportZipRequest{FilesystemID: fsID, Path: path, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpImportZip, req, &resp)
}

// MigrateFilesystem requests a migration of the bound filesystem.
func (c *Client) MigrateFilesystem(ctx context.Context) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpMigrateFilesystem)
	if err != nil {
		return nil, err
	}
	req := MigrateFilesystemRequest{FilesystemID: fsID, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpMigrateFilesystem, req, &resp)
}

// RemoveFilesystem requests removal of the bound filesystem.
func (c *Client) RemoveFilesystem(ctx context.Context) (*AckResponse, error) {
	fsID, am, err := c.stamp(OpRemoveFilesystem)
	if err != nil {
		return nil, err
	}
	req := RemoveFilesystemRequest{FilesystemID: fsID, AuthorizationMetadata: am}
	var resp AckResponse
	return &resp, c.call(ctx, OpRemoveFilesystem, req, &resp)
}
