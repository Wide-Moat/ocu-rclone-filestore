// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — opaque cursor handling for paged listing ops.
//
// The broker returns pagination cursors as opaque tokens:
//
//   - listDirectory recursive paging: a "cursor" field in the response is
//     echoed verbatim in subsequent requests. The client never models the
//     cursor's internal structure.
//
//   - listFiles uuid-paginated paging: an "after_uuid" field plays the same
//     role — echoed opaquely across pages.
//
// The opaque-echo discipline is a security requirement: a cursor may carry
// broker-internal scope information; parsing or mutating it could break the
// broker's invariants or leak enumeration paths (D7 / D8).

package brokerrpc

import (
	"context"
	"fmt"
)

// OpaqueCursor is an opaque pagination token. It is transmitted as a string
// on the wire and must be echoed unmodified. The client never inspects its
// internals.
type OpaqueCursor string

// ---------------------------------------------------------------------------
// Recursive listDirectory paging
// ---------------------------------------------------------------------------

// listDirectoryPageResponse is the JSON response shape for listDirectory.
// We decode only the fields we echo (cursor) plus the entries we aggregate.
type listDirectoryPageResponse struct {
	Entries []Directory  `json:"entries,omitempty"`
	Cursor  OpaqueCursor `json:"cursor,omitempty"`
}

// listDirectoryPageRequest overrides ListDirectoryRequest to include the
// cursor for page-2+ requests.
type listDirectoryPageRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
	Cursor                OpaqueCursor          `json:"cursor,omitempty"`
}

// ListDirectoryAll performs recursive listDirectory paging, echoing the
// opaque cursor across pages, and returns the full accumulated entry list.
func (c *Client) ListDirectoryAll(ctx context.Context, path string) ([]Directory, error) {
	fsID, am, err := c.stamp(OpListDirectory)
	if err != nil {
		return nil, err
	}

	var all []Directory
	var cursor OpaqueCursor

	for {
		req := listDirectoryPageRequest{
			FilesystemID:          fsID,
			Path:                  path,
			AuthorizationMetadata: am,
			Cursor:                cursor,
		}

		var resp listDirectoryPageResponse
		if err := c.call(ctx, OpListDirectory, req, &resp); err != nil {
			return nil, fmt.Errorf("brokerrpc: ListDirectoryAll: %w", err)
		}

		all = append(all, resp.Entries...)

		if resp.Cursor == "" {
			break
		}
		// Progress guard: if the broker echoes the same cursor we just sent,
		// the listing is not advancing. Without this, a broker bug would spin
		// this loop forever with unbounded memory growth inside the mount.
		if cursor != "" && resp.Cursor == cursor {
			return nil, fmt.Errorf("brokerrpc: ListDirectoryAll: cursor did not advance (%q) — aborting non-progressing pagination", string(resp.Cursor))
		}
		cursor = resp.Cursor
	}

	return all, nil
}

// ---------------------------------------------------------------------------
// UUID-paginated listFiles paging
// ---------------------------------------------------------------------------

// listFilesPageResponse is the JSON response shape for listFiles with paging.
type listFilesPageResponse struct {
	Files     []FilesystemFile `json:"files,omitempty"`
	AfterUUID OpaqueCursor     `json:"after_uuid,omitempty"`
}

// listFilesPageRequest overrides ListFilesRequest to include the after_uuid
// cursor for page-2+ requests.
type listFilesPageRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	UUID                  string                `json:"uuid"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
	AfterUUID             OpaqueCursor          `json:"after_uuid,omitempty"`
}

// ListFilesAll performs uuid-paginated listFiles paging, echoing the opaque
// after_uuid cursor across pages, and returns the full accumulated file list.
func (c *Client) ListFilesAll(ctx context.Context, uuid string) ([]FilesystemFile, error) {
	fsID, am, err := c.stamp(OpListFiles)
	if err != nil {
		return nil, err
	}

	var all []FilesystemFile
	var afterUUID OpaqueCursor

	for {
		req := listFilesPageRequest{
			FilesystemID:          fsID,
			UUID:                  uuid,
			AuthorizationMetadata: am,
			AfterUUID:             afterUUID,
		}

		var resp listFilesPageResponse
		if err := c.call(ctx, OpListFiles, req, &resp); err != nil {
			return nil, fmt.Errorf("brokerrpc: ListFilesAll: %w", err)
		}

		all = append(all, resp.Files...)

		if resp.AfterUUID == "" {
			break
		}
		// Progress guard: a repeated after_uuid means the listing is not
		// advancing; abort rather than loop forever (see ListDirectoryAll).
		if afterUUID != "" && resp.AfterUUID == afterUUID {
			return nil, fmt.Errorf("brokerrpc: ListFilesAll: after_uuid did not advance (%q) — aborting non-progressing pagination", string(resp.AfterUUID))
		}
		afterUUID = resp.AfterUUID
	}

	return all, nil
}
