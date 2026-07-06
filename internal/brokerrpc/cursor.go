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
// Entries uses the pinned union type []ListDirEntry (raised from []Directory
// in Phase 3 — a response-decoder correction only, no new transport/op/auth
// path, SEC-25).
type listDirectoryPageResponse struct {
	Entries []ListDirEntry `json:"entries,omitempty"`
	Cursor  OpaqueCursor   `json:"cursor,omitempty"`
}

// listDirectoryPageRequest overrides ListDirectoryRequest to include the
// cursor for page-2+ requests.
type listDirectoryPageRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
	Cursor                OpaqueCursor          `json:"cursor,omitempty"`
}

// ListDirectoryStream performs recursive listDirectory paging, echoing the
// opaque cursor across pages, and invokes yield once per entry AS EACH PAGE
// ARRIVES. It never accumulates the full recursive tree in memory: a caller
// that only wants a depth-1 slice (Fs.List) can filter inside yield and keep
// just the survivors, so a huge recursive listing does not force a monolithic
// allocation inside the guest. A yield that returns a non-nil error stops
// pagination and surfaces that error to the caller.
func (c *Client) ListDirectoryStream(ctx context.Context, path string, yield func(ListDirEntry) error) error {
	fsID, am, err := c.stamp(OpListDirectory)
	if err != nil {
		return err
	}

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
			return fmt.Errorf("brokerrpc: ListDirectoryAll: %w", err)
		}

		for _, e := range resp.Entries {
			if err := yield(e); err != nil {
				return err
			}
		}

		if resp.Cursor == "" {
			break
		}
		// Progress guard: if the broker echoes the same cursor we just sent,
		// the listing is not advancing. Without this, a broker bug would spin
		// this loop forever with unbounded memory growth inside the mount.
		if cursor != "" && resp.Cursor == cursor {
			return fmt.Errorf("brokerrpc: ListDirectoryAll: cursor did not advance (%q) — aborting non-progressing pagination", string(resp.Cursor))
		}
		cursor = resp.Cursor
	}

	return nil
}

// ListDirectoryAll is the buffering convenience wrapper over
// ListDirectoryStream: it collects every entry into one slice and returns it.
// Callers that can process entries incrementally should prefer the stream form
// so a large recursive listing is never held whole. The returned []ListDirEntry
// reflects the pinned union shape (file XOR directory per D6); the published
// return type was raised from []Directory in Phase 3. This is a response-decoder
// correction only — no new transport, op, or auth path was added (SEC-25).
func (c *Client) ListDirectoryAll(ctx context.Context, path string) ([]ListDirEntry, error) {
	var all []ListDirEntry
	if err := c.ListDirectoryStream(ctx, path, func(e ListDirEntry) error {
		all = append(all, e)
		return nil
	}); err != nil {
		return nil, err
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

// ListFilesStream performs uuid-paginated listFiles paging, echoing the opaque
// after_uuid cursor across pages, and invokes yield once per file as each page
// arrives — the listFiles analogue of ListDirectoryStream. A yield returning a
// non-nil error stops pagination and surfaces that error.
func (c *Client) ListFilesStream(ctx context.Context, uuid string, yield func(FilesystemFile) error) error {
	fsID, am, err := c.stamp(OpListFiles)
	if err != nil {
		return err
	}

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
			return fmt.Errorf("brokerrpc: ListFilesAll: %w", err)
		}

		for _, fEntry := range resp.Files {
			if err := yield(fEntry); err != nil {
				return err
			}
		}

		if resp.AfterUUID == "" {
			break
		}
		// Progress guard: a repeated after_uuid means the listing is not
		// advancing; abort rather than loop forever (see ListDirectoryStream).
		if afterUUID != "" && resp.AfterUUID == afterUUID {
			return fmt.Errorf("brokerrpc: ListFilesAll: after_uuid did not advance (%q) — aborting non-progressing pagination", string(resp.AfterUUID))
		}
		afterUUID = resp.AfterUUID
	}

	return nil
}

// ListFilesAll is the buffering convenience wrapper over ListFilesStream: it
// collects every file into one slice. Callers that can process files
// incrementally should prefer the stream form.
func (c *Client) ListFilesAll(ctx context.Context, uuid string) ([]FilesystemFile, error) {
	var all []FilesystemFile
	if err := c.ListFilesStream(ctx, uuid, func(f FilesystemFile) error {
		all = append(all, f)
		return nil
	}); err != nil {
		return nil, err
	}
	return all, nil
}
