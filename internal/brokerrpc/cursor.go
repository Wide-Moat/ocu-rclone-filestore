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
	"crypto/sha256"
	"fmt"
)

// OpaqueCursor is an opaque pagination token. It is transmitted as a string
// on the wire and must be echoed unmodified. The client never inspects its
// internals.
type OpaqueCursor string

// defaultMaxListPages is the default hard ceiling on how many pages a single
// paged listing may fetch before the loop aborts. Each page from an honest
// broker carries at least one entry, so the ceiling admits listings of tens of
// thousands of entries per listing — far beyond any session filesystem this
// mount serves — while bounding both the pagination loop and the seen-cursor
// set at a fixed worst-case size. Hitting it surfaces a loud, attributable
// error instead of guest OOM (the same least-provisioned-guest rationale as
// defaultMaxDownloadBytes). Broker throttling (SEC-46) arrives as per-call
// errors, never as endless pages, so the ceiling cannot misfire under
// throttle.
const defaultMaxListPages = 65536

// pageGuard bounds a pagination loop against a broker that never lets the
// listing complete. Two failure shapes exist on this wire and each needs its
// own bound:
//
//   - A repeated cursor at ANY distance (the A,B,A,B echo, not just the
//     immediate repeat): the shipped guard already treated an
//     immediately-repeated cursor as non-progress and failed loudly; the seen
//     set extends that same decision to longer cycles. The frozen contract
//     pins nothing about cursor uniqueness and the opaque-echo discipline
//     (package doc above) forbids reasoning about cursor structure, so a
//     broker whose cursors legitimately repeat while progressing is
//     indistinguishable from a cycle on this wire — the page ceiling below is
//     the true bound, and failing at the repeat is the established decision
//     applied at every distance. Cursors are stored as fixed-size SHA-256
//     digests so a hostile arbitrarily-long cursor cannot balloon the set.
//
//   - Distinct cursors forever: no set catches a broker that mints a fresh
//     cursor per page without end, so a hard page ceiling backstops the loop
//     (and with it the seen set's memory).
type pageGuard struct {
	fn       string // emitting function, named in the error text
	maxPages int
	pages    int
	seen     map[[sha256.Size]byte]struct{}
}

func newPageGuard(fn string, maxPages int) *pageGuard {
	return &pageGuard{fn: fn, maxPages: maxPages, seen: make(map[[sha256.Size]byte]struct{})}
}

// admit accounts one fetched page and validates the non-empty cursor the
// broker returned for the next page. It fails when the listing exceeds the
// page ceiling or when the cursor repeats any cursor already seen in this
// listing (a pagination cycle — the "did not advance" error class).
func (g *pageGuard) admit(cursor OpaqueCursor) error {
	g.pages++
	if g.pages >= g.maxPages {
		return fmt.Errorf("brokerrpc: %s: pagination exceeded the %d-page ceiling — aborting unbounded listing", g.fn, g.maxPages)
	}
	key := sha256.Sum256([]byte(cursor))
	if _, dup := g.seen[key]; dup {
		return fmt.Errorf("brokerrpc: %s: cursor did not advance (%q) — aborting pagination cycle", g.fn, string(cursor))
	}
	g.seen[key] = struct{}{}
	return nil
}

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
	guard := newPageGuard("ListDirectoryStream", c.maxListPages)

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
		// Progress guard: a cursor repeated at any distance or a listing past
		// the page ceiling means pagination is not converging. Without this, a
		// broker bug would spin this loop forever with unbounded memory growth
		// inside the mount (see pageGuard).
		if err := guard.admit(resp.Cursor); err != nil {
			return err
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
	guard := newPageGuard("ListFilesStream", c.maxListPages)

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
		// Progress guard: an after_uuid repeated at any distance or a listing
		// past the page ceiling aborts rather than looping forever (see
		// pageGuard).
		if err := guard.admit(resp.AfterUUID); err != nil {
			return err
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
