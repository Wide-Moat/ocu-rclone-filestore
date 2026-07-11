// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestRecursiveCursorEchoedUnmodified verifies that the recursive listDirectory
// cursor is echoed back verbatim across page requests without any parsing or
// mutation.
func TestRecursiveCursorEchoedUnmodified(t *testing.T) {
	// Page-1 response contains a cursor value.
	page1Cursor := "opaque-cursor-bytes-XYZ123"
	var page2Cursor string
	callCount := 0

	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var body struct {
			Cursor string `json:"cursor,omitempty"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if callCount == 2 {
			page2Cursor = body.Cursor
		}

		var respBody []byte
		if callCount == 1 {
			// Page 1: return cursor pointing to page 2. Use the union shape the
			// widened decoder expects: each entry has a `file` or `directory` key.
			type dirEntry struct {
				Path string `json:"path"`
			}
			type entry struct {
				Directory *dirEntry `json:"directory,omitempty"`
			}
			type resp struct {
				Entries []entry `json:"entries,omitempty"`
				Cursor  string  `json:"cursor,omitempty"`
			}
			respBody, _ = json.Marshal(resp{
				Entries: []entry{{Directory: &dirEntry{Path: "/a"}}},
				Cursor:  page1Cursor,
			})
		} else {
			// Page 2: return empty cursor (last page).
			type dirEntry struct {
				Path string `json:"path"`
			}
			type entry struct {
				Directory *dirEntry `json:"directory,omitempty"`
			}
			type resp struct {
				Entries []entry `json:"entries,omitempty"`
			}
			respBody, _ = json.Marshal(resp{
				Entries: []entry{{Directory: &dirEntry{Path: "/b"}}},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}

	c, _ := newTLSTestClient(t, "fs-cursor-01", handler)
	entries, err := c.ListDirectoryAll(context.Background(), "/")
	if err != nil {
		t.Fatalf("ListDirectoryAll: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries across 2 pages, got %d", len(entries))
	}
	if page2Cursor != page1Cursor {
		t.Errorf("cursor echo: got %q, want %q", page2Cursor, page1Cursor)
	}
	if callCount != 2 {
		t.Errorf("expected 2 page calls, got %d", callCount)
	}
}

// TestListDirectoryAllStopsOnNonAdvancingCursor verifies that a broker echoing
// the same cursor forever does not spin ListDirectoryAll into an infinite loop
// with unbounded memory growth; the helper detects the non-progressing cursor
// and returns an error (MD-03).
func TestListDirectoryAllStopsOnNonAdvancingCursor(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Always return the SAME non-empty cursor — never advances.
		type dirEntry struct {
			Path string `json:"path"`
		}
		type entry struct {
			Directory *dirEntry `json:"directory,omitempty"`
		}
		type resp struct {
			Entries []entry `json:"entries,omitempty"`
			Cursor  string  `json:"cursor,omitempty"`
		}
		respBody, _ := json.Marshal(resp{
			Entries: []entry{{Directory: &dirEntry{Path: "/x"}}},
			Cursor:  "stuck-cursor",
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}

	c, _ := newTLSTestClient(t, "fs-cursor-01", handler)
	_, err := c.ListDirectoryAll(context.Background(), "/")
	if err == nil {
		t.Fatal("expected error on non-advancing cursor, got nil (would loop forever)")
	}
	// The first page sends an empty cursor, the second sends "stuck-cursor",
	// the third sees the same cursor echoed and aborts — bounded call count.
	if callCount > 3 {
		t.Errorf("expected the loop to abort quickly, got %d calls", callCount)
	}
}

// ---------------------------------------------------------------------------
// Union decode tests — the widened listDirectory decoder (D6, Phase 3).
// ---------------------------------------------------------------------------

// TestListDirUnionDecodeMixedPage verifies that a listDirectory page JSON
// containing a mixed entries array — one file entry and one directory entry —
// decodes into []ListDirEntry where the file arm is populated for the file
// entry (uuid+size+mtime non-zero) and the directory arm is populated for
// the directory entry (mtime non-zero), and the opposite arm is nil.
// Fixtures use the `mtime` JSON key (the current struct tag); the
// created_at↔mtime source reconciliation is a tracked follow-up (LD-2).
func TestListDirUnionDecodeMixedPage(t *testing.T) {
	const mixedPage = `{
		"entries": [
			{
				"file": {
					"path": "/docs/readme.txt",
					"size": 1024,
					"uuid": "file-uuid-abc",
					"mime": "text/plain",
					"mtime": "2026-01-15T10:00:00Z",
					"extra_unknown_field": "ignored"
				}
			},
			{
				"directory": {
					"path": "/docs/sub",
					"mtime": "2026-01-10T08:00:00Z",
					"extra_unknown_field": "ignored"
				}
			}
		]
	}`

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mixedPage))
	}

	c, _ := newTLSTestClient(t, "fs-union-01", handler)
	entries, err := c.ListDirectoryAll(context.Background(), "/docs")
	if err != nil {
		t.Fatalf("ListDirectoryAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// First entry: file arm populated, directory arm nil.
	fileEntry := entries[0]
	if fileEntry.File == nil {
		t.Fatal("entries[0].File is nil, expected a populated FilesystemFile")
	}
	if fileEntry.Directory != nil {
		t.Error("entries[0].Directory is non-nil, expected nil for a file entry")
	}
	if fileEntry.File.UUID != "file-uuid-abc" {
		t.Errorf("entries[0].File.UUID = %q, want %q", fileEntry.File.UUID, "file-uuid-abc")
	}
	if fileEntry.File.Size != 1024 {
		t.Errorf("entries[0].File.Size = %d, want 1024", fileEntry.File.Size)
	}
	if fileEntry.File.MIME != "text/plain" {
		t.Errorf("entries[0].File.MIME = %q, want %q", fileEntry.File.MIME, "text/plain")
	}
	if fileEntry.File.Mtime == "" {
		t.Error("entries[0].File.Mtime is empty, expected non-empty mtime")
	}

	// Second entry: directory arm populated, file arm nil.
	dirEntry := entries[1]
	if dirEntry.Directory == nil {
		t.Fatal("entries[1].Directory is nil, expected a populated Directory")
	}
	if dirEntry.File != nil {
		t.Error("entries[1].File is non-nil, expected nil for a directory entry")
	}
	if dirEntry.Directory.Path != "/docs/sub" {
		t.Errorf("entries[1].Directory.Path = %q, want %q", dirEntry.Directory.Path, "/docs/sub")
	}
	if dirEntry.Directory.Mtime == "" {
		t.Error("entries[1].Directory.Mtime is empty, expected non-empty mtime")
	}
}

// TestListDirUnionTwoPageAggregation verifies that ListDirectoryAll correctly
// aggregates union entries across two pages, echoing the opaque cursor, and
// returns all entries as []ListDirEntry.
func TestListDirUnionTwoPageAggregation(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var respBody []byte
		if callCount == 1 {
			// Page 1: one file entry, cursor points to page 2.
			respBody = []byte(`{
				"entries": [{"file": {"path": "/f1", "uuid": "u1", "size": 10, "mtime": "2026-01-01T00:00:00Z"}}],
				"cursor": "page2-cursor"
			}`)
		} else {
			// Page 2: one directory entry, no cursor (last page).
			respBody = []byte(`{
				"entries": [{"directory": {"path": "/d1", "mtime": "2026-01-02T00:00:00Z"}}]
			}`)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	}

	c, _ := newTLSTestClient(t, "fs-union-02", handler)
	entries, err := c.ListDirectoryAll(context.Background(), "/")
	if err != nil {
		t.Fatalf("ListDirectoryAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries from 2 pages, got %d", len(entries))
	}
	if callCount != 2 {
		t.Errorf("expected 2 page calls, got %d", callCount)
	}
	// First: file entry; second: directory entry.
	if entries[0].File == nil {
		t.Error("entries[0].File is nil, expected file arm populated")
	}
	if entries[1].Directory == nil {
		t.Error("entries[1].Directory is nil, expected directory arm populated")
	}
}

// TestListDirectoryStreamErrorsMidPagination drives the call-error branch of
// the paging loop AFTER a successful first page: page 1 returns entries and a
// cursor, page 2 returns a non-2xx. The error must propagate naming the
// function that emits it (ListDirectoryStream — the loop lives there, reached
// here through its buffering wrapper) while preserving the underlying
// sentinel, and pagination must halt — partial pages are never returned as a
// complete listing.
func TestListDirectoryStreamErrorsMidPagination(t *testing.T) {
	callCount := 0
	c, _ := newTLSTestClient(t, "fs-lda-midfail", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"entries":[{"directory":{"path":"/a"}}],"cursor":"page2"}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("page 2 unavailable"))
	})
	entries, err := c.ListDirectoryAll(context.Background(), "/")
	if err == nil {
		t.Fatal("expected a page-2 error, got nil")
	}
	if entries != nil {
		t.Errorf("a mid-pagination failure must not return partial entries, got %d", len(entries))
	}
	if !strings.Contains(err.Error(), "ListDirectoryStream") {
		t.Errorf("error %q does not name the emitting function ListDirectoryStream", err.Error())
	}
	if callCount != 2 {
		t.Errorf("expected exactly 2 page calls before the failure halted paging, got %d", callCount)
	}
}

// TestListDirectoryStreamAbortsCursorCycle verifies the progress guard catches
// a cursor cycle LONGER than one: a broker paging bug that alternates two
// cursor values (A,B,A,B,...) never repeats the immediately-preceding cursor,
// yet the listing makes no progress — pagination must abort with the
// non-advancing-cursor error instead of looping forever re-yielding the same
// pages with unbounded memory growth.
func TestListDirectoryStreamAbortsCursorCycle(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Alternate two cursor values forever.
		next := "cursor-A"
		if callCount%2 == 0 {
			next = "cursor-B"
		}
		// Self-terminate after 64 pages so a guardless run ends in a completed
		// listing (failing the error assertion) instead of spinning the test.
		if callCount > 64 {
			next = ""
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(dirPage(callCount-1, 1, next))
	}

	c, _ := newTLSTestClient(t, "fs-cycle-dir", handler)
	err := c.ListDirectoryStream(context.Background(), "/d", func(ListDirEntry) error { return nil })
	if err == nil {
		t.Fatalf("an A,B,A,B cursor cycle must abort pagination, got nil error after %d pages", callCount)
	}
	if !strings.Contains(err.Error(), "did not advance") {
		t.Errorf("error %q does not name the non-advancing-cursor abort", err.Error())
	}
	if !strings.Contains(err.Error(), "ListDirectoryStream") {
		t.Errorf("error %q does not name the emitting function ListDirectoryStream", err.Error())
	}
	// Page 1 (sent "") returns A, page 2 (sent A) returns B, page 3 (sent B)
	// returns A again — the repeat is detectable at page 3.
	if callCount > 4 {
		t.Errorf("cycle caught after %d page calls, want it caught at the first repeated cursor", callCount)
	}
}

// TestListStreamsEnforcePageCeiling verifies the hard page ceiling: a broker
// that mints a DISTINCT cursor on every page forever defeats any repeat
// detection, so the loop must abort at the client's page ceiling instead of
// paging (and growing the caller's aggregate) without bound.
func TestListStreamsEnforcePageCeiling(t *testing.T) {
	const ceiling = 8

	t.Run("listDirectory", func(t *testing.T) {
		callCount := 0
		handler := func(w http.ResponseWriter, r *http.Request) {
			callCount++
			// A fresh cursor every page, never repeating, never ending.
			next := fmt.Sprintf("cursor-%d", callCount)
			// Self-terminate after 64 pages so a ceiling-less run completes and
			// fails the error assertion instead of spinning the test.
			if callCount > 64 {
				next = ""
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(dirPage(callCount-1, 1, next))
		}

		c, _ := newTLSTestClient(t, "fs-ceiling-dir", handler)
		c.maxListPages = ceiling
		err := c.ListDirectoryStream(context.Background(), "/d", func(ListDirEntry) error { return nil })
		if err == nil {
			t.Fatalf("a never-ending distinct-cursor listing must hit the page ceiling, got nil error after %d pages", callCount)
		}
		if !strings.Contains(err.Error(), "ceiling") {
			t.Errorf("error %q does not name the page ceiling", err.Error())
		}
		if callCount > ceiling {
			t.Errorf("made %d page calls, the %d-page ceiling must bound the loop", callCount, ceiling)
		}
	})
}

// dirPage renders a listDirectory page of perPage directory entries whose paths
// are globally unique and monotonically increasing, so a caller can check both
// completeness and order. cursor, when non-empty, is set on the response.
func dirPage(page, perPage int, cursor string) []byte {
	type dirEntry struct {
		Path string `json:"path"`
	}
	type entry struct {
		Directory *dirEntry `json:"directory,omitempty"`
	}
	type resp struct {
		Entries []entry `json:"entries,omitempty"`
		Cursor  string  `json:"cursor,omitempty"`
	}
	out := resp{Entries: make([]entry, 0, perPage), Cursor: cursor}
	for i := 0; i < perPage; i++ {
		idx := page*perPage + i
		out.Entries = append(out.Entries, entry{Directory: &dirEntry{Path: fmt.Sprintf("/d/%06d", idx)}})
	}
	b, _ := json.Marshal(out)
	return b
}

// TestListDirectoryAllLargeListing exercises the aggregation loop at volume,
// two-sided in one test. The advancing arm proves a broker returning many pages
// of many entries produces the complete listing in order, one call per page,
// without ever false-tripping the non-advancing-cursor progress guard. The stuck
// arm proves the same guard DOES fire when the broker stalls the cursor deep into
// a large listing — the loop aborts with a "did not advance" error rather than
// spinning forever with unbounded memory.
func TestListDirectoryAllLargeListing(t *testing.T) {
	const pages, perPage = 50, 200
	const total = pages * perPage

	t.Run("advancing_volume_completes", func(t *testing.T) {
		callCount := 0
		handler := func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Cursor string `json:"cursor,omitempty"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			// Page 1 arrives with an empty cursor; page N+1 carries "cursor-N".
			page := 0
			if body.Cursor != "" {
				if _, err := fmt.Sscanf(body.Cursor, "cursor-%d", &page); err != nil {
					t.Errorf("unexpected cursor echo %q", body.Cursor)
				}
			}
			callCount++
			next := ""
			if page < pages-1 {
				next = fmt.Sprintf("cursor-%d", page+1)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(dirPage(page, perPage, next))
		}

		c, _ := newTLSTestClient(t, "fs-large-dir", handler)
		entries, err := c.ListDirectoryAll(context.Background(), "/d")
		if err != nil {
			t.Fatalf("ListDirectoryAll over %d pages: %v", pages, err)
		}
		if len(entries) != total {
			t.Fatalf("aggregated %d entries, want %d (%d pages × %d)", len(entries), total, pages, perPage)
		}
		if callCount != pages {
			t.Errorf("made %d page calls, want %d (one per page)", callCount, pages)
		}
		// Order must be preserved end-to-end across every page boundary.
		for i, e := range entries {
			if e.Directory == nil {
				t.Fatalf("entries[%d].Directory is nil at volume", i)
			}
			want := fmt.Sprintf("/d/%06d", i)
			if e.Directory.Path != want {
				t.Fatalf("entries[%d].Path = %q, want %q — aggregation reordered or dropped entries", i, e.Directory.Path, want)
			}
		}
	})

	t.Run("stuck_cursor_at_volume_aborts", func(t *testing.T) {
		// The broker advances normally for a stretch of pages, then stalls: from
		// the stallAt page onward it echoes the SAME cursor the client just sent.
		// The guard must fire on the first non-advancing repeat, not before.
		const stallAt = 20
		const stuckCursor = "cursor-stuck"
		callCount := 0
		handler := func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Cursor string `json:"cursor,omitempty"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			callCount++
			var next string
			switch {
			case body.Cursor == stuckCursor:
				// The stall: echo the same cursor back, never advancing.
				next = stuckCursor
			case callCount >= stallAt:
				next = stuckCursor
			default:
				next = fmt.Sprintf("cursor-%d", callCount)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(dirPage(callCount-1, perPage, next))
		}

		c, _ := newTLSTestClient(t, "fs-large-dir-stuck", handler)
		entries, err := c.ListDirectoryAll(context.Background(), "/d")
		if err == nil {
			t.Fatalf("a stalled cursor at volume must abort, got %d entries and nil error", len(entries))
		}
		if entries != nil {
			t.Errorf("a non-progressing listing must not return a partial result, got %d entries", len(entries))
		}
		if !strings.Contains(err.Error(), "did not advance") {
			t.Errorf("error %q does not name the non-advancing-cursor abort", err.Error())
		}
		// The guard fires on the first repeat, not on a bounded runaway: the stall
		// begins at stallAt and the very next request repeats the cursor, so the
		// loop must stop within a couple of calls of the stall, never spinning.
		if callCount > stallAt+2 {
			t.Errorf("guard fired late after %d calls; the loop should abort on the first non-advancing repeat", callCount)
		}
	})
}
