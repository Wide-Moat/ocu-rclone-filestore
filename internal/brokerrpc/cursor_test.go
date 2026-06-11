// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"context"
	"encoding/json"
	"net/http"
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

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
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
			// Page 1: return cursor pointing to page 2.
			type entry struct {
				Path string `json:"path"`
			}
			type resp struct {
				Entries []entry `json:"entries,omitempty"`
				Cursor  string  `json:"cursor,omitempty"`
			}
			respBody, _ = json.Marshal(resp{
				Entries: []entry{{Path: "/a"}},
				Cursor:  page1Cursor,
			})
		} else {
			// Page 2: return empty cursor (last page).
			type entry struct {
				Path string `json:"path"`
			}
			type resp struct {
				Entries []entry `json:"entries,omitempty"`
			}
			respBody, _ = json.Marshal(resp{
				Entries: []entry{{Path: "/b"}},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	})

	c, _ := New(sock, "fs-cursor-01")
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

// TestListFilesCursorEchoedUnmodified verifies that the uuid-paginated
// listFiles cursor is echoed back verbatim (opaque echo, never inspected).
func TestListFilesCursorEchoedUnmodified(t *testing.T) {
	page1Cursor := "after-uuid-ABCDEF"
	var page2AfterUUID string
	callCount := 0

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var body struct {
			AfterUUID string `json:"after_uuid,omitempty"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if callCount == 2 {
			page2AfterUUID = body.AfterUUID
		}

		type file struct {
			UUID string `json:"uuid"`
		}
		type resp struct {
			Files     []file `json:"files,omitempty"`
			AfterUUID string `json:"after_uuid,omitempty"`
		}
		var respBody []byte
		if callCount == 1 {
			respBody, _ = json.Marshal(resp{
				Files:     []file{{UUID: "u1"}},
				AfterUUID: page1Cursor,
			})
		} else {
			respBody, _ = json.Marshal(resp{
				Files: []file{{UUID: "u2"}},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	})

	c, _ := New(sock, "fs-cursor-01")
	files, err := c.ListFilesAll(context.Background(), "root-uuid")
	if err != nil {
		t.Fatalf("ListFilesAll: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files across 2 pages, got %d", len(files))
	}
	if page2AfterUUID != page1Cursor {
		t.Errorf("after_uuid echo: got %q, want %q", page2AfterUUID, page1Cursor)
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
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Always return the SAME non-empty cursor — never advances.
		type entry struct {
			Path string `json:"path"`
		}
		type resp struct {
			Entries []entry `json:"entries,omitempty"`
			Cursor  string  `json:"cursor,omitempty"`
		}
		respBody, _ := json.Marshal(resp{
			Entries: []entry{{Path: "/x"}},
			Cursor:  "stuck-cursor",
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	})

	c, _ := New(sock, "fs-cursor-01")
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

// TestListFilesAllStopsOnNonAdvancingCursor verifies the same progress guard
// for the uuid-paginated listFiles path (MD-03).
func TestListFilesAllStopsOnNonAdvancingCursor(t *testing.T) {
	callCount := 0
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		type file struct {
			UUID string `json:"uuid"`
		}
		type resp struct {
			Files     []file `json:"files,omitempty"`
			AfterUUID string `json:"after_uuid,omitempty"`
		}
		respBody, _ := json.Marshal(resp{
			Files:     []file{{UUID: "u"}},
			AfterUUID: "stuck-after-uuid",
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	})

	c, _ := New(sock, "fs-cursor-01")
	_, err := c.ListFilesAll(context.Background(), "root-uuid")
	if err == nil {
		t.Fatal("expected error on non-advancing after_uuid, got nil (would loop forever)")
	}
	if callCount > 3 {
		t.Errorf("expected the loop to abort quickly, got %d calls", callCount)
	}
}
