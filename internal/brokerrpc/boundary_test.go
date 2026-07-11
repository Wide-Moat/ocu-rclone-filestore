// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// TestListDirectoryAllZeroEntriesSinglePage verifies the empty-listing boundary
// for the recursive listDirectory path: a single page carrying zero entries and
// an empty cursor must terminate after exactly ONE call and return a usable
// (non-nil-deref) result of length zero.
func TestListDirectoryAllZeroEntriesSinglePage(t *testing.T) {
	var callCount int
	c, _ := newTLSTestClient(t, "fs-empty-01", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	entries, err := c.ListDirectoryAll(context.Background(), "/")
	if err != nil {
		t.Fatalf("ListDirectoryAll on empty page: %v", err)
	}
	if callCount != 1 {
		t.Errorf("empty cursor must terminate after one call, got %d calls", callCount)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
	for range entries {
		t.Error("ranged over a supposedly empty entry list")
	}
}
