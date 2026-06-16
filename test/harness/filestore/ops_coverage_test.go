// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// opServer builds a single-RW-scope server whose StaticCredentialValidator maps
// the bearer "rw-cred" to the scope, so handler arms can be driven directly.
func opServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	srv := NewServer(Options{
		Scopes:      []Scope{{FilesystemID: "fsrw", Root: root, ReadOnly: false}},
		Credentials: StaticCredentialValidator{Credentials: map[string]string{"rw-cred": "fsrw"}},
	})
	return srv, root
}

// do posts a JSON op body and returns the response recorder.
func do(t *testing.T, srv *Server, op string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, restBase+op, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer rw-cred")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// TestOpHandlerArms drives the create / mkdir / rmdir / copy / move handler arms,
// including the path-escape and conflict error branches, against the real server.
func TestOpHandlerArms(t *testing.T) {
	srv, _ := opServer(t)
	meta := map[string]any{"intent": "write"}

	// createFile success.
	if w := do(t, srv, "createFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "a.txt"}); w.Code != http.StatusOK {
		t.Fatalf("createFile returned %d, want 200", w.Code)
	}
	// createFile with a missing path field -> 400 (malformed body arm).
	if w := do(t, srv, "createFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": 12345}); w.Code != http.StatusBadRequest {
		t.Fatalf("createFile malformed path returned %d, want 400", w.Code)
	}

	// makeDirectory success then removeDirectory success.
	if w := do(t, srv, "makeDirectory", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "d"}); w.Code != http.StatusOK {
		t.Fatalf("makeDirectory returned %d, want 200", w.Code)
	}
	if w := do(t, srv, "removeDirectory", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "d"}); w.Code != http.StatusOK {
		t.Fatalf("removeDirectory returned %d, want 200", w.Code)
	}

	// copyFile success (a.txt -> b.txt) then a no-overwrite conflict.
	if w := do(t, srv, "copyFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "source": "a.txt", "destination": "b.txt"}); w.Code != http.StatusOK {
		t.Fatalf("copyFile returned %d, want 200", w.Code)
	}
	if w := do(t, srv, "copyFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "source": "a.txt", "destination": "b.txt"}); w.Code != http.StatusConflict {
		t.Fatalf("copyFile no-overwrite conflict returned %d, want 409", w.Code)
	}

	// moveFile success (b.txt -> c.txt).
	if w := do(t, srv, "moveFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "source": "b.txt", "destination": "c.txt"}); w.Code != http.StatusOK {
		t.Fatalf("moveFile returned %d, want 200", w.Code)
	}

	// moveFile with a malformed source field -> 400 (malformed body arm).
	if w := do(t, srv, "moveFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "source": 123, "destination": "y"}); w.Code != http.StatusBadRequest {
		t.Fatalf("moveFile malformed body returned %d, want 400", w.Code)
	}

	// removeFile success.
	if w := do(t, srv, "removeFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "c.txt"}); w.Code != http.StatusOK {
		t.Fatalf("removeFile returned %d, want 200", w.Code)
	}

	// makeDirectory / removeDirectory malformed-body arms -> 400.
	if w := do(t, srv, "makeDirectory", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": 99}); w.Code != http.StatusBadRequest {
		t.Fatalf("makeDirectory malformed returned %d, want 400", w.Code)
	}
	if w := do(t, srv, "removeDirectory", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": 99}); w.Code != http.StatusBadRequest {
		t.Fatalf("removeDirectory malformed returned %d, want 400", w.Code)
	}
	if w := do(t, srv, "removeFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": 99}); w.Code != http.StatusBadRequest {
		t.Fatalf("removeFile malformed returned %d, want 400", w.Code)
	}
	if w := do(t, srv, "copyFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "source": 1}); w.Code != http.StatusBadRequest {
		t.Fatalf("copyFile malformed returned %d, want 400", w.Code)
	}

	// Filesystem-error arms: with a regular file at "f", a makeDirectory and a
	// createFile UNDER it (treating the file as a parent dir) fail in the OS and
	// surface through writeMetaError, covering those handler arms.
	if w := do(t, srv, "createFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "f"}); w.Code != http.StatusOK {
		t.Fatalf("createFile f returned %d, want 200", w.Code)
	}
	if w := do(t, srv, "makeDirectory", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "f/under"}); w.Code == http.StatusOK {
		t.Fatalf("makeDirectory under a file unexpectedly succeeded")
	}
	if w := do(t, srv, "createFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "f/child"}); w.Code == http.StatusOK {
		t.Fatalf("createFile under a file unexpectedly succeeded")
	}
	// readMetadata / readFile on a missing path -> 404 (writeMetaError not-found arm).
	if w := do(t, srv, "readMetadata", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("readMetadata missing returned %d, want 404", w.Code)
	}
	if w := do(t, srv, "removeFile", map[string]any{"filesystem_id": "fsrw", "authorization_metadata": meta, "path": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("removeFile missing returned %d, want 404", w.Code)
	}
}
