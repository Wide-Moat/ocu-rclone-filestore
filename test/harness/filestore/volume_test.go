// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUnderConfinesAndEscapes(t *testing.T) {
	root := t.TempDir()

	// A normal relative path resolves under the root.
	got, err := resolveUnder(root, "/a/b.txt")
	if err != nil {
		t.Fatalf("resolveUnder: %v", err)
	}
	if filepath.Dir(filepath.Dir(got)) != root {
		t.Fatalf("resolved %q not under root %q", got, root)
	}

	// A traversal is cleaned back under the root rather than escaping.
	got, err = resolveUnder(root, "/../../../etc/passwd")
	if err != nil {
		t.Fatalf("traversal resolveUnder: %v", err)
	}
	if filepath.Dir(got) != root && got != root {
		// It must remain under root.
		rel, rerr := filepath.Rel(root, got)
		if rerr != nil || len(rel) >= 2 && rel[0] == '.' && rel[1] == '.' {
			t.Fatalf("traversal escaped root: %q", got)
		}
	}

	// The root itself resolves to the root.
	got, err = resolveUnder(root, "/")
	if err != nil {
		t.Fatalf("root resolveUnder: %v", err)
	}
	if got != root {
		t.Fatalf("root path: got %q want %q", got, root)
	}
}

func TestWriteMetaErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{os.ErrNotExist, http.StatusNotFound},
		{os.ErrExist, http.StatusConflict},
		{os.ErrPermission, http.StatusInternalServerError},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		writeMetaError(rec, c.err)
		if rec.Code != c.want {
			t.Fatalf("writeMetaError(%v): got %d want %d", c.err, rec.Code, c.want)
		}
	}
}

func TestFileMetaMissing(t *testing.T) {
	scope := Scope{FilesystemID: fsOutputs, Root: t.TempDir()}
	if _, _, _, _, err := fileMeta(scope, "/nope", filepath.Join(scope.Root, "nope")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestRelPathForUUIDMissAndHit(t *testing.T) {
	root := t.TempDir()
	scope := Scope{FilesystemID: fsOutputs, Root: root}
	if err := os.WriteFile(filepath.Join(root, "found.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	uuid := uuidForRelPath(fsOutputs, "/found.txt")
	rel, ok := relPathForUUID(scope, uuid)
	if !ok || rel != "found.txt" {
		t.Fatalf("hit: got rel=%q ok=%v", rel, ok)
	}
	if _, ok := relPathForUUID(scope, "0000000000000000"); ok {
		t.Fatalf("miss: expected no hit for unknown uuid")
	}
}

func TestUUIDForRelPathDeterministicPerScope(t *testing.T) {
	a := uuidForRelPath("fs-1", "/x")
	b := uuidForRelPath("fs-2", "/x")
	if a == b {
		t.Fatalf("uuid must be scoped by filesystem_id")
	}
	if a != uuidForRelPath("fs-1", "x") {
		t.Fatalf("uuid must be stable across a leading-slash difference")
	}
}

func TestMkdirParentFailsOnFileInPath(t *testing.T) {
	// Create a regular file, then try to create a file whose parent path
	// component is that file: MkdirAll fails, surfacing a 500.
	e := newTestEnv(t)
	resp := e.post(t, e.outputsCred, string(opCreateFile), jsonBody(fsOutputs, "write", map[string]any{"path": "/blocker"}))
	_ = resp.Body.Close()
	resp = e.post(t, e.outputsCred, string(opCreateFile), jsonBody(fsOutputs, "write", map[string]any{"path": "/blocker/child.txt"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("mkdir over file: got %d want 500", resp.StatusCode)
	}
}

func TestUploadMkdirParentFailsOnFileInPath(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, e.outputsCred, string(opCreateFile), jsonBody(fsOutputs, "write", map[string]any{"path": "/ublock"}))
	_ = resp.Body.Close()
	r := e.upload(t, e.outputsCred, fsOutputs, "/ublock/child.bin", []byte("x"), false)
	defer func() { _ = r.Body.Close() }()
	if r.StatusCode != http.StatusInternalServerError {
		t.Fatalf("upload mkdir over file: got %d want 500", r.StatusCode)
	}
}

func TestReadMetadataDirectoryArm(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, e.outputsCred, string(opMakeDirectory), jsonBody(fsOutputs, "write", map[string]any{"path": "/somedir"}))
	_ = resp.Body.Close()
	resp = e.post(t, e.outputsCred, string(opReadMetadata), jsonBody(fsOutputs, "read", map[string]any{"path": "/somedir"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readMetadata dir: got %d want 200", resp.StatusCode)
	}
}

func TestListDirectoryWithSubdir(t *testing.T) {
	e := newTestEnv(t)
	// A directory containing both a file and a subdirectory exercises both list
	// arms (file entry and directory entry).
	resp := e.post(t, e.outputsCred, string(opMakeDirectory), jsonBody(fsOutputs, "write", map[string]any{"path": "/parent/sub"}))
	_ = resp.Body.Close()
	resp = e.post(t, e.outputsCred, string(opCreateFile), jsonBody(fsOutputs, "write", map[string]any{"path": "/parent/file.txt"}))
	_ = resp.Body.Close()
	resp = e.post(t, e.outputsCred, string(opListDirectory), jsonBody(fsOutputs, "read", map[string]any{"path": "/parent"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list mixed: got %d want 200", resp.StatusCode)
	}
}
