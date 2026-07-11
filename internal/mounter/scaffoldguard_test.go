// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureMountpointShadowsNoContent covers the direct branch surface of the
// shadow guard (F-31/F-32): the tolerated scaffold shapes pass, every real-
// content shape fails naming the offending path, and the missing-destination
// case gets its own non-shadow wording.
func TestEnsureMountpointShadowsNoContent(t *testing.T) {
	t.Run("empty destination passes", func(t *testing.T) {
		if err := ensureMountpointShadowsNoContent(t.TempDir()); err != nil {
			t.Fatalf("empty destination refused: %v", err)
		}
	})

	t.Run("dirs-only scaffold passes", func(t *testing.T) {
		dest := t.TempDir()
		for _, d := range []string{"outputs", "uploads", "outputs/nested"} {
			if err := os.MkdirAll(filepath.Join(dest, d), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}
		if err := ensureMountpointShadowsNoContent(dest); err != nil {
			t.Fatalf("dirs-only scaffold refused: %v", err)
		}
	})

	t.Run("top-level file refused with path and remedy", func(t *testing.T) {
		dest := t.TempDir()
		if err := os.WriteFile(filepath.Join(dest, "data.bin"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		err := ensureMountpointShadowsNoContent(dest)
		if err == nil {
			t.Fatal("a destination holding a file passed the guard")
		}
		if !strings.Contains(err.Error(), "data.bin") || !strings.Contains(err.Error(), "restart the mount") {
			t.Errorf("error %q lacks the offending path or the remedy", err.Error())
		}
	})

	t.Run("nested file refused", func(t *testing.T) {
		dest := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dest, "outputs", "deep"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dest, "outputs", "deep", "note.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		err := ensureMountpointShadowsNoContent(dest)
		if err == nil {
			t.Fatal("a nested file passed the guard")
		}
		if !strings.Contains(err.Error(), "note.txt") {
			t.Errorf("error %q does not name the nested offending path", err.Error())
		}
	})

	t.Run("symlink refused", func(t *testing.T) {
		dest := t.TempDir()
		if err := os.Symlink("/etc", filepath.Join(dest, "link")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		err := ensureMountpointShadowsNoContent(dest)
		if err == nil {
			t.Fatal("a symlink passed the guard")
		}
		if !strings.Contains(err.Error(), "link") {
			t.Errorf("error %q does not name the symlink", err.Error())
		}
	})

	t.Run("entry ceiling refused as real content", func(t *testing.T) {
		dest := t.TempDir()
		for i := 0; i <= scaffoldWalkEntryCeiling; i++ {
			if err := os.Mkdir(filepath.Join(dest, fmt.Sprintf("d%05d", i)), 0o755); err != nil {
				t.Fatalf("mkdir %d: %v", i, err)
			}
		}
		err := ensureMountpointShadowsNoContent(dest)
		if err == nil {
			t.Fatal("a tree wider than the entry ceiling passed the guard")
		}
		if !strings.Contains(err.Error(), "entries under the mount destination") {
			t.Errorf("error %q is not the ceiling refusal", err.Error())
		}
	})

	t.Run("missing destination gets its own wording", func(t *testing.T) {
		err := ensureMountpointShadowsNoContent(filepath.Join(t.TempDir(), "absent"))
		if err == nil {
			t.Fatal("a missing destination passed the guard")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error %q is not the missing-destination message", err.Error())
		}
		if strings.Contains(err.Error(), "refusing to shadow") {
			t.Errorf("error %q words a missing destination as shadow-refusal", err.Error())
		}
	})
}
