// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rclone/rclone/fs/config"
)

// withSavedCacheDir saves and restores the process-global rclone cache dir so a
// test that calls SetCacheDir does not leak the mutation into sibling tests.
// The global is why these tests must not run in parallel.
func withSavedCacheDir(t *testing.T) {
	t.Helper()
	saved := config.GetCacheDir()
	t.Cleanup(func() { _ = config.SetCacheDir(saved) })
}

// TestEnsureWritableCacheDirLeavesWritableDefaultUntouched pins that an already
// writable resolved cache dir is not redirected — the development and CI path,
// where overriding a deliberate location would be wrong.
func TestEnsureWritableCacheDirLeavesWritableDefaultUntouched(t *testing.T) {
	withSavedCacheDir(t)

	writable := t.TempDir()
	if err := config.SetCacheDir(writable); err != nil {
		t.Fatalf("seed writable cache dir: %v", err)
	}
	want := config.GetCacheDir()

	if err := EnsureWritableCacheDir(); err != nil {
		t.Fatalf("EnsureWritableCacheDir on a writable default: %v", err)
	}
	if got := config.GetCacheDir(); got != want {
		t.Fatalf("writable default was redirected: got %q, want unchanged %q", got, want)
	}
}

// TestEnsureWritableCacheDirRedirectsFromReadOnlyDefault pins the core fix: when
// the resolved default is not writable, the cache dir is redirected to a
// writable fallback rather than left on the doomed path. It models the read-only
// rootfs by pointing the default at a path under a file (which cannot be a
// directory) and making the first candidate resolvable via a redirected HOME.
func TestEnsureWritableCacheDirRedirectsFromReadOnlyDefault(t *testing.T) {
	withSavedCacheDir(t)

	// A path whose parent is a regular file: MkdirAll under it always fails, so
	// dirIsWritable reports false — a stand-in for the read-only-rootfs default.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	unwritable := filepath.Join(blocker, "cache")
	if err := config.SetCacheDir(unwritable); err != nil {
		t.Fatalf("seed unwritable cache dir: %v", err)
	}

	if err := EnsureWritableCacheDir(); err != nil {
		t.Fatalf("EnsureWritableCacheDir should redirect, not error, when a fallback is writable: %v", err)
	}

	got := config.GetCacheDir()
	if got == unwritable {
		t.Fatalf("cache dir was not redirected off the unwritable default %q", unwritable)
	}
	if !dirIsWritable(got) {
		t.Fatalf("redirected cache dir %q is not writable", got)
	}
}

// TestDirIsWritable pins the probe: a writable dir is true, an empty path and a
// path under a regular file are false.
func TestDirIsWritable(t *testing.T) {
	if !dirIsWritable(t.TempDir()) {
		t.Fatal("a fresh temp dir must be writable")
	}
	if dirIsWritable("") {
		t.Fatal("an empty path must not be writable")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if dirIsWritable(filepath.Join(blocker, "sub")) {
		t.Fatal("a path under a regular file must not be writable")
	}
}
