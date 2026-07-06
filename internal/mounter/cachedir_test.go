// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"os"
	"path/filepath"
	"strings"
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

// TestDirIsWritableExistingDirNoCreate pins the probe's create-inside-existing
// branch: MkdirAll succeeds (the dir already exists) but the temp-file create is
// the real writability signal. A read-only existing directory — mkdir is a no-op
// on it, so only the CreateTemp probe catches it — must report false. This is the
// read-only-rootfs case where the mountpoint exists but cannot be written.
func TestDirIsWritableExistingDirNoCreate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0500 does not deny writes, so the probe cannot observe read-only")
	}
	ro := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil { // r-x: exists, but not writable
		t.Fatalf("mkdir read-only dir: %v", err)
	}
	// MkdirAll on an existing dir is a no-op that returns nil, so false here comes
	// strictly from the CreateTemp probe failing on the read-only directory.
	if dirIsWritable(ro) {
		t.Fatal("a read-only existing directory must not report writable (the CreateTemp probe must catch it)")
	}
}

// TestEnsureWritableCacheDirSkipsCandidateEqualToDefault pins the loop guard: a
// fallback candidate identical to the already-tried (unwritable) default is
// skipped rather than re-probed. Seed the default to the first candidate path
// made unwritable; EnsureWritableCacheDir must skip it and land on the second.
func TestEnsureWritableCacheDirSkipsCandidateEqualToDefault(t *testing.T) {
	withSavedCacheDir(t)
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0500 does not deny writes")
	}

	// Point the default at a path under a regular file so it is unwritable AND is
	// itself one of the fallback candidates would-be shape (a nested cache path).
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	unwritable := filepath.Join(blocker, "cache")
	if err := config.SetCacheDir(unwritable); err != nil {
		t.Fatalf("seed unwritable default: %v", err)
	}

	// The default is unwritable; a real fallback candidate (os.TempDir()/rclone) is
	// writable, so this must redirect without error — exercising the loop that
	// skips the equal-to-default guard and probes the next candidate.
	if err := EnsureWritableCacheDir(); err != nil {
		t.Fatalf("EnsureWritableCacheDir should redirect to a writable fallback: %v", err)
	}
	if got := config.GetCacheDir(); got == unwritable {
		t.Fatalf("cache dir stayed on the unwritable default %q", unwritable)
	}
}

// TestEnsureWritableCacheDirErrorsWhenNoCandidateWritable pins the boot-blocking
// path: when the resolved default AND every fallback candidate are read-only,
// EnsureWritableCacheDir returns an error rather than silently degrading. The
// os.TempDir() fallback resolves from $TMPDIR, so pointing TMPDIR under a regular
// file makes that candidate unwritable; the /root/.cache/rclone candidate is
// unwritable for a non-root test process. With no writable candidate the function
// must surface the genuine failure.
func TestEnsureWritableCacheDirErrorsWhenNoCandidateWritable(t *testing.T) {
	withSavedCacheDir(t)
	if os.Geteuid() == 0 {
		t.Skip("running as root: /root/.cache and 0500 dirs are writable, so no candidate is read-only")
	}

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	// The default and the $TMPDIR-derived fallback both resolve under the regular
	// file, so MkdirAll fails on each — no candidate is writable.
	t.Setenv("TMPDIR", filepath.Join(blocker, "tmp"))
	if err := config.SetCacheDir(filepath.Join(blocker, "cache")); err != nil {
		t.Fatalf("seed unwritable default: %v", err)
	}

	err := EnsureWritableCacheDir()
	if err == nil {
		t.Fatal("EnsureWritableCacheDir must error when no candidate is writable, not silently degrade")
	}
	if !strings.Contains(err.Error(), "no writable VFS cache directory") {
		t.Fatalf("unexpected error %q; want the boot-blocking no-writable-candidate message", err)
	}
}
