// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rclone/rclone/fs/config"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/posture"
)

// EnsureWritableCacheDir guarantees the VFS disk cache has a writable directory
// before any mount starts, independent of the process environment.
//
// The VFS cache path is a single global rclone value: config.GetCacheDir(),
// resolved once at rclone init from os.UserCacheDir() — i.e. $XDG_CACHE_HOME or
// $HOME/.cache, with a fall-through to os.TempDir(). Under the guest's hardened
// posture the container root filesystem is read-only and the only writable
// surface is a tmpfs at /root/.cache. When HOME is unset (the distroless base
// image sets none), os.UserCacheDir() resolves to a root-level /.cache (or an
// equally read-only /tmp) and the cache directory cannot be created — the VFS
// silently disables its disk cache and the SEC-46 hold-data-across-throttle path
// degrades to memory-only.
//
// The image ships HOME=/root so the default resolves onto the tmpfs, but the
// mount binary must not depend on the launcher setting that env: a per-session
// launch, a bare-binary invocation, or a re-based image that drops the ENV would
// each re-open the same silent degrade. This function is the binary-owned
// invariant: it probes the resolved cache dir and, only if it is not writable,
// redirects the global cache dir to the first writable candidate. A cache dir
// that is already writable (the normal development and CI case) is left
// untouched, so this never overrides a deliberately configured location.
//
// Candidates, in order: the posture tmpfs mount (/root/.cache/rclone, matching
// what HOME=/root would yield) and finally os.TempDir()/rclone. It returns an
// error only when no candidate — including the current default — is writable,
// which is a genuine boot-blocking condition rather than a silent degrade.
func EnsureWritableCacheDir() error {
	current := config.GetCacheDir()
	if dirIsWritable(current) {
		return nil
	}

	// The resolved default is not writable (typically root-level /.cache under a
	// read-only rootfs with HOME unset). Fall back to a candidate that matches
	// the hardened posture's writable tmpfs — the single declared posture value
	// (posture.CacheTmpfs, what HOME=posture.Home would yield), so the binary
	// never carries its own copy of the deploy-layer path.
	candidates := []string{
		filepath.Join(posture.CacheTmpfs, "rclone"),
		filepath.Join(os.TempDir(), "rclone"),
	}
	for _, dir := range candidates {
		if dir == current {
			continue // already tried as the default
		}
		if dirIsWritable(dir) {
			if err := config.SetCacheDir(dir); err != nil {
				return fmt.Errorf("redirect VFS cache dir to %q: %w", dir, err)
			}
			return nil
		}
	}
	return fmt.Errorf("no writable VFS cache directory: default %q and fallbacks are all read-only (SEC-46 cache would silently disable)", current)
}

// dirIsWritable reports whether dir can hold the VFS cache: it creates dir (and
// parents) if absent and confirms a file can be created and removed inside it.
// A create/probe failure — the read-only-rootfs case — returns false so the
// caller can fall back rather than proceed onto a cache dir that will fail on
// first write.
func dirIsWritable(dir string) bool {
	if dir == "" {
		return false
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	probe, err := os.CreateTemp(dir, ".ocu-cache-probe-")
	if err != nil {
		return false
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return true
}
