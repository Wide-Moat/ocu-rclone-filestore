// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/cmd/mountlib"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/vfs"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// TestResolveMountMethodReachable proves the thin-wrapper discipline holds: a
// blank import of cmd/mount2 self-registers its mount function under the name
// "mount2", and mountlib.ResolveMountMethod resolves it from the registry with
// ZERO upstream diff. This file carries mount2's build tag, so it compiles only
// where mount2 registers a function; the authoritative gate is the linux CI leg.
// On a platform where the lookup returns nil here, that is a hard STOP — the
// registry approach failed and a fork would be the only alternative.
func TestResolveMountMethodReachable(t *testing.T) {
	name, fn := mountlib.ResolveMountMethod("mount2")
	if name != "mount2" {
		t.Fatalf("ResolveMountMethod(\"mount2\") name = %q, want \"mount2\"", name)
	}
	if fn == nil {
		t.Fatal("ResolveMountMethod(\"mount2\") returned a nil MountFn on a mount2-supported platform: the registry lookup failed and the thin-wrapper approach is broken")
	}
}

// TestNewRealPointMounterFailsClosed asserts the production seam constructor
// returns the typed fail-closed error when handed a nil MountFn (the mount
// method is unavailable), never a silent no-op (MNT-02).
func TestNewRealPointMounterFailsClosed(t *testing.T) {
	_, err := newRealPointMounter(nil)
	if !errors.Is(err, errMountMethodUnavailable) {
		t.Fatalf("newRealPointMounter(nil) error = %v; want errMountMethodUnavailable", err)
	}
}

// fakeMountFn records that it was invoked and returns a benign errChan plus a
// no-op unmount. It performs no real kernel mount, so it drives the seam's
// option-assembly and MountPoint construction without /dev/fuse.
func fakeMountFn(invoked *bool) mountlib.MountFn {
	return func(_ *vfs.VFS, mountpoint string, _ *mountlib.Options) (<-chan error, func() error, string, error) {
		*invoked = true
		errChan := make(chan error, 1)
		unmount := func() error { return nil }
		return errChan, unmount, mountpoint, nil
	}
}

// fsID returns a pointer to a filesystem id literal for the test config.
func fsID(s string) *string { return &s }

// TestMountAndWaitReadyAssemblesOptions drives mountAndWaitReady with a FAKE
// MountFn so the option-assembly (ocufs Fs build via the registry, the mapped
// VFS/mount options) and the NewMountPoint/Mount call are covered with no
// /dev/fuse. The readyTimeout is set tiny so the readiness poll fails fast on
// the non-mounted directory rather than blocking on the full ~30s poll.
//
// The readiness assertion is leg-dependent because the seam polls only where
// the kernel can be queried (it no longer calls the nil-daemon
// mountlib.WaitMountReady, which crashed on the first not-ready poll):
//   - linux (mountlib.CanCheckMountReady=true): CheckMountReady on a plain
//     non-mounted temp dir never succeeds, so the poll times out and returns
//     the wrapped "wait for mount ready" error after option assembly.
//   - darwin/amd64 (CanCheckMountReady=false): readiness cannot be kernel-
//     verified; since Mount() already succeeded the seam blind-trusts and
//     returns a live point with no error.
//
// Either way the fake MountFn MUST have been invoked, proving Mount ran over the
// assembled options (no option-assembly error short-circuited it).
func TestMountAndWaitReadyAssemblesOptions(t *testing.T) {
	var invoked bool
	r := &realPointMounter{
		mountFn:      fakeMountFn(&invoked),
		readyTimeout: 10 * time.Millisecond,
	}

	spec := mountSpec{
		mount: mountcfg.Mount{
			Destination:     t.TempDir(),
			FilesystemID:    fsID("session_unit_fs"),
			VfsCacheMode:    "writes",
			VfsCacheMaxSize: "256M",
			DirPerms:        "0755",
			FilePerms:       "0644",
		},
		readOnly:   false,
		socketPath: "/tmp/ocufs-unit-not-dialed.sock",
	}

	p, err := r.mountAndWaitReady(context.Background(), spec)

	if !invoked {
		t.Fatal("fake MountFn was never invoked: option assembly errored before Mount, or NewMountPoint/Mount was not reached")
	}

	if mountlib.CanCheckMountReady {
		// linux: the poll over a non-mounted dir must time out with the wrapped
		// readiness error — NOT crash (the old nil-daemon WaitMountReady path
		// SIGSEGV'd here) and NOT an option-assembly error.
		if err == nil {
			t.Fatal("mountAndWaitReady returned nil on a leg that polls readiness; want the readiness timeout error on the non-mounted dir")
		}
		if got := err.Error(); !strings.Contains(got, "wait for mount ready") {
			t.Fatalf("mountAndWaitReady error = %q; want the readiness stage to fail after option assembly", got)
		}
		return
	}

	// darwin/amd64: readiness is blind-trusted, so a live point is returned.
	if err != nil {
		t.Fatalf("mountAndWaitReady on a non-polling leg returned %v; want a blind-trusted point", err)
	}
	if p == nil {
		t.Fatal("mountAndWaitReady on a non-polling leg returned a nil point; want a live point")
	}
}

// capturingMountFn records the *vfs.VFS handed to each Mount call so a test can
// assert two mounts received DISTINCT VFS instances (no active-cache collision).
func capturingMountFn(seen *[]*vfs.VFS) mountlib.MountFn {
	return func(v *vfs.VFS, mountpoint string, _ *mountlib.Options) (<-chan error, func() error, string, error) {
		*seen = append(*seen, v)
		errChan := make(chan error, 1)
		unmount := func() error { return nil }
		return errChan, unmount, mountpoint, nil
	}
}

// TestMountIdentityIsPerMount is the CR-01 regression: two specs with IDENTICAL
// mapped VFS options but DIFFERENT destinations must NOT collide in rclone's
// package-level active-VFS cache (keyed on the Fs ConfigString + options). With
// the constant Fs identity the second mount silently received the first mount's
// VFS bound to the first filesystem_id — a cross-scope exposure. We drive two
// mountAndWaitReady calls through a capturing fake MountFn and assert the two
// mounts received DISTINCT *vfs.VFS and DISTINCT Fs ConfigString.
func TestMountIdentityIsPerMount(t *testing.T) {
	var seen []*vfs.VFS
	r := &realPointMounter{
		mountFn:      capturingMountFn(&seen),
		readyTimeout: 10 * time.Millisecond,
	}

	mk := func(dest, fsid string) mountSpec {
		return mountSpec{
			mount: mountcfg.Mount{
				Destination:     dest,
				FilesystemID:    fsID(fsid),
				VfsCacheMode:    "writes",
				VfsCacheMaxSize: "256M",
				DirPerms:        "0755",
				FilePerms:       "0644",
			},
			readOnly:   false,
			socketPath: "/tmp/ocufs-unit-not-dialed.sock",
		}
	}

	specA := mk(t.TempDir(), "session_fs_a")
	specB := mk(t.TempDir(), "session_fs_b")

	// The MountFn records the VFS before readiness is polled, so the captured
	// handles are populated regardless of the leg's readiness outcome (linux
	// times out over the non-mounted dir; darwin/amd64 blind-trusts). We ignore
	// the readiness error here — this test is about VFS/Fs identity, not
	// readiness.
	_, _ = r.mountAndWaitReady(context.Background(), specA)
	_, _ = r.mountAndWaitReady(context.Background(), specB)

	if len(seen) != 2 {
		t.Fatalf("MountFn invoked %d times; want 2 (both mounts reached Mount)", len(seen))
	}
	if seen[0] == seen[1] {
		t.Fatal("the two mounts received the SAME *vfs.VFS: active-cache collision (CR-01) — the second mount serves the first filesystem")
	}
	csA := fs.ConfigString(seen[0].Fs())
	csB := fs.ConfigString(seen[1].Fs())
	if csA == csB {
		t.Fatalf("Fs ConfigString identical for distinct mounts (%q == %q): the active-VFS cache key collides (CR-01)", csA, csB)
	}
}

// TestRealPointMounterUnmountTypeGuard asserts unmount rejects a foreign point
// type rather than panicking.
func TestRealPointMounterUnmountTypeGuard(t *testing.T) {
	r := &realPointMounter{}
	err := r.unmount(stubPoint{})
	if err == nil {
		t.Fatal("unmount of a foreign point type returned nil; want a typed error")
	}
}

// stubPoint is a point of a type the real seam does not produce.
type stubPoint struct{}

func (stubPoint) destination() string { return "/stub" }
func (stubPoint) wait() error         { return nil }
