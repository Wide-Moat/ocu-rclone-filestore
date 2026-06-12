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
// /dev/fuse. The readyTimeout is set tiny so WaitMountReady fails fast on the
// non-mounted directory rather than blocking on its ~30s spin-poll — the test
// asserts the fake MountFn WAS invoked (proving Mount ran over the assembled
// options) and that the failure is the expected WaitMountReady error, not an
// option-assembly error.
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

	_, err := r.mountAndWaitReady(context.Background(), spec)
	if err == nil {
		t.Fatal("mountAndWaitReady over a fake MountFn returned nil error; want the WaitMountReady failure on the non-mounted dir")
	}
	if !invoked {
		t.Fatal("fake MountFn was never invoked: option assembly errored before Mount, or NewMountPoint/Mount was not reached")
	}
	// The failure must be the readiness wait, not an option-assembly error: the
	// error string names the destination and the wait stage.
	if got := err.Error(); !strings.Contains(got, "wait for mount ready") {
		t.Fatalf("mountAndWaitReady error = %q; want the WaitMountReady stage to fail after option assembly", got)
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
