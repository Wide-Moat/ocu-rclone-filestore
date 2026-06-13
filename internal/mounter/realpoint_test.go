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
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/vfs"
	"github.com/rclone/rclone/vfs/vfscommon"

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

// countingUnmountMountFn returns a MountFn whose unmount closure increments
// *count, so a test can assert how many times the underlying unmount ran.
func countingUnmountMountFn(count *int) mountlib.MountFn {
	return func(_ *vfs.VFS, mountpoint string, _ *mountlib.Options) (<-chan error, func() error, string, error) {
		errChan := make(chan error, 1)
		unmount := func() error { *count++; return nil }
		return errChan, unmount, mountpoint, nil
	}
}

// TestRealPointDoUnmountOnce is the WR-01 guard: routing two unmount calls on the
// SAME realPoint through the seam must invoke the underlying mp.Unmount() exactly
// once. On a live mount the orchestrator's signal-teardown can race the point's
// own Wait()-driven finalise; the sync.Once removes the double-call from OUR
// path (the rclone-internal finalise is out of scope here).
func TestRealPointDoUnmountOnce(t *testing.T) {
	var count int
	mountFn := countingUnmountMountFn(&count)
	r := &realPointMounter{mountFn: mountFn, readyTimeout: 10 * time.Millisecond}

	// Build a real ocufs Fs (vfs.New needs a non-nil Fs) and a MountPoint over
	// the counting MountFn, then start it so UnmountFn is wired.
	info, err := fs.Find("ocufs")
	if err != nil {
		t.Fatalf("ocufs backend not registered: %v", err)
	}
	cm := configmap.Simple{}
	cm.Set("socket_path", "/tmp/ocufs-unit-not-dialed.sock")
	cm.Set("filesystem_id", "session_unit_fs")
	cm.Set("read_only", "false")
	fsObj, err := info.NewFs(context.Background(), "ocufs-wr01", "", cm)
	if err != nil {
		t.Fatalf("build ocufs Fs: %v", err)
	}
	mp := mountlib.NewMountPoint(mountFn, t.TempDir(), fsObj, &mountlib.Options{}, &vfscommon.Options{})
	if _, err := mp.Mount(); err != nil {
		t.Fatalf("mp.Mount(): %v", err)
	}
	p := &realPoint{dest: mp.MountPoint, mp: mp}

	if err := r.unmount(p); err != nil {
		t.Fatalf("first unmount: %v", err)
	}
	if err := r.unmount(p); err != nil {
		t.Fatalf("second unmount: %v", err)
	}
	if count != 1 {
		t.Fatalf("underlying unmount ran %d times; want exactly 1 (sync.Once must dedup OUR path)", count)
	}
}

// blockingUnmountMountFn returns a MountFn whose UnmountFn never returns until
// stop is closed, modelling the in-process kernel detach that does not return
// on a userspace-kernel sandbox. The error channel and mountpoint are benign.
func blockingUnmountMountFn(stop <-chan struct{}) mountlib.MountFn {
	return func(_ *vfs.VFS, mountpoint string, _ *mountlib.Options) (<-chan error, func() error, string, error) {
		errChan := make(chan error, 1)
		unmount := func() error { <-stop; return nil }
		return errChan, unmount, mountpoint, nil
	}
}

// TestDoUnmountBoundsTheDetach pins the sandbox-tier teardown contract: when the
// in-process kernel detach does not return within the grace window, doUnmount
// stops waiting and reports the typed errDetachDidNotReturn (the drain already
// ran, and the runtime reclaims the still-served mount on process exit), and the
// seam-level unmount SWALLOWS that sentinel and returns nil — so a clean SIGTERM
// shutdown on that tier never aggregates into a non-nil run error. On a native
// kernel the detach returns promptly and this branch is never taken (covered by
// TestRealPointDoUnmountOnce).
func TestDoUnmountBoundsTheDetach(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop) // release the blocked UnmountFn goroutine at test end

	mountFn := blockingUnmountMountFn(stop)
	r := &realPointMounter{mountFn: mountFn, readyTimeout: 10 * time.Millisecond}

	info, err := fs.Find("ocufs")
	if err != nil {
		t.Fatalf("ocufs backend not registered: %v", err)
	}
	cm := configmap.Simple{}
	cm.Set("socket_path", "/tmp/ocufs-unit-not-dialed.sock")
	cm.Set("filesystem_id", "session_unit_fs")
	cm.Set("read_only", "false")
	fsObj, err := info.NewFs(context.Background(), "ocufs-detach", "", cm)
	if err != nil {
		t.Fatalf("build ocufs Fs: %v", err)
	}
	mp := mountlib.NewMountPoint(mountFn, t.TempDir(), fsObj, &mountlib.Options{}, &vfscommon.Options{})
	if _, err := mp.Mount(); err != nil {
		t.Fatalf("mp.Mount(): %v", err)
	}
	// A tiny grace so the did-not-return branch fires without the real wait.
	p := &realPoint{dest: mp.MountPoint, mp: mp, detachGrace: 20 * time.Millisecond}

	if err := p.doUnmount(); !errors.Is(err, errDetachDidNotReturn) {
		t.Fatalf("doUnmount err = %v; want errDetachDidNotReturn when the detach does not return within the grace", err)
	}
	if err := r.unmount(p); err != nil {
		t.Fatalf("seam unmount err = %v; want nil (the did-not-return sentinel must not surface as a teardown failure)", err)
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

// TestDefaultRealSeamResolves exercises defaultRealSeam on a supported leg: it
// builds the production seam over the first-party direct-mount MountFn, so the
// constructor must return a non-nil seam and no error. (The wiring assertion —
// directMountFn, not the registry-resolved mount2 function — lives in
// directmount_test.go; the unsupported-platform fail-closed path is covered
// separately by the negated-tag test.)
func TestDefaultRealSeamResolves(t *testing.T) {
	seam, err := defaultRealSeam()
	if err != nil {
		t.Fatalf("defaultRealSeam() error = %v; want a resolved seam on a mount2-supported leg", err)
	}
	if seam == nil {
		t.Fatal("defaultRealSeam() seam = nil; want the production seam built from the resolved mount2 MountFn")
	}
	if _, ok := seam.(*realPointMounter); !ok {
		t.Fatalf("defaultRealSeam() returned %T; want *realPointMounter", seam)
	}
}

// fedMountFn returns a MountFn that hands back the SAME errChan the caller owns,
// so the test can make mp.Wait() return by feeding a terminal value onto it.
// mountlib.MountPoint.Wait() blocks on the channel returned here; a no-op
// unmount closure alone never unblocks it, so the test drives the terminal exit
// explicitly.
func fedMountFn(errChan chan error) mountlib.MountFn {
	return func(_ *vfs.VFS, mountpoint string, _ *mountlib.Options) (<-chan error, func() error, string, error) {
		unmount := func() error { return nil }
		return errChan, unmount, mountpoint, nil
	}
}

// TestRealPointDestinationAndWait covers realPoint.destination() and
// realPoint.wait() by constructing a live point through a fake MountFn path:
// destination() must echo the served path and wait() must return the terminal
// error fed on the mount's errChan. No /dev/fuse is touched; the errChan the
// MountFn hands back is what mp.Wait() ultimately observes, so feeding it a
// terminal value drives wait() to return.
func TestRealPointDestinationAndWait(t *testing.T) {
	errChan := make(chan error, 1)
	r := &realPointMounter{
		mountFn:      fedMountFn(errChan),
		readyTimeout: 10 * time.Millisecond,
	}

	info, err := fs.Find("ocufs")
	if err != nil {
		t.Fatalf("ocufs backend not registered: %v", err)
	}
	cm := configmap.Simple{}
	cm.Set("socket_path", "/tmp/ocufs-unit-not-dialed.sock")
	cm.Set("filesystem_id", "session_unit_fs")
	cm.Set("read_only", "false")
	fsObj, err := info.NewFs(context.Background(), "ocufs-destwait", "", cm)
	if err != nil {
		t.Fatalf("build ocufs Fs: %v", err)
	}

	dest := t.TempDir()
	mp := mountlib.NewMountPoint(r.mountFn, dest, fsObj, &mountlib.Options{}, &vfscommon.Options{})
	if _, err := mp.Mount(); err != nil {
		t.Fatalf("mp.Mount(): %v", err)
	}
	p := &realPoint{dest: dest, mp: mp}

	if got := p.destination(); got != dest {
		t.Fatalf("realPoint.destination() = %q; want %q", got, dest)
	}

	// wait() blocks on mp.Wait() until the mount reports terminal exit. Feed the
	// errChan a clean (nil) terminal value so wait() returns and the test never
	// hangs.
	waitErr := make(chan error, 1)
	go func() { waitErr <- p.wait() }()
	errChan <- nil
	select {
	case <-waitErr:
		// wait() returned, covering the method.
	case <-time.After(2 * time.Second):
		t.Fatal("realPoint.wait() did not return after a terminal value was fed on the mount errChan")
	}
}

// TestWaitReadyDeadlineTimeout covers the deadline-timeout branch of waitReady on
// the polling leg (linux, CanCheckMountReady=true): a tiny readyTimeout over a
// plain non-mounted directory never reports ready, so the poll loop must reach
// the deadline and return the wrapped readiness error. On the non-polling leg
// (darwin/amd64) waitReady short-circuits to nil, so the assertion is
// leg-dependent.
func TestWaitReadyDeadlineTimeout(t *testing.T) {
	r := &realPointMounter{readyTimeout: 5 * time.Millisecond}
	dest := t.TempDir()

	err := r.waitReady(context.Background(), dest)

	if !mountlib.CanCheckMountReady {
		if err != nil {
			t.Fatalf("waitReady on a non-polling leg = %v; want nil (readiness blind-trusted)", err)
		}
		return
	}
	if err == nil {
		t.Fatal("waitReady over a non-mounted dir = nil; want the deadline-timeout readiness error")
	}
	if got := err.Error(); !strings.Contains(got, "wait for mount ready") {
		t.Fatalf("waitReady error = %q; want the wrapped readiness-timeout error", got)
	}
}

// TestWaitReadyContextCanceled covers the ctx-cancel branch of waitReady on the
// polling leg: an already-canceled context must make the loop return the wrapped
// context error on its first iteration rather than polling to the deadline. On
// the non-polling leg waitReady returns nil before it ever inspects the context.
func TestWaitReadyContextCanceled(t *testing.T) {
	// A generous readyTimeout proves the early return is driven by the canceled
	// context, not the deadline.
	r := &realPointMounter{readyTimeout: 30 * time.Second}
	dest := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.waitReady(ctx, dest)

	if !mountlib.CanCheckMountReady {
		if err != nil {
			t.Fatalf("waitReady on a non-polling leg = %v; want nil (context never inspected)", err)
		}
		return
	}
	if err == nil {
		t.Fatal("waitReady with a canceled context = nil; want the wrapped context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitReady error = %v; want it to wrap context.Canceled", err)
	}
}

// TestMountServesDeviceBoundary pins the functional fallback's discriminator:
// a directory that was never mounted shares its parent's st_dev and is NOT a
// mount point, and a path that does not resolve is not one either. This is what
// keeps the fallback from passing a bare directory as "ready" — the property
// that makes TestWaitReadyDeadlineTimeout (a plain temp dir) still time out
// rather than be rescued by the fallback. The positive case (a real
// cross-device mount returns true) is exercised by the live e2e harness, which
// runs a real FUSE mount; here the negatives are the soundness-critical ones.
func TestMountServesDeviceBoundary(t *testing.T) {
	if !mountlib.CanCheckMountReady {
		t.Skip("device-boundary probe is only consulted on the polling leg")
	}
	// A freshly created subdirectory under the test temp dir: same filesystem,
	// so same st_dev as its parent — not a mount point.
	dir := t.TempDir()
	if mountServes(dir) {
		t.Fatalf("mountServes(%q) = true for an unmounted directory; the "+
			"device-boundary check must reject a bare dir or the fallback would "+
			"pass any existing path as ready", dir)
	}
	// A path that does not exist is not a mount point.
	if mountServes(dir + "/does-not-exist") {
		t.Fatal("mountServes on a nonexistent path = true; want false")
	}
}

// TestWaitReadyFunctionalFallback proves waitReady accepts readiness via the
// functional probe when the kernel mount table never confirms — the runsc /
// userspace-kernel path, where the FUSE mount serves but is absent from
// /proc/self/mountinfo so CheckMountReady can never succeed. The probe is
// injected to return true (standing in for a served mount on a runtime that
// hides it from the mount table); waitReady must then return nil after the
// CheckMountReady poll exhausts its deadline.
func TestWaitReadyFunctionalFallback(t *testing.T) {
	if !mountlib.CanCheckMountReady {
		t.Skip("the functional fallback only runs on the polling leg")
	}
	r := &realPointMounter{
		readyTimeout: 5 * time.Millisecond,
		servesProbe:  func(string) bool { return true },
	}
	dest := t.TempDir() // bare dir: CheckMountReady will never confirm it

	if err := r.waitReady(context.Background(), dest); err != nil {
		t.Fatalf("waitReady with a serving functional probe = %v; want nil "+
			"(the mount serves but the kernel mount table does not list it)", err)
	}
}

// TestWaitReadyFallbackRejectsBareDir proves the fallback does not rescue a
// directory that is not actually serving: with the probe reporting false (the
// honest result for a bare dir) waitReady must still surface the readiness
// timeout error rather than declaring the mount ready.
func TestWaitReadyFallbackRejectsBareDir(t *testing.T) {
	if !mountlib.CanCheckMountReady {
		t.Skip("the functional fallback only runs on the polling leg")
	}
	r := &realPointMounter{
		readyTimeout: 5 * time.Millisecond,
		servesProbe:  func(string) bool { return false },
	}
	dest := t.TempDir()

	err := r.waitReady(context.Background(), dest)
	if err == nil {
		t.Fatal("waitReady over a non-serving dir = nil; want the readiness-timeout error")
	}
	if got := err.Error(); !strings.Contains(got, "wait for mount ready") {
		t.Fatalf("waitReady error = %q; want the wrapped readiness-timeout error", got)
	}
}
