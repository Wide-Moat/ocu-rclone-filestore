// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rclone/rclone/cmd/mountlib"
	"github.com/rclone/rclone/fs"

	// Keep rclone's mount2 package linked: its exported FS/Node surface is what
	// the first-party direct-mount frontend (directmount.go) builds the
	// rclone<->FUSE node tree from, with ZERO upstream diff — no rclone source
	// is forked. Its init() also self-registers under "mount2" via
	// mountlib.AddRc; the tests use that registry entry to prove the seam is
	// wired to the first-party MountFn INSTEAD of the registry-resolved one.
	// mount2 carries the same build tag as this file, so both supported legs
	// see the same package set.
	_ "github.com/rclone/rclone/cmd/mount2"

	// Blank-import the local backend so the VFS disk cache can build its cache
	// area: rclone's vfscache resolves the backend named "local" for the
	// on-disk cache directory, and without this registration the cache is
	// silently disabled — vfs_cache_mode writes/minimal becomes inert and the
	// hold-data-across-a-throttled-retry mechanism (SEC-46) does not exist.
	// This is a disk backend for the cache dir only: NOT a second transport
	// and NOT an object-store client, so SEC-25 is untouched — the sole
	// network/IPC path remains the broker unix socket.
	_ "github.com/rclone/rclone/backend/local"
)

// waitMountReadyTimeout bounds how long the seam waits for the kernel to report
// the mountpoint live before treating the mount as failed. It is pinned here so
// a stuck mount surfaces as a hard error rather than blocking the session
// forever.
const waitMountReadyTimeout = 30 * time.Second

// realPointMounter is the production pointMounter: it builds the ocufs Fs from
// the orchestrator's configmap, hands it to a mountlib.MountPoint with the
// mapped VFS/mount options, starts the live FUSE mount, and confirms readiness.
// It opens no second transport and stamps no auth material of its own — the
// only handle is the ocufs Fs scoped by filesystem_id (SEC-25).
type realPointMounter struct {
	// mountFn is the mount function the seam drives — in production the
	// first-party directMountFn. It is injected through the constructor so a
	// test can drive the option-assembly and MountPoint wiring with a fake
	// function and no /dev/fuse.
	mountFn mountlib.MountFn
	// readyTimeout bounds the readiness poll. It defaults to
	// waitMountReadyTimeout and is a field so a unit test driving a fake MountFn
	// can set it tiny and not block on the real ~30s poll over a non-mounted
	// directory.
	readyTimeout time.Duration
}

// newRealPointMounter builds the production seam from a resolved MountFn. It
// fails closed with a typed error when the function is nil (the mount method is
// unavailable on this platform/arch), so the session never silently no-op
// mounts (MNT-02).
func newRealPointMounter(fn mountlib.MountFn) (pointMounter, error) {
	if fn == nil {
		return nil, errMountMethodUnavailable
	}
	return &realPointMounter{mountFn: fn, readyTimeout: waitMountReadyTimeout}, nil
}

// defaultRealSeam builds the production seam over the first-party direct-mount
// MountFn (directmount.go). This is what New() wires on a supported platform.
//
// The registry-resolved mount2 function is deliberately NOT used: without
// DirectMount set, go-fuse's default mount path execs a fusermount helper
// binary, and the minimal static guest image carries none — the mount would
// fail at runtime. The first-party frontend performs the mount syscall itself
// (DirectMountStrict), so only /dev/fuse and CAP_SYS_ADMIN are needed.
func defaultRealSeam() (pointMounter, error) {
	return newRealPointMounter(directMountFn)
}

// realPoint bridges a live mountlib.MountPoint into the orchestrator's opaque
// point: destination() reports the served path, wait() blocks on the mount's
// terminal exit, and unmount() tears it down.
//
// doUnmount is guarded by a sync.Once so OUR unmount path runs mp.Unmount()
// exactly once even when the orchestrator's signal-teardown races a spontaneous
// exit on the same point. mountlib.MountPoint.Wait() runs its own finalise that
// also calls Unmount() — that is rclone-internal and not deduplicatable from
// here, so the residual race is rclone-internal finalise vs our unmount; the
// Once removes the double-call from OUR code path, which is the cheap, correct
// guard available without an upstream diff.
type realPoint struct {
	dest        string
	mp          *mountlib.MountPoint
	unmountOnce sync.Once
	unmountErr  error
}

func (p *realPoint) destination() string { return p.dest }
func (p *realPoint) wait() error         { return p.mp.Wait() }

// doUnmount tears the mount down at most once, caching and returning the result
// of the single mp.Unmount() call. Concurrent callers all observe that one
// result.
func (p *realPoint) doUnmount() error {
	p.unmountOnce.Do(func() { p.unmountErr = p.mp.Unmount() })
	return p.unmountErr
}

// mountAndWaitReady builds the ocufs Fs for spec, constructs the MountPoint with
// the mapped options, starts the mount, and confirms readiness. The VFS is built
// INSIDE MountPoint.Mount(); the seam never constructs a VFS itself, so no second
// VFS is leaked into the package-level active cache. On any failure it
// best-effort unmounts and returns the error wrapped with the destination.
func (r *realPointMounter) mountAndWaitReady(ctx context.Context, spec mountSpec) (point, error) {
	dest := spec.mount.Destination

	cm, err := buildOcufsConfigmap(spec.mount, spec.readOnly, spec.socketPath)
	if err != nil {
		return nil, err
	}

	info, err := fs.Find("ocufs")
	if err != nil {
		return nil, fmt.Errorf("mount %q: ocufs backend not registered: %w", dest, err)
	}
	// Give every Fs a name unique to its destination so fs.ConfigString never
	// collides across mounts. rclone's vfs.New keeps a package-level active-VFS
	// cache keyed on (ConfigString, Options); two mounts with identical mapped
	// VFS options — the common case (same cache mode/cap/duration/perms/
	// read-only) — would otherwise share one cached VFS, and the second mount
	// would silently serve the FIRST filesystem. The destination is the natural
	// unique axis. The root parameter stays EMPTY: the ocufs backend joins root
	// into broker paths, so a non-empty root would corrupt those paths; the name
	// is display-only on this backend (scope comes from the configmap's
	// filesystem_id, not the name), so it is safe to vary.
	fsObj, err := info.NewFs(ctx, "ocufs-"+dest, "", cm)
	if err != nil {
		return nil, fmt.Errorf("mount %q: build ocufs Fs: %w", dest, err)
	}

	vfsOpt, err := buildVFSOptions(spec.mount, spec.readOnly)
	if err != nil {
		return nil, fmt.Errorf("mount %q: build VFS options: %w", dest, err)
	}
	mountOpt, err := buildMountOptions(spec.mount)
	if err != nil {
		return nil, fmt.Errorf("mount %q: build mount options: %w", dest, err)
	}

	mp := mountlib.NewMountPoint(r.mountFn, dest, fsObj, &mountOpt, &vfsOpt)

	if _, err := mp.Mount(); err != nil {
		return nil, fmt.Errorf("mount %q: start mount: %w", dest, err)
	}

	if err := r.waitReady(ctx, dest); err != nil {
		// Best-effort teardown of the half-started mount before surfacing.
		_ = mp.Unmount()
		return nil, err
	}

	return &realPoint{dest: dest, mp: mp}, nil
}

// waitReady confirms the mountpoint is live using only the exported, nil-safe
// mountlib primitives, so it carries zero upstream diff and never reaches the
// nil-daemon nil-pointer path inside mountlib.WaitMountReady (which reads the
// daemon process pid unconditionally on every poll; our non-daemon mp.Mount()
// always returns a nil daemon, so calling WaitMountReady would crash on the
// first not-ready poll).
//
// On a leg where mountlib.CanCheckMountReady is false (e.g. darwin/amd64), the
// kernel cannot be polled for readiness. mp.Mount() already returned success, so
// readiness is blind-trusted there. linux (CanCheckMountReady=true) is the
// production target and is the only leg that kernel-verifies readiness; the
// darwin/amd64 leg is a build convenience that cannot poll the kernel.
func (r *realPointMounter) waitReady(ctx context.Context, dest string) error {
	if !mountlib.CanCheckMountReady {
		return nil
	}

	const pollInterval = 100 * time.Millisecond
	deadline := time.Now().Add(r.readyTimeout)
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("mount %q: wait for mount ready: %w", dest, err)
		}
		lastErr = mountlib.CheckMountReady(dest)
		if lastErr == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("mount %q: wait for mount ready: %w", dest, lastErr)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("mount %q: wait for mount ready: %w", dest, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// unmount best-effort unmounts one live point.
func (r *realPointMounter) unmount(p point) error {
	rp, ok := p.(*realPoint)
	if !ok {
		return fmt.Errorf("unmount: unexpected point type %T", p)
	}
	return rp.doUnmount()
}
