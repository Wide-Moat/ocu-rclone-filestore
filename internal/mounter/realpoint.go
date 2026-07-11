// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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
	// network/egress path remains the broker HTTPS endpoint.
	_ "github.com/rclone/rclone/backend/local"
)

// waitMountReadyTimeout bounds how long the seam waits for the kernel to report
// the mountpoint live before treating the mount as failed. It is pinned here so
// a stuck mount surfaces as a hard error rather than blocking the session
// forever.
const waitMountReadyTimeout = 30 * time.Second

// writebackDrainTimeout and unmountDetachGrace live in teardown.go (untagged)
// so the compose-grace invariant test references the real constants on every
// platform.

// errDetachDidNotReturn is the typed result when the in-process kernel detach
// did not return within unmountDetachGrace. It is NOT a failure to unmount: the
// drain completed, and on the tier where this fires the sandbox reclaims the
// mount when the process exits. It is surfaced so teardown is never silently
// reported as a clean detach when the detach call is in fact still outstanding.
var errDetachDidNotReturn = errors.New("in-process kernel detach did not return within the grace window; the runtime reclaims the mount on process exit")

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
	// servesProbe is the functional liveness fallback waitReady consults when the
	// kernel mount table never confirms the mount. It defaults to mountServes
	// (the device-boundary check) and is a field only so a unit test can drive
	// the fallback branch deterministically without a real cross-device mount. A
	// nil probe falls back to mountServes.
	servesProbe func(dest string) bool
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
	// detachGrace bounds the in-process kernel-detach wait in doUnmount. It
	// defaults to unmountDetachGrace and is a field only so a unit test can
	// drive the did-not-return branch deterministically without the real
	// multi-second wait. A zero value falls back to unmountDetachGrace.
	detachGrace time.Duration
}

func (p *realPoint) destination() string { return p.dest }
func (p *realPoint) wait() error         { return p.mp.Wait() }

// doUnmount drains the VFS write-back queue, then tears the mount down — at most
// once, caching and returning the result of the single mp.Unmount() call.
// Concurrent callers all observe that one result.
//
// The drain runs BEFORE Unmount: a write-back cache uploads dirty bytes to the
// broker asynchronously, so unmounting first would discard whatever the upload
// queue has not yet flushed and silently lose the most recent writes (the
// SIGTERM-teardown data-loss path). WaitForWriters blocks until active writers
// and in-use cache items both reach zero or the bounded timeout elapses;
// FlushDirCache then forgets the cached tree so the unmount sees a quiescent
// VFS. mp.VFS is nil-guarded because a fake MountFn in a unit test never builds
// one.
func (p *realPoint) doUnmount() error {
	p.unmountOnce.Do(func() {
		if p.mp.VFS != nil {
			p.mp.VFS.WaitForWriters(writebackDrainTimeout)
			p.mp.VFS.FlushDirCache()
		}
		// Bound only the kernel-detach call. On a native kernel it returns
		// promptly and detached carries its real result; on a userspace-kernel
		// sandbox it never returns, so after the grace we record the typed
		// did-not-return result and let teardown proceed — the process exit then
		// lets the runtime reclaim the still-served mount. The drain above has
		// already completed either way, so this bound drops no write-back bytes.
		grace := p.detachGrace
		if grace == 0 {
			grace = unmountDetachGrace
		}
		detached := make(chan error, 1)
		go func() { detached <- p.mp.Unmount() }()
		select {
		case err := <-detached:
			p.unmountErr = err
		case <-time.After(grace):
			p.unmountErr = errDetachDidNotReturn
		}
	})
	return p.unmountErr
}

// mountAndWaitReady builds the ocufs Fs for spec, constructs the MountPoint with
// the mapped options, starts the mount, and confirms readiness. The VFS is built
// INSIDE MountPoint.Mount(); the seam never constructs a VFS itself, so no second
// VFS is leaked into the package-level active cache. On any failure it
// best-effort unmounts and returns the error wrapped with the destination.
func (r *realPointMounter) mountAndWaitReady(ctx context.Context, spec mountSpec) (point, error) {
	dest := spec.mount.Destination

	cm, err := buildOcufsConfigmap(spec.mount, spec.readOnly, spec.serviceURL, spec.caCertPEM)
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
		// Best-effort teardown of the half-started mount before surfacing —
		// through the same bounded discipline doUnmount applies. A bare
		// mp.Unmount() never returns on the tier whose in-process kernel
		// detach blocks (the reason doUnmount bounds it), so the readiness-
		// failure path would wedge run() forever with the ready-file
		// lifecycle stuck behind it. The drain half is a no-op on a
		// just-mounted VFS (no writers, no in-use cache items), so this adds
		// no latency on the failure path.
		rp := &realPoint{dest: dest, mp: mp}
		_ = rp.doUnmount()
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
//
// Readiness has two signals, both checked on every poll iteration:
//
//  1. mountlib.CheckMountReady — scans the kernel mount table
//     (/proc/self/mountinfo) for an entry at dest whose filesystem type names
//     rclone. This is the authoritative confirmation on a real kernel and the
//     unchanged primary signal under runc / a microVM guest.
//  2. A functional liveness probe (mountServes) — the device-boundary test:
//     dest's st_dev differs from its parent's. This is what confirms readiness
//     on a runtime whose kernel mount table does not surface FUSE mounts at all:
//     under a userspace-kernel sandbox the FUSE mount serves correctly but never
//     appears in /proc/self/mountinfo, so signal (1) is structurally
//     unsatisfiable there no matter how long it is polled, yet the served root
//     still presents a device distinct from the directory it shadows.
//
// Both are checked each iteration so the sandbox path becomes ready as soon as
// the device boundary is observable rather than only after the full readyTimeout
// elapses (which, across several mounts, would otherwise serialise into minutes
// of pure dead waiting). The functional probe is sound because reaching this
// loop means mp.Mount() already returned success, and mp.Mount() returns success
// only after the direct-mount frontend's server.WaitMount() returned nil —
// go-fuse's authoritative "the mount syscall completed and the server is live"
// signal — and the device-boundary test cannot pass for a bare, unmounted
// directory (it shares its parent's device). On a real kernel signal (1)
// typically confirms first, so behaviour there is unchanged; signal (2) is the
// one that makes the userspace-kernel tier reach readiness at all.
func (r *realPointMounter) waitReady(ctx context.Context, dest string) error {
	if !mountlib.CanCheckMountReady {
		return nil
	}

	serves := r.servesProbe
	if serves == nil {
		serves = mountServes
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
		// Functional fallback for a runtime that does not surface FUSE in the
		// kernel mount table: a served mount presents a device boundary at dest
		// even when /proc/self/mountinfo omits it. Checked every iteration so the
		// sandbox path does not pay the full readyTimeout in dead waiting.
		if serves(dest) {
			fs.Infof(dest, "mount ready via functional probe: the kernel "+
				"mount table does not list the mount, but the mountpoint presents "+
				"a device boundary (the running container runtime does not surface "+
				"FUSE mounts in /proc/self/mountinfo)")
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

// mountServes is the functional liveness fallback for waitReady: it reports
// whether dest is a real mount point by the device-boundary test — the
// mountpoint's st_dev differs from its parent directory's st_dev. A filesystem
// mounted at dest (FUSE included) gives the mountpoint a device distinct from
// the directory it shadows; a bare, unmounted directory shares its parent's
// device. This is the same boundary mountpoint(1) uses, and it holds on both a
// real kernel and a userspace-kernel sandbox (where statfs reports an unknown
// filesystem type and /proc/self/mountinfo omits the FUSE mount entirely, yet
// the served root still presents a distinct st_dev).
//
// It is consulted ONLY after both:
//
//   - mp.Mount() returned success — which on the direct-mount frontend means
//     directMountFn's server.WaitMount() returned nil, go-fuse's authoritative
//     confirmation that the mount syscall completed and the FUSE server started
//     serving; and
//   - the kernel mount table did not list the mount within the full readiness
//     timeout — the signature of a userspace-kernel runtime that serves FUSE
//     but does not surface it in /proc/self/mountinfo.
//
// The device-boundary check is what keeps the fallback from passing a bare
// directory: a directory that was never mounted shares its parent's device and
// fails here, so a stale or never-started mountpoint is not mistaken for ready.
func mountServes(dest string) bool {
	// Clean dest first: filepath.Dir of a trailing-slash path ("/mnt/foo/")
	// yields the path itself, which would compare the mountpoint against its own
	// device and report a false negative. Cleaning strips the trailing slash so
	// the parent is the real parent directory.
	cleanDest := filepath.Clean(dest)
	parentPath := filepath.Dir(cleanDest)
	if parentPath == cleanDest {
		// dest is a filesystem root (e.g. "/"): there is no distinct parent to
		// compare against, so the device-boundary test cannot apply.
		return false
	}
	dst, err := os.Stat(cleanDest)
	if err != nil {
		return false
	}
	parent, err := os.Stat(parentPath)
	if err != nil {
		return false
	}
	dstSys, ok1 := dst.Sys().(*syscall.Stat_t)
	parSys, ok2 := parent.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return false
	}
	return dstSys.Dev != parSys.Dev
}

// unmount best-effort unmounts one live point.
func (r *realPointMounter) unmount(p point) error {
	rp, ok := p.(*realPoint)
	if !ok {
		return fmt.Errorf("unmount: unexpected point type %T", p)
	}
	err := rp.doUnmount()
	if errors.Is(err, errDetachDidNotReturn) {
		// Not a teardown failure: the drain completed and the runtime reclaims
		// the still-served mount on process exit. Log it for diagnostics but do
		// not surface it as an unmount error — otherwise a clean SIGTERM
		// shutdown on the sandbox tier would aggregate into a non-nil run error
		// and a non-zero exit. On a native kernel the detach returns promptly
		// and this branch is never taken.
		slog.Info("kernel detach did not return within the grace window; the runtime reclaims the mount on process exit", "dest", rp.destination())
		return nil
	}
	return err
}
