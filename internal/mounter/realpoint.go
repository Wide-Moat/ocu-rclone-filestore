// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"context"
	"fmt"
	"time"

	"github.com/rclone/rclone/cmd/mountlib"
	"github.com/rclone/rclone/fs"

	// Blank-import the mount2 backend so its init() self-registers its mount
	// function under the name "mount2" via mountlib.AddRc. ResolveMountMethod
	// then resolves it from the registry with ZERO upstream diff: no rclone
	// source is forked to export the (unexported) mount symbol. mount2 carries
	// the same build tag as this file, so on a platform where mount2 registers
	// nothing the resolved MountFn is nil and the constructor fails closed.
	//
	// mount2 is preferred over the cmd/mount path because its direct kernel
	// mount avoids spawning a fusermount helper subprocess, which matters in a
	// minimal guest where that helper may be absent and an extra process is
	// undesirable.
	_ "github.com/rclone/rclone/cmd/mount2"
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
	// mountFn is the registered mount function resolved from the mountlib
	// registry. It is injected through the constructor so a test can drive the
	// option-assembly and MountPoint wiring with a fake function and no
	// /dev/fuse.
	mountFn mountlib.MountFn
	// readyTimeout bounds WaitMountReady. It defaults to waitMountReadyTimeout
	// and is a field so a unit test driving a fake MountFn can set it tiny and
	// not block on the real ~30s spin-poll over a non-mounted directory.
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

// defaultRealSeam resolves the mount2 MountFn from the registry and builds the
// production seam. This is what New() wires on a mount2-supported platform.
func defaultRealSeam() (pointMounter, error) {
	_, fn := mountlib.ResolveMountMethod("mount2")
	return newRealPointMounter(fn)
}

// realPoint bridges a live mountlib.MountPoint into the orchestrator's opaque
// point: destination() reports the served path, wait() blocks on the mount's
// terminal exit, and unmount() tears it down.
type realPoint struct {
	dest string
	mp   *mountlib.MountPoint
}

func (p *realPoint) destination() string { return p.dest }
func (p *realPoint) wait() error         { return p.mp.Wait() }

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
	fsObj, err := info.NewFs(ctx, "ocufs", "", cm)
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

	daemon, err := mp.Mount()
	if err != nil {
		return nil, fmt.Errorf("mount %q: start mount: %w", dest, err)
	}

	if err := mountlib.WaitMountReady(dest, r.readyTimeout, daemon); err != nil {
		// Best-effort teardown of the half-started mount before surfacing.
		_ = mp.Unmount()
		return nil, fmt.Errorf("mount %q: wait for mount ready: %w", dest, err)
	}

	return &realPoint{dest: dest, mp: mp}, nil
}

// unmount best-effort unmounts one live point.
func (r *realPointMounter) unmount(p point) error {
	rp, ok := p.(*realPoint)
	if !ok {
		return fmt.Errorf("unmount: unexpected point type %T", p)
	}
	return rp.mp.Unmount()
}
