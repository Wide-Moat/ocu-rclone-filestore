// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"fmt"
	"runtime"
	"time"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/rclone/rclone/cmd/mount2"
	"github.com/rclone/rclone/cmd/mountlib"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/vfs"
)

// directMountFn is the first-party production mountlib.MountFn: it serves the
// VFS over FUSE through go-fuse's direct mount(2) path (DirectMountStrict), so
// the kernel mount needs only /dev/fuse and CAP_SYS_ADMIN — no fusermount
// helper binary and no helper subprocess.
//
// This is OUR posture for a minimal static guest image: there is no fusermount
// tooling to install in a static image, and a helper subprocess is one more
// thing to deadlock or be killed mid-mount. DirectMountStrict makes go-fuse
// perform the mount syscall itself and NEVER fall back to exec'ing a helper,
// so a missing helper can never turn into a runtime mount failure.
//
// The rclone<->FUSE node tree comes from rclone's own mount2 package through
// its exported surface (mount2.NewFS and (*FS).Root), so every file operation
// maps exactly as rclone's mount2 frontend maps it and the diff to upstream
// rclone stays zero. Only the server assembly lives here, built from the same
// exported go-fuse pieces (fusefs.NewNodeFS + fuse.NewServer) that mount2's
// own frontend assembles.
//
// SEC-25 is untouched: this is a kernel mount frontend, not a transport. The
// only network/IPC path remains the ocufs backend's broker unix socket.
func directMountFn(VFS *vfs.VFS, mountpoint string, opt *mountlib.Options) (<-chan error, func() error, string, error) {
	f := VFS.Fs()
	if err := mountlib.CheckOverlap(f, mountpoint); err != nil {
		return nil, nil, "", err
	}
	// AllowNonEmpty maps here: when it is unset the mountpoint must be empty
	// (and on linux not already mounted), exactly the gate rclone's own
	// frontends apply before touching the kernel.
	if err := mountlib.CheckAllowNonEmpty(mountpoint, opt); err != nil {
		return nil, nil, "", err
	}
	fs.Debugf(f, "Direct-mounting on %q", mountpoint)

	fsys := mount2.NewFS(VFS, opt)
	root, err := fsys.Root()
	if err != nil {
		return nil, nil, "", err
	}

	mo := buildFuseMountOptions(fsys, opt)
	nodeOpts := buildNodeFSOptions(fsys, opt, mo)

	rawFS := fusefs.NewNodeFS(root, &nodeOpts)
	server, err := fuse.NewServer(rawFS, mountpoint, &nodeOpts.MountOptions)
	if err != nil {
		return nil, nil, "", fmt.Errorf("direct mount %q: %w", mountpoint, err)
	}

	errs, umount := serveFuse(server, fsys.VFS.Shutdown)

	if err := server.WaitMount(); err != nil {
		// The kernel mount exists but never came up; detach it best-effort so
		// no dangling mountpoint outlives the failure.
		_ = umount()
		return nil, nil, "", fmt.Errorf("direct mount %q: wait for mount: %w", mountpoint, err)
	}

	fs.Debugf(f, "Direct mount started on %q", mountpoint)
	return errs, umount, mountpoint, nil
}

// fuseServer is the slice of *fuse.Server the serve/teardown tail depends on,
// kept as a seam so the lifecycle wiring is unit-testable without a kernel
// mount.
type fuseServer interface {
	Serve()
	Wait()
	Unmount() error
}

// serveFuse starts serving srv in the background and returns the terminal
// error channel plus the unmount closure.
//
// The terminal value lands on the channel only once the serve loop has exited
// AND its outstanding request goroutines have drained (srv.Wait), so consumers
// see a fully quiesced server. The unmount closure shuts the VFS down FIRST so
// in-flight writes flush before the kernel mount goes away, then detaches the
// kernel mount.
func serveFuse(srv fuseServer, shutdownVFS func()) (<-chan error, func() error) {
	umount := func() error {
		shutdownVFS()
		return srv.Unmount()
	}
	errs := make(chan error, 1)
	go func() {
		srv.Serve()
		srv.Wait()
		errs <- nil
	}()
	return errs, umount
}

// buildFuseMountOptions maps *mountlib.Options onto go-fuse's fuse.MountOptions
// for the direct-mount frontend. The field mapping matches what rclone's mount2
// frontend feeds go-fuse (same names, same defaults: MaxWrite pinned to 1 MiB,
// xattrs and ReadDirPlus disabled), with one deliberate divergence:
// DirectMountStrict is ALWAYS set, so go-fuse calls the mount syscall itself
// and never execs a fusermount helper — the load-bearing property for the
// static guest image. DirectMountStrict wins over DirectMount and has no
// helper fallback.
func buildFuseMountOptions(fsys *mount2.FS, opt *mountlib.Options) fuse.MountOptions {
	mo := fuse.MountOptions{
		AllowOther:         opt.AllowOther,
		FsName:             opt.DeviceName,
		Name:               "rclone",
		DisableXAttrs:      true,
		Debug:              opt.DebugFUSE,
		MaxReadAhead:       int(opt.MaxReadAhead),
		MaxWrite:           1024 * 1024, // Linux v4.20+ caps requests at 1 MiB
		DisableReadDirPlus: true,
		DirectMountStrict:  true,
	}
	var opts []string
	if opt.AllowOther {
		opts = append(opts, "allow_other")
	}
	if opt.AllowRoot {
		opts = append(opts, "allow_root")
	}
	if opt.DefaultPermissions {
		opts = append(opts, "default_permissions")
	}
	if fsys.VFS.Opt.ReadOnly {
		opts = append(opts, "ro")
	}
	if runtime.GOOS == "darwin" {
		// darwin/amd64 is a build-convenience leg, never the production guest;
		// keep the volume options its FUSE stack expects.
		opts = append(opts,
			fmt.Sprintf("volname=%s", opt.VolumeName),
			"noapplexattr",
			"noappledouble",
		)
	}
	// With no helper subprocess there is only one channel for extra options:
	// the option string handed to the mount syscall. Both extra-option axes
	// ride it.
	opts = append(opts, opt.ExtraOptions...)
	opts = append(opts, opt.ExtraFlags...)
	mo.Options = opts
	return mo
}

// buildNodeFSOptions wraps the assembled fuse.MountOptions with the node-layer
// knobs go-fuse needs: the kernel attribute/entry cache windows and the
// uid/gid stamped on served nodes. The entry timeout deliberately tracks the
// attribute timeout — one staleness window for both axes — matching how
// rclone's mount2 frontend feeds go-fuse.
func buildNodeFSOptions(fsys *mount2.FS, opt *mountlib.Options, mo fuse.MountOptions) fusefs.Options {
	return fusefs.Options{
		MountOptions: mo,
		EntryTimeout: (*time.Duration)(&opt.AttrTimeout),
		AttrTimeout:  (*time.Duration)(&opt.AttrTimeout),
		UID:          fsys.VFS.Opt.UID,
		GID:          fsys.VFS.Opt.GID,
	}
}
