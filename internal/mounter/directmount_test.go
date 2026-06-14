// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/cmd/mount2"
	"github.com/rclone/rclone/cmd/mountlib"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/vfs"
	"github.com/rclone/rclone/vfs/vfscommon"
)

// newTestMount2FS builds a *mount2.FS over a real ocufs Fs (registry-built,
// never dialed) and a VFS with the given options, so the option-assembly
// helpers can be driven with the exact exported types the production path
// hands them. The Fs name must be unique per test so the package-level
// active-VFS cache never collides across tests (CR-01 axis).
func newTestMount2FS(t *testing.T, name string, vfsOpt *vfscommon.Options, mountOpt *mountlib.Options) *mount2.FS {
	t.Helper()
	info, err := fs.Find("ocufs")
	if err != nil {
		t.Fatalf("ocufs backend not registered: %v", err)
	}
	cm := configmap.Simple{}
	cm.Set("socket_path", "/tmp/ocufs-unit-not-dialed.sock")
	cm.Set("filesystem_id", "session_unit_fs")
	cm.Set("read_only", "false")
	fsObj, err := info.NewFs(context.Background(), name, "", cm)
	if err != nil {
		t.Fatalf("build ocufs Fs: %v", err)
	}
	v := vfs.New(context.Background(), fsObj, vfsOpt)
	return mount2.NewFS(v, mountOpt)
}

// TestBuildFuseMountOptionsDirectMountStrict pins the load-bearing property of
// the first-party frontend: DirectMountStrict is ALWAYS set, so go-fuse
// performs the mount syscall itself and never execs a fusermount helper — the
// static guest image carries none. It also asserts the mountlib.Options fields
// map onto the fuse.MountOptions the kernel mount sees: AllowOther (field only
// — go-fuse appends the kernel option itself under direct mount, so no
// duplicate string append), DebugFUSE, DeviceName, read-only, and the
// ExtraOptions pass-through.
func TestBuildFuseMountOptionsDirectMountStrict(t *testing.T) {
	vfsOpt := vfscommon.Opt
	vfsOpt.ReadOnly = true
	mountOpt := mountlib.Opt
	mountOpt.AllowOther = true
	mountOpt.DefaultPermissions = true
	mountOpt.DebugFUSE = true
	mountOpt.DeviceName = "ocufs-unit-dev"
	mountOpt.ExtraOptions = []string{"max_read=131072"}

	fsys := newTestMount2FS(t, "ocufs-fuseopts", &vfsOpt, &mountOpt)
	mo, err := buildFuseMountOptions(fsys, &mountOpt)
	if err != nil {
		t.Fatalf("buildFuseMountOptions: %v; want the default option set to build", err)
	}

	if !mo.DirectMountStrict {
		t.Fatal("DirectMountStrict = false: the mount would fall back to a fusermount helper the static guest image does not carry")
	}
	if !mo.AllowOther {
		t.Fatal("AllowOther was not mapped from mountlib.Options")
	}
	if slices.Contains(mo.Options, "allow_other") {
		t.Fatalf("allow_other appears in the option strings %v: it must ride the AllowOther field only, or the mount data carries it twice", mo.Options)
	}
	if !mo.Debug {
		t.Fatal("DebugFUSE was not mapped onto fuse.MountOptions.Debug")
	}
	if mo.FsName != "ocufs-unit-dev" {
		t.Fatalf("FsName = %q; want the mapped DeviceName", mo.FsName)
	}
	for _, want := range []string{"default_permissions", "max_read=131072"} {
		if !slices.Contains(mo.Options, want) {
			t.Fatalf("mount option %q missing from %v", want, mo.Options)
		}
	}
	// Read-only is expressed per platform: on the production linux leg it
	// must ride the mount FLAGS (MS_RDONLY) and NOT appear as a "ro" option
	// string, because under DirectMountStrict that token is handed to the
	// mount(2) syscall as FUSE mount data the kernel does not parse and a
	// userspace-kernel sandbox rejects the whole mount with EINVAL. The
	// platform-specific helper asserts the correct expression for its leg.
	assertReadOnlyExpressed(t, mo)
}

// TestBuildFuseMountOptionsRejectsHelperOnlyOptions pins the EINVAL guard:
// under DirectMountStrict every option string is handed raw to the mount
// syscall, so the two axes the kernel cannot parse — allow_root (a
// userspace-helper concept) and ExtraFlags (helper-era flags) — must be
// rejected up front with the typed unsupported-under-direct-mount error
// instead of failing the whole mount with a misleading kernel EINVAL.
func TestBuildFuseMountOptionsRejectsHelperOnlyOptions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*mountlib.Options)
	}{
		{name: "allow-root", mutate: func(o *mountlib.Options) { o.AllowRoot = true }},
		{name: "extra-flags", mutate: func(o *mountlib.Options) { o.ExtraFlags = []string{"sync"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vfsOpt := vfscommon.Opt
			mountOpt := mountlib.Opt
			tc.mutate(&mountOpt)

			fsys := newTestMount2FS(t, "ocufs-reject-"+tc.name, &vfsOpt, &mountOpt)
			_, err := buildFuseMountOptions(fsys, &mountOpt)
			if err == nil {
				t.Fatalf("%s built mount options for the kernel; want the typed rejection", tc.name)
			}
			if !errors.Is(err, errUnsupportedDirectMountOption) {
				t.Fatalf("error = %v; want errors.Is(err, errUnsupportedDirectMountOption)", err)
			}
			if !strings.Contains(err.Error(), "unsupported under direct mount") {
				t.Fatalf("error = %q; want a clear unsupported-under-direct-mount message", err)
			}
		})
	}
}

// TestBuildNodeFSOptionsMapsTimeoutsAndIDs asserts the node-layer options map
// the attribute/entry cache windows from mountlib.Options.AttrTimeout (one
// staleness window for both axes) and the UID/GID from the VFS options, and
// that the assembled fuse.MountOptions pass through intact.
func TestBuildNodeFSOptionsMapsTimeoutsAndIDs(t *testing.T) {
	vfsOpt := vfscommon.Opt
	vfsOpt.UID = 1234
	vfsOpt.GID = 5678
	mountOpt := mountlib.Opt
	mountOpt.AttrTimeout = fs.Duration(7 * time.Second)

	fsys := newTestMount2FS(t, "ocufs-nodeopts", &vfsOpt, &mountOpt)
	mo, err := buildFuseMountOptions(fsys, &mountOpt)
	if err != nil {
		t.Fatalf("buildFuseMountOptions: %v; want the default option set to build", err)
	}
	nodeOpts := buildNodeFSOptions(fsys, &mountOpt, mo)

	if nodeOpts.AttrTimeout == nil || *nodeOpts.AttrTimeout != 7*time.Second {
		t.Fatalf("AttrTimeout = %v; want 7s mapped from mountlib.Options", nodeOpts.AttrTimeout)
	}
	if nodeOpts.EntryTimeout == nil || *nodeOpts.EntryTimeout != 7*time.Second {
		t.Fatalf("EntryTimeout = %v; want 7s (tracks the attribute timeout)", nodeOpts.EntryTimeout)
	}
	if nodeOpts.UID != 1234 {
		t.Fatalf("UID = %d; want 1234 mapped from the VFS options", nodeOpts.UID)
	}
	if nodeOpts.GID != 5678 {
		t.Fatalf("GID = %d; want 5678 mapped from the VFS options", nodeOpts.GID)
	}
	if !nodeOpts.MountOptions.DirectMountStrict {
		t.Fatal("assembled fuse.MountOptions did not pass through intact (DirectMountStrict lost)")
	}
}

// TestDefaultRealSeamUsesFirstPartyDirectMount asserts the production seam is
// wired to the first-party directMountFn and NOT to the registry-resolved
// mount2 function: the registry one execs a fusermount helper that the static
// guest image does not carry, so wiring it would fail at runtime in the guest.
func TestDefaultRealSeamUsesFirstPartyDirectMount(t *testing.T) {
	seam, err := defaultRealSeam()
	if err != nil {
		t.Fatalf("defaultRealSeam() error = %v; want the production seam on a supported leg", err)
	}
	rp, ok := seam.(*realPointMounter)
	if !ok {
		t.Fatalf("defaultRealSeam() returned %T; want *realPointMounter", seam)
	}

	got := reflect.ValueOf(rp.mountFn).Pointer()
	want := reflect.ValueOf(mountlib.MountFn(directMountFn)).Pointer()
	if got != want {
		t.Fatal("production seam mountFn is not the first-party directMountFn")
	}

	_, registryFn := mountlib.ResolveMountMethod("mount2")
	if registryFn != nil && got == reflect.ValueOf(registryFn).Pointer() {
		t.Fatal("production seam mountFn is the registry-resolved mount2 function: it depends on a fusermount helper the static guest image does not carry")
	}
}

// TestDirectMountFnRejectsNonEmptyMountpoint covers the AllowNonEmpty gate: a
// non-empty mountpoint with AllowNonEmpty unset must be rejected before any
// kernel work, returning the empty 4-tuple. This is the same pre-mount gate
// rclone's own frontends apply.
func TestDirectMountFnRejectsNonEmptyMountpoint(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "occupant"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed mountpoint: %v", err)
	}

	vfsOpt := vfscommon.Opt
	mountOpt := mountlib.Opt
	mountOpt.AllowNonEmpty = false
	fsys := newTestMount2FS(t, "ocufs-nonempty", &vfsOpt, &mountOpt)

	errChan, unmount, mp, err := directMountFn(fsys.VFS, dir, &mountOpt)
	if err == nil {
		t.Fatal("directMountFn on a non-empty mountpoint with AllowNonEmpty unset returned nil; want the not-empty rejection")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("error = %q; want the not-empty rejection", err)
	}
	if errChan != nil || unmount != nil || mp != "" {
		t.Fatalf("error return must be the empty 4-tuple; got chan=%v unmount-set=%v mountpoint=%q", errChan, unmount != nil, mp)
	}
}

// fakeFuseServer records the serve/teardown calls so the lifecycle wiring can
// be asserted without a kernel mount. serveStarted is buffered so Serve can
// signal without blocking; release holds Serve open until the test lets go.
type fakeFuseServer struct {
	serveStarted chan struct{}
	release      chan struct{}
	waited       bool
	unmounted    bool
}

func (s *fakeFuseServer) Serve() {
	s.serveStarted <- struct{}{}
	<-s.release
}
func (s *fakeFuseServer) Wait()          { s.waited = true }
func (s *fakeFuseServer) Unmount() error { s.unmounted = true; return nil }

// TestServeFuseLifecycle pins the serve/teardown wiring of the direct-mount
// frontend: the server is served in the background, the terminal value lands
// on the error channel only after the serve loop has exited and drained
// (Wait), and the unmount closure shuts the VFS down BEFORE detaching the
// kernel mount so in-flight writes flush while the mount still exists.
func TestServeFuseLifecycle(t *testing.T) {
	srv := &fakeFuseServer{
		serveStarted: make(chan struct{}, 1),
		release:      make(chan struct{}),
	}
	var order []string
	shutdownVFS := func() { order = append(order, "vfs-shutdown") }

	errs, umount := serveFuse(srv, shutdownVFS)

	select {
	case <-srv.serveStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve was not started in the background")
	}
	select {
	case <-errs:
		t.Fatal("terminal value landed while the serve loop was still running")
	default:
	}

	if err := umount(); err != nil {
		t.Fatalf("unmount closure: %v", err)
	}
	order = append(order, "kernel-detach-done")
	if !srv.unmounted {
		t.Fatal("unmount closure never detached the kernel mount")
	}
	if order[0] != "vfs-shutdown" {
		t.Fatalf("teardown order = %v; want the VFS shut down before the kernel detach", order)
	}

	close(srv.release)
	select {
	case v := <-errs:
		if v != nil {
			t.Fatalf("terminal value = %v; want nil for a clean serve exit", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal value never landed after the serve loop exited")
	}
	if !srv.waited {
		t.Fatal("serve goroutine fed the channel without draining via Wait")
	}
}

// TestDirectMountFnNoFusermountDependency drives the full server assembly
// (node tree, option mapping, NewNodeFS, NewServer) against a real empty
// mountpoint. In CI and on developer machines there is no usable FUSE device
// or no privilege for the mount syscall, so the strict direct path must fail
// CLEANLY with the empty 4-tuple — proving the failure mode is the syscall
// itself and never a missing helper binary. If the environment can actually
// mount (root with /dev/fuse), the mount must come up and unmount cleanly; the
// live end-to-end pass stays with the VM harness.
func TestDirectMountFnNoFusermountDependency(t *testing.T) {
	vfsOpt := vfscommon.Opt
	mountOpt := mountlib.Opt
	fsys := newTestMount2FS(t, "ocufs-directmount", &vfsOpt, &mountOpt)

	errChan, unmount, mp, err := directMountFn(fsys.VFS, t.TempDir(), &mountOpt)
	if err != nil {
		if errChan != nil || unmount != nil || mp != "" {
			t.Fatalf("error return must be the empty 4-tuple; got chan=%v unmount-set=%v mountpoint=%q", errChan, unmount != nil, mp)
		}
		if strings.Contains(err.Error(), "fusermount") {
			t.Fatalf("direct mount failed through a fusermount helper path: %v", err)
		}
		t.Logf("direct mount unavailable here (expected without /dev/fuse + privilege): %v", err)
		return
	}

	// The environment can really mount: tear it down and require a clean exit.
	if unmount == nil || mp == "" || errChan == nil {
		t.Fatal("successful mount must return a live 4-tuple")
	}
	if err := unmount(); err != nil {
		t.Fatalf("unmount after live direct mount: %v", err)
	}
	select {
	case <-errChan:
	case <-time.After(5 * time.Second):
		t.Fatal("serve loop did not exit after unmount")
	}
}
