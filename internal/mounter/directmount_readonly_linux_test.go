// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux

package mounter

import (
	"slices"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// assertReadOnlyExpressed pins the production (linux) read-only expression: the
// MS_RDONLY flag bit is set in DirectMountFlags (alongside the go-fuse
// MS_NOSUID|MS_NODEV defaults), and "ro" never rides the option string. The
// option-string form is rejected by a userspace-kernel sandbox's mount(2) with
// EINVAL, so read-only must be a flag here.
func assertReadOnlyExpressed(t *testing.T, mo fuse.MountOptions) {
	t.Helper()
	if slices.Contains(mo.Options, "ro") {
		t.Fatalf("option strings %v carry \"ro\": read-only must ride the mount flags, not the FUSE mount-data option string (a sandboxed kernel rejects the unknown data option with EINVAL)", mo.Options)
	}
	const want = uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_RDONLY)
	if mo.DirectMountFlags != want {
		t.Fatalf("DirectMountFlags = %#x; want %#x (MS_NOSUID|MS_NODEV|MS_RDONLY) so the read-only posture rides the mount flags", mo.DirectMountFlags, want)
	}
}
