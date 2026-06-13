// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux

package mounter

import (
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// applyReadOnly expresses a read-only mount through the mount(2) flag bits
// rather than an option string.
//
// Under DirectMountStrict the option string is passed verbatim to the mount(2)
// syscall as FUSE mount DATA. The kernel FUSE filesystem parses only a fixed
// set of data options, and "ro" is not one of them: read-only is a property of
// the mount, carried by the MS_RDONLY flag, not of the filesystem instance. A
// native kernel ignores the unrecognised "ro" data token, but a
// userspace-kernel sandbox rejects the whole mount with EINVAL — so a "ro"
// string makes a read-only mount fail there while writable mounts (which add no
// such token) succeed. Setting MS_RDONLY in the flags makes the read-only mount
// succeed on both kernels.
//
// go-fuse uses MS_NOSUID|MS_NODEV as its DirectMountFlags default (matching the
// fusermount helper) when the field is zero; those bits are preserved here and
// MS_RDONLY is added so the read-only posture rides the flags and the option
// string stays empty. It returns no extra option strings on this platform.
func applyReadOnly(mo *fuse.MountOptions, readOnly bool) []string {
	if !readOnly {
		return nil
	}
	mo.DirectMountFlags = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_RDONLY
	return nil
}
