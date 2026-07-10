// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"github.com/hanwen/go-fuse/v2/fuse"
)

// xattrENOTSUPFileSystem wraps a fuse.RawFileSystem and rewrites the status of
// the extended-attribute operations from ENOSYS to ENOTSUP.
//
// The mount serves no extended attributes: rclone's mount2 node answers every
// xattr op with ENOSYS. On a native kernel that is harmless — the kernel's FUSE
// layer caches the "no xattr support" signal and hands userspace ENOTSUP, the
// POSIX answer for "this filesystem does not support extended attributes", which
// tools absorb silently. Under the gVisor (runsc) sentry there is no such
// rewrite: the ENOSYS is forwarded to userspace verbatim, and coreutils
// `ls -la` (which probes getxattr/listxattr on each path to render the SELinux/
// ACL column) prints a spurious "Function not implemented" line for every entry
// while still completing the listing. A file manager doing the same probe shows
// the same noise.
//
// This decorator makes the two kernels agree by returning ENOTSUP directly, so
// the guest sees the same clean "no xattrs here" answer a native mount gives.
// It is a translation ONLY: any other status — a real xattr value (OK), a
// genuine ENOATTR/ENODATA, or a transport error — passes through unchanged, so
// the wrapper is a no-op the moment the underlying node grows real xattr
// support. The write-side ops (SetXAttr/RemoveXAttr) are translated for the same
// reason, though the read path is where the visible symptom lives.
//
// The wrapper lives here rather than as a mount option because go-fuse's own
// DisableXAttrs short-circuits xattr ops to ENOSYS INSIDE the server, before any
// filesystem method runs — exactly the leak this fixes. So DisableXAttrs is left
// unset (buildFuseMountOptions) and the ops are allowed to reach this decorator,
// which supplies the correct errno. Keeping the fix in a first-party wrapper
// leaves the upstream mount2 node and go-fuse untouched (zero rebase diff).
type xattrENOTSUPFileSystem struct {
	fuse.RawFileSystem
}

// newXattrENOTSUPFileSystem wraps inner so its xattr ops answer ENOTSUP instead
// of ENOSYS. Every non-xattr op is served by the embedded RawFileSystem
// unchanged.
func newXattrENOTSUPFileSystem(inner fuse.RawFileSystem) *xattrENOTSUPFileSystem {
	return &xattrENOTSUPFileSystem{RawFileSystem: inner}
}

// enosysToENOTSUP maps a single ENOSYS status to ENOTSUP and leaves every other
// status untouched.
func enosysToENOTSUP(s fuse.Status) fuse.Status {
	if s == fuse.ENOSYS {
		return fuse.ENOTSUP
	}
	return s
}

func (fsw *xattrENOTSUPFileSystem) GetXAttr(cancel <-chan struct{}, header *fuse.InHeader, attr string, dest []byte) (uint32, fuse.Status) {
	n, s := fsw.RawFileSystem.GetXAttr(cancel, header, attr, dest)
	return n, enosysToENOTSUP(s)
}

func (fsw *xattrENOTSUPFileSystem) ListXAttr(cancel <-chan struct{}, header *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	n, s := fsw.RawFileSystem.ListXAttr(cancel, header, dest)
	return n, enosysToENOTSUP(s)
}

func (fsw *xattrENOTSUPFileSystem) SetXAttr(cancel <-chan struct{}, input *fuse.SetXAttrIn, attr string, data []byte) fuse.Status {
	return enosysToENOTSUP(fsw.RawFileSystem.SetXAttr(cancel, input, attr, data))
}

func (fsw *xattrENOTSUPFileSystem) RemoveXAttr(cancel <-chan struct{}, header *fuse.InHeader, attr string) fuse.Status {
	return enosysToENOTSUP(fsw.RawFileSystem.RemoveXAttr(cancel, header, attr))
}
