// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// fakeRawFS is a minimal fuse.RawFileSystem stub whose xattr methods return a
// programmable status, so the decorator's translation can be asserted without a
// kernel mount. It embeds NewDefaultRawFileSystem for every method the tests do
// not exercise.
type fakeRawFS struct {
	fuse.RawFileSystem
	getStatus  fuse.Status
	listStatus fuse.Status
	setStatus  fuse.Status
	rmStatus   fuse.Status
	// calls records which xattr method the wrapper forwarded to, proving the
	// wrapper delegates rather than answering on its own.
	getCalled, listCalled, setCalled, rmCalled bool
}

func newFakeRawFS() *fakeRawFS {
	return &fakeRawFS{RawFileSystem: fuse.NewDefaultRawFileSystem()}
}

func (f *fakeRawFS) GetXAttr(cancel <-chan struct{}, header *fuse.InHeader, attr string, dest []byte) (uint32, fuse.Status) {
	f.getCalled = true
	return 0, f.getStatus
}

func (f *fakeRawFS) ListXAttr(cancel <-chan struct{}, header *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	f.listCalled = true
	return 0, f.listStatus
}

func (f *fakeRawFS) SetXAttr(cancel <-chan struct{}, input *fuse.SetXAttrIn, attr string, data []byte) fuse.Status {
	f.setCalled = true
	return f.setStatus
}

func (f *fakeRawFS) RemoveXAttr(cancel <-chan struct{}, header *fuse.InHeader, attr string) fuse.Status {
	f.rmCalled = true
	return f.rmStatus
}

// TestXattrWrapperTranslatesGetXAttrENOSYS pins the core fix: a node that
// answers GETXATTR with ENOSYS must surface as ENOTSUP to the kernel, because a
// native kernel silently rewrites a cached-ENOSYS xattr op to ENOTSUP for
// userspace but the gVisor sentry forwards ENOSYS verbatim, and coreutils `ls
// -la` prints "Function not implemented" on ENOSYS while staying silent on
// ENOTSUP (the POSIX "no xattrs here" answer).
func TestXattrWrapperTranslatesGetXAttrENOSYS(t *testing.T) {
	inner := newFakeRawFS()
	inner.getStatus = fuse.ENOSYS
	w := newXattrENOTSUPFileSystem(inner)

	_, got := w.GetXAttr(nil, &fuse.InHeader{}, "security.selinux", nil)

	if !inner.getCalled {
		t.Fatal("wrapper did not delegate GetXAttr to the inner filesystem")
	}
	if got != fuse.ENOTSUP {
		t.Fatalf("GetXAttr ENOSYS should translate to ENOTSUP, got %v", got)
	}
}

// TestXattrWrapperTranslatesListXAttrENOSYS pins the same translation for
// LISTXATTR, the op `ls -la` issues first when rendering the security column.
func TestXattrWrapperTranslatesListXAttrENOSYS(t *testing.T) {
	inner := newFakeRawFS()
	inner.listStatus = fuse.ENOSYS
	w := newXattrENOTSUPFileSystem(inner)

	_, got := w.ListXAttr(nil, &fuse.InHeader{}, nil)

	if !inner.listCalled {
		t.Fatal("wrapper did not delegate ListXAttr to the inner filesystem")
	}
	if got != fuse.ENOTSUP {
		t.Fatalf("ListXAttr ENOSYS should translate to ENOTSUP, got %v", got)
	}
}

// TestXattrWrapperTranslatesWriteSideENOSYS pins the write-side ops too: a
// SetXAttr/RemoveXAttr that a node cannot honour must also fail with the POSIX
// "not supported" errno rather than the gVisor-leaky ENOSYS.
func TestXattrWrapperTranslatesWriteSideENOSYS(t *testing.T) {
	inner := newFakeRawFS()
	inner.setStatus = fuse.ENOSYS
	inner.rmStatus = fuse.ENOSYS
	w := newXattrENOTSUPFileSystem(inner)

	if got := w.SetXAttr(nil, &fuse.SetXAttrIn{}, "user.k", []byte("v")); got != fuse.ENOTSUP {
		t.Fatalf("SetXAttr ENOSYS should translate to ENOTSUP, got %v", got)
	}
	if !inner.setCalled {
		t.Fatal("wrapper did not delegate SetXAttr to the inner filesystem")
	}
	if got := w.RemoveXAttr(nil, &fuse.InHeader{}, "user.k"); got != fuse.ENOTSUP {
		t.Fatalf("RemoveXAttr ENOSYS should translate to ENOTSUP, got %v", got)
	}
	if !inner.rmCalled {
		t.Fatal("wrapper did not delegate RemoveXAttr to the inner filesystem")
	}
}

// TestXattrWrapperPassesThroughNonENOSYS proves the wrapper touches ONLY the
// ENOSYS→ENOTSUP case: a real xattr value (OK), a genuine "no such attribute"
// (ENOATTR), and any other errno must pass through byte-for-byte, so the
// translation never masks a working xattr backend or a real error. If the
// inner node ever gains real xattr support, the wrapper is a no-op for it.
func TestXattrWrapperPassesThroughNonENOSYS(t *testing.T) {
	cases := []fuse.Status{fuse.OK, fuse.ENOATTR, fuse.EIO, fuse.EACCES, fuse.ERANGE}
	for _, st := range cases {
		inner := newFakeRawFS()
		inner.getStatus = st
		inner.listStatus = st
		inner.setStatus = st
		inner.rmStatus = st
		w := newXattrENOTSUPFileSystem(inner)

		if _, got := w.GetXAttr(nil, &fuse.InHeader{}, "user.k", nil); got != st {
			t.Errorf("GetXAttr status %v should pass through unchanged, got %v", st, got)
		}
		if _, got := w.ListXAttr(nil, &fuse.InHeader{}, nil); got != st {
			t.Errorf("ListXAttr status %v should pass through unchanged, got %v", st, got)
		}
		if got := w.SetXAttr(nil, &fuse.SetXAttrIn{}, "user.k", nil); got != st {
			t.Errorf("SetXAttr status %v should pass through unchanged, got %v", st, got)
		}
		if got := w.RemoveXAttr(nil, &fuse.InHeader{}, "user.k"); got != st {
			t.Errorf("RemoveXAttr status %v should pass through unchanged, got %v", st, got)
		}
	}
}
