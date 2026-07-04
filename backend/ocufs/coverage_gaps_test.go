// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocufs tests — error-branch and edge-case coverage for the mapping
// layer (copymove.go, object.go, ocufs.go). Each test asserts an observable
// outcome (error sentinel, wrapped error, path passed to the client, or the
// absence of a client call), never just line execution.
package ocufs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"
)

// ---------------------------------------------------------------------------
// foreignObjectInfoReal — an fs.ObjectInfo that is NOT an *Object, used to
// drive the "src is not an *Object from this backend" branch of Copy/Move (the
// path is derived from src.Remote() relative to the Fs root rather than from a
// stored *Object.path).
// ---------------------------------------------------------------------------

type foreignObjectInfoReal struct {
	remote string
}

func (o *foreignObjectInfoReal) Fs() fs.Info                           { return nil }
func (o *foreignObjectInfoReal) String() string                        { return o.remote }
func (o *foreignObjectInfoReal) Remote() string                        { return o.remote }
func (o *foreignObjectInfoReal) ModTime(ctx context.Context) time.Time { return time.Time{} }
func (o *foreignObjectInfoReal) Size() int64                           { return 0 }
func (o *foreignObjectInfoReal) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return "", nil
}
func (o *foreignObjectInfoReal) Storable() bool { return true }

// The fs.Object surface beyond fs.ObjectInfo. The Copy/Move foreign-src branch
// derives the path from Remote() and never invokes these; they exist only so
// the type satisfies fs.Object.
func (o *foreignObjectInfoReal) SetModTime(ctx context.Context, t time.Time) error { return nil }
func (o *foreignObjectInfoReal) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	return nil, nil
}
func (o *foreignObjectInfoReal) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	return nil
}
func (o *foreignObjectInfoReal) Remove(ctx context.Context) error { return nil }

// ---------------------------------------------------------------------------
// Copy — foreign src and error branch.
// ---------------------------------------------------------------------------

// TestCopyForeignSrcRejected verifies that when src is NOT an *Object bound to
// this Fs, Copy returns fs.ErrorCantCopy and issues NO CopyFile call — so rclone
// falls back to download+upload across the scope boundary rather than the broker
// server-side copying a path that does not exist in this filesystem_id.
func TestCopyForeignSrcRejected(t *testing.T) {
	c := &fakeClient{}
	c.copyFileResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		t.Fatalf("CopyFile must not be called for a foreign src (got %q → %q)", srcPath, dstPath)
		return nil, nil
	}

	f := newTestFsWithRoot(t, c, "/data", false)
	f.enc = defaultEncoding

	src := &foreignObjectInfoReal{remote: "a/foreign.txt"}
	_, err := f.Copy(context.Background(), src, "b/dst.txt")
	if !errors.Is(err, fs.ErrorCantCopy) {
		t.Fatalf("Copy with foreign src = %v, want fs.ErrorCantCopy", err)
	}
	if c.copyFileCount != 0 {
		t.Errorf("CopyFile called %d times for a foreign src, want 0", c.copyFileCount)
	}
}

// TestCopyClientErrorWrapped verifies that a CopyFile error is wrapped (not
// dropped) and propagated by Copy, and that no destination Object is returned.
func TestCopyClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.copyFileResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		return nil, brokerrpc.ErrPermissionDenied
	}
	f := newTestFsWithRoot(t, c, "/", false)
	f.enc = defaultEncoding

	srcObj := &Object{fs: f, path: "/src.txt", remote: "src.txt", uuid: "u"}
	got, err := f.Copy(context.Background(), srcObj, "dst.txt")
	if err == nil {
		t.Fatal("Copy with client error returned nil error, want a wrapped error")
	}
	if !errors.Is(err, brokerrpc.ErrPermissionDenied) {
		t.Errorf("Copy error = %v, want it to wrap brokerrpc.ErrPermissionDenied", err)
	}
	if got != nil {
		t.Errorf("Copy with client error returned object %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// Move — foreign src and error branch.
// ---------------------------------------------------------------------------

// TestMoveForeignSrcRejected verifies the foreign-src rejection branch of Move:
// a src not bound to this Fs returns fs.ErrorCantMove and issues NO MoveFile
// call, so rclone falls back to copy+delete across the scope boundary.
func TestMoveForeignSrcRejected(t *testing.T) {
	c := &fakeClient{}
	c.moveFileResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		t.Fatalf("MoveFile must not be called for a foreign src (got %q → %q)", srcPath, dstPath)
		return nil, nil
	}

	f := newTestFsWithRoot(t, c, "/", false)
	f.enc = defaultEncoding

	src := &foreignObjectInfoReal{remote: "old/name.bin"}
	_, err := f.Move(context.Background(), src, "new/name.bin")
	if !errors.Is(err, fs.ErrorCantMove) {
		t.Fatalf("Move with foreign src = %v, want fs.ErrorCantMove", err)
	}
	if c.moveFileCount != 0 {
		t.Errorf("MoveFile called %d times for a foreign src, want 0", c.moveFileCount)
	}
}

// TestMoveClientErrorWrapped verifies that a MoveFile error is wrapped and
// propagated and no destination Object is returned.
func TestMoveClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.moveFileResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		return nil, brokerrpc.ErrNotFound
	}
	f := newTestFsWithRoot(t, c, "/", false)
	f.enc = defaultEncoding

	srcObj := &Object{fs: f, path: "/src.txt", remote: "src.txt", uuid: "u"}
	got, err := f.Move(context.Background(), srcObj, "dst.txt")
	if err == nil {
		t.Fatal("Move with client error returned nil error, want a wrapped error")
	}
	if !errors.Is(err, brokerrpc.ErrNotFound) {
		t.Errorf("Move error = %v, want it to wrap brokerrpc.ErrNotFound", err)
	}
	if got != nil {
		t.Errorf("Move with client error returned object %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// DirMove — error branch.
// ---------------------------------------------------------------------------

// TestDirMoveClientErrorWrapped verifies that a MoveDirectory error is wrapped
// and propagated by DirMove (the same-Fs identity check has already passed).
func TestDirMoveClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.moveDirectoryResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		return nil, brokerrpc.ErrAlreadyExists
	}
	f := newTestFsWithRoot(t, c, "/", false)
	f.enc = defaultEncoding

	err := f.DirMove(context.Background(), f, "src/dir", "dst/dir")
	if err == nil {
		t.Fatal("DirMove with client error returned nil error, want a wrapped error")
	}
	if !errors.Is(err, brokerrpc.ErrAlreadyExists) {
		t.Errorf("DirMove error = %v, want it to wrap brokerrpc.ErrAlreadyExists", err)
	}
}

// ---------------------------------------------------------------------------
// object.go — Update / Remove / Open / resolve error branches.
// ---------------------------------------------------------------------------

// TestUpdateClientErrorWrapped verifies that an Upload error from Update is
// wrapped and propagated, and the Object's uuid is NOT cleared on failure
// (the success-only post-state must not run).
func TestUpdateClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.uploadResult = func(ctx context.Context, path string, src io.Reader, totalBytes int64) error {
		return brokerrpc.ErrPermissionDenied
	}
	f := newTestFs(t, c, false)

	obj := &Object{fs: f, path: "/docs/file.txt", uuid: "keep-uuid", size: 100}
	src := &fakeObjectInfo{remote: "docs/file.txt", size: 5}

	err := obj.Update(context.Background(), bytes.NewReader([]byte("data!")), src)
	if err == nil {
		t.Fatal("Update with Upload error returned nil error, want a wrapped error")
	}
	if !errors.Is(err, brokerrpc.ErrPermissionDenied) {
		t.Errorf("Update error = %v, want it to wrap brokerrpc.ErrPermissionDenied", err)
	}
	// On the error path the success-only state mutations must not run.
	if obj.uuid != "keep-uuid" {
		t.Errorf("Update cleared uuid on failure (uuid=%q); the success-only post-state ran on an error", obj.uuid)
	}
}

// TestRemoveClientErrorWrapped verifies that a RemoveFile error from Remove is
// wrapped and propagated.
func TestRemoveClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.removeFileResult = func(ctx context.Context, path string) (*brokerrpc.AckResponse, error) {
		return nil, brokerrpc.ErrNotFound
	}
	f := newTestFs(t, c, false)

	obj := &Object{fs: f, path: "/gone.txt", uuid: "u", size: 1}
	err := obj.Remove(context.Background())
	if err == nil {
		t.Fatal("Remove with client error returned nil error, want a wrapped error")
	}
	if !errors.Is(err, brokerrpc.ErrNotFound) {
		t.Errorf("Remove error = %v, want it to wrap brokerrpc.ErrNotFound", err)
	}
}

// TestUpdateClearsUUIDOnSuccess verifies that on a successful Update the uuid is
// cleared (so the next access re-resolves) and size is updated optimistically
// from src.
func TestUpdateClearsUUIDOnSuccess(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)

	obj := &Object{fs: f, path: "/docs/file.txt", uuid: "old-uuid", size: 100}
	src := &fakeObjectInfo{remote: "docs/file.txt", size: 42}

	if err := obj.Update(context.Background(), bytes.NewReader(make([]byte, 42)), src); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if obj.uuid != "" {
		t.Errorf("after Update, uuid = %q, want empty (re-resolve on next access)", obj.uuid)
	}
	if obj.size != 42 {
		t.Errorf("after Update, size = %d, want 42 (optimistic from src)", obj.size)
	}
	if c.lastUploadOverwrite != true {
		t.Error("Update issued Upload with overwrite=false, want overwrite=true (in-place replace)")
	}
}

// TestOpenResolveErrorPropagated verifies that when resolve() fails (a non
// not-found broker error), Open returns that error and issues NO download.
func TestOpenResolveErrorPropagated(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return nil, brokerrpc.ErrPermissionDenied
	}
	downloadCalled := false
	c.downloadResult = func(ctx context.Context, uuid string) ([]byte, error) {
		downloadCalled = true
		return nil, nil
	}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/denied.bin", uuid: ""}

	_, err := obj.Open(context.Background())
	if err == nil {
		t.Fatal("Open with resolve error returned nil error, want a propagated error")
	}
	if !errors.Is(err, brokerrpc.ErrPermissionDenied) {
		t.Errorf("Open error = %v, want it to wrap brokerrpc.ErrPermissionDenied", err)
	}
	if downloadCalled {
		t.Error("Open issued a Download after a failed resolve; want none")
	}
}

// TestOpenFullReadDownloadError verifies the full-read (Download) error branch:
// a List-derived Object with no range option triggers Download, and a Download
// error is propagated unwrapped for rclone's retry layer.
func TestOpenFullReadDownloadError(t *testing.T) {
	c := &fakeClient{}
	sentinel := errors.New("download transport failure")
	c.downloadResult = func(ctx context.Context, uuid string) ([]byte, error) {
		return nil, sentinel
	}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/file.bin", uuid: "u-full", size: 10}

	_, err := obj.Open(context.Background())
	if !errors.Is(err, sentinel) {
		t.Errorf("Open full-read error = %v, want the propagated download error", err)
	}
	if c.downloadCount != 1 {
		t.Errorf("Download called %d times, want 1 (full read with no range option)", c.downloadCount)
	}
}

// TestOpenRangeDownloadError verifies the ranged-read (DownloadRange) error
// branch is propagated.
func TestOpenRangeDownloadError(t *testing.T) {
	c := &fakeClient{}
	sentinel := errors.New("ranged download failure")
	c.downloadRangeResult = func(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
		return nil, sentinel
	}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/file.bin", uuid: "u-range", size: 100}

	_, err := obj.Open(context.Background(), &fs.RangeOption{Start: 0, End: 9})
	if !errors.Is(err, sentinel) {
		t.Errorf("Open ranged-read error = %v, want the propagated download error", err)
	}
}

// TestOpenSeekBeyondEndClampsLengthToZero verifies the defensive clamp in the
// SeekOption branch: a seek offset past EOF yields a negative computed length,
// which Open clamps to 0 so DownloadRange receives a non-negative window.
func TestOpenSeekBeyondEndClampsLengthToZero(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/file.bin", uuid: "u-seek", size: 100}

	rc, err := obj.Open(context.Background(), &fs.SeekOption{Offset: 150}) // past EOF
	if err != nil {
		t.Fatalf("Open with seek past EOF: %v", err)
	}
	_ = rc.Close()
	if c.downloadRangeCount != 1 {
		t.Fatalf("DownloadRange called %d times, want 1", c.downloadRangeCount)
	}
	if c.lastDownloadRangeOffset != 150 {
		t.Errorf("DownloadRange offset = %d, want 150", c.lastDownloadRangeOffset)
	}
	if c.lastDownloadRangeLength != 0 {
		t.Errorf("DownloadRange length = %d, want 0 (clamped: seek past EOF)", c.lastDownloadRangeLength)
	}
}

// TestOpenRangeToEndBeyondEndClampsLengthToZero verifies the defensive clamp in
// the RangeOption "to end" branch (End=-1): a start offset past EOF yields a
// negative computed length, clamped to 0.
func TestOpenRangeToEndBeyondEndClampsLengthToZero(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/file.bin", uuid: "u-range-end", size: 100}

	// Start past EOF, open-ended (End=-1 → "to end" sentinel from Decode).
	rc, err := obj.Open(context.Background(), &fs.RangeOption{Start: 150, End: -1})
	if err != nil {
		t.Fatalf("Open with open-ended range past EOF: %v", err)
	}
	_ = rc.Close()
	if c.downloadRangeCount != 1 {
		t.Fatalf("DownloadRange called %d times, want 1", c.downloadRangeCount)
	}
	if c.lastDownloadRangeOffset != 150 {
		t.Errorf("DownloadRange offset = %d, want 150", c.lastDownloadRangeOffset)
	}
	if c.lastDownloadRangeLength != 0 {
		t.Errorf("DownloadRange length = %d, want 0 (clamped: start past EOF)", c.lastDownloadRangeLength)
	}
}

// TestImmediateChildRemoteBothArmsNil verifies that an entry whose File and
// Directory arms are both nil (an unknown/future union variant) is filtered out
// by immediateChildRemote (the default arm returns false) and dropped by List.
func TestImmediateChildRemoteBothArmsNil(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false)
	_, ok := f.immediateChildRemote("", brokerrpc.ListDirEntry{}) // both arms nil
	if ok {
		t.Error("immediateChildRemote for an entry with both arms nil returned true, want false")
	}
}

// TestListDropsBothArmsNilEntry verifies that List silently tolerates and drops
// a union entry with neither arm populated (forward-tolerant per D6).
func TestListDropsBothArmsNilEntry(t *testing.T) {
	c := &fakeClient{}
	c.listDirectoryAllResult = func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
		return []brokerrpc.ListDirEntry{
			{File: &brokerrpc.FilesystemFile{Path: "/root/keep.txt", UUID: "u", Mtime: "2026-01-01T00:00:00Z"}},
			{}, // both arms nil — must be tolerated and dropped
		}, nil
	}
	f := newTestFs(t, c, false)
	f.root = "/"
	entries, err := f.List(context.Background(), "root")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %d entries, want 1 (the nil-arm entry must be dropped)", len(entries))
	}
}

// TestResolveIsDir verifies that resolve() on a uuid-less Object whose
// ReadMetadata response classifies as a directory returns fs.ErrorIsDir (via
// Open, which calls resolve first).
func TestResolveIsDir(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			Directory: brokerrpc.Directory{Path: path},
		}, nil
	}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/actually-a-dir", uuid: ""}

	_, err := obj.Open(context.Background())
	if !errors.Is(err, fs.ErrorIsDir) {
		t.Errorf("Open on a path that resolves to a directory: got %v, want fs.ErrorIsDir", err)
	}
}

// TestResolveAbsentObjectNotFound verifies that resolve() on a response whose
// arms are both absent returns fs.ErrorObjectNotFound.
func TestResolveAbsentObjectNotFound(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{}, nil // neither arm present
	}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/nothing-here", uuid: ""}

	_, err := obj.Open(context.Background())
	if !errors.Is(err, fs.ErrorObjectNotFound) {
		t.Errorf("Open on an absent-arm resolve: got %v, want fs.ErrorObjectNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// ocufs.go — NewObject / Put / Rmdir / List error branches.
// ---------------------------------------------------------------------------

// TestNewObjectClientErrorWrapped verifies that a non-not-found ReadMetadata
// error from NewObject is wrapped (not mapped to ErrorObjectNotFound) and
// propagated.
func TestNewObjectClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return nil, brokerrpc.ErrPermissionDenied
	}
	f := newTestFs(t, c, false)

	_, err := f.NewObject(context.Background(), "file.txt")
	if err == nil {
		t.Fatal("NewObject with client error returned nil error, want a wrapped error")
	}
	if errors.Is(err, fs.ErrorObjectNotFound) {
		t.Errorf("NewObject mapped a permission error to ErrorObjectNotFound; want the wrapped permission error")
	}
	if !errors.Is(err, brokerrpc.ErrPermissionDenied) {
		t.Errorf("NewObject error = %v, want it to wrap brokerrpc.ErrPermissionDenied", err)
	}
}

// TestNewObjectNilResponse verifies that a nil ReadMetadata response (no error)
// maps to fs.ErrorObjectNotFound.
func TestNewObjectNilResponse(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return nil, nil
	}
	f := newTestFs(t, c, false)

	_, err := f.NewObject(context.Background(), "file.txt")
	if !errors.Is(err, fs.ErrorObjectNotFound) {
		t.Errorf("NewObject with nil response: got %v, want fs.ErrorObjectNotFound", err)
	}
}

// TestPutClientErrorWrapped verifies that an Upload error from Put is wrapped
// and propagated and no Object is returned.
func TestPutClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.uploadResult = func(ctx context.Context, path string, src io.Reader, totalBytes int64) error {
		return brokerrpc.ErrAlreadyExists
	}
	f := newTestFs(t, c, false)

	src := &fakeObjectInfo{remote: "new.txt", size: 3}
	got, err := f.Put(context.Background(), bytes.NewReader([]byte("abc")), src)
	if err == nil {
		t.Fatal("Put with Upload error returned nil error, want a wrapped error")
	}
	if !errors.Is(err, brokerrpc.ErrAlreadyExists) {
		t.Errorf("Put error = %v, want it to wrap brokerrpc.ErrAlreadyExists", err)
	}
	if got != nil {
		t.Errorf("Put with client error returned object %v, want nil", got)
	}
}

// TestPutUsesOverwriteFalse verifies that Put (the create-new write path)
// issues Upload with overwrite=false so a colliding destination is a conflict,
// not a silent in-place replacement.
func TestPutUsesOverwriteFalse(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)

	src := &fakeObjectInfo{remote: "new.txt", size: 3}
	if _, err := f.Put(context.Background(), bytes.NewReader([]byte("abc")), src); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if c.lastUploadOverwrite != false {
		t.Error("Put issued Upload with overwrite=true, want overwrite=false (create-new path)")
	}
}

// TestRmdirClientErrorWrapped verifies that a RemoveDirectory error from Rmdir
// is wrapped and propagated.
func TestRmdirClientErrorWrapped(t *testing.T) {
	c := &fakeClient{}
	c.removeDirectoryResult = func(ctx context.Context, path string) (*brokerrpc.AckResponse, error) {
		return nil, brokerrpc.ErrNotFound
	}
	f := newTestFs(t, c, false)

	err := f.Rmdir(context.Background(), "olddir")
	if err == nil {
		t.Fatal("Rmdir with client error returned nil error, want a wrapped error")
	}
	if !errors.Is(err, brokerrpc.ErrNotFound) {
		t.Errorf("Rmdir error = %v, want it to wrap brokerrpc.ErrNotFound", err)
	}
}

// TestListDirNotFoundMappedToErrorDirNotFound verifies that a broker not_found
// from ListDirectoryAll maps to fs.ErrorDirNotFound (so the VFS distinguishes a
// missing directory from a transport failure).
func TestListDirNotFoundMappedToErrorDirNotFound(t *testing.T) {
	c := &fakeClient{}
	c.listDirectoryAllResult = func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
		return nil, brokerrpc.ErrNotFound
	}
	f := newTestFs(t, c, false)

	_, err := f.List(context.Background(), "missingdir")
	if !errors.Is(err, fs.ErrorDirNotFound) {
		t.Errorf("List on a not-found directory: got %v, want fs.ErrorDirNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// classifyReadMetadata — nil response arm.
// ---------------------------------------------------------------------------

// TestClassifyReadMetadataNil verifies that classifyReadMetadata(nil) returns
// metaArmAbsent (the nil guard inside the helper).
func TestClassifyReadMetadataNil(t *testing.T) {
	if got := classifyReadMetadata(nil); got != metaArmAbsent {
		t.Errorf("classifyReadMetadata(nil) = %v, want metaArmAbsent", got)
	}
}

// ---------------------------------------------------------------------------
// parseMtime — the RFC3339 fallback branch is provably unreachable.
// ---------------------------------------------------------------------------

// TestParseMtimeFirstLayoutDecodesEveryWireShape pins that parseMtime's FIRST
// layout (time.RFC3339Nano) decodes every timestamp shape the wire can carry to
// the exact instant: with and without a fractional-seconds component, single-
// digit and full nanosecond fractions, and both the Z and numeric-offset zone
// forms. This is the live branch every production decode takes.
func TestParseMtimeFirstLayoutDecodesEveryWireShape(t *testing.T) {
	cases := []string{
		"2026-06-13T15:04:05Z",                // no fraction, Z
		"2026-06-13T15:04:05+02:00",           // no fraction, numeric offset
		"2026-06-13T15:04:05.5Z",              // single-digit fraction
		"2026-06-13T15:04:05.123456789Z",      // full nanosecond fraction
		"2026-06-13T15:04:05.123456789-07:30", // full fraction, numeric offset
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			want, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				t.Fatalf("time.Parse(RFC3339Nano, %q) = %v; the case input must be valid", s, err)
			}
			got := parseMtime(s)
			if !got.Equal(want) {
				t.Errorf("parseMtime(%q) = %v; want %v (the RFC3339Nano layout must decode it exactly)", s, got, want)
			}
		})
	}
}

// TestParseMtimeRFC3339FallbackIsUnreachable documents and pins, empirically,
// that the second time.Parse (time.RFC3339) in parseMtime is dead code: it can
// never run on any input, because the two layouts accept the IDENTICAL set of
// strings and decode each to the IDENTICAL instant.
//
// Go's time.Parse permits an optional fractional-seconds component after the
// seconds field for BOTH layouts — the only difference between RFC3339 and
// RFC3339Nano is how they FORMAT a time, not which strings they PARSE. So the
// first time.Parse (RFC3339Nano) succeeds for every string the second
// (RFC3339) would succeed on; the fallback is never reached.
//
// The earlier test in this position claimed to exercise the fallback while
// feeding it an input the first layout already accepts; that misleading claim
// is removed. This test asserts the real property over a generated grid of
// every zone form, fraction shape, and a wide span of instants: for each input,
// the two layouts agree on parse-success and (when both succeed) on the instant.
// A single divergence — the only thing that could ever make the fallback
// reachable or behaviourally distinct — fails the test.
func TestParseMtimeRFC3339FallbackIsUnreachable(t *testing.T) {
	zones := []string{"Z", "+00:00", "+02:00", "-07:30", "+14:00", "-12:00"}
	fractions := []string{"", ".5", ".123", ".000000001", ".999999999"}
	// A span of instants across decades, including a leap day and year/month
	// boundaries, to exercise the date fields alongside the fraction/zone grid.
	bases := []string{
		"2000-01-01T00:00:00",
		"2024-02-29T23:59:59", // leap day
		"2026-06-13T15:04:05",
		"2099-12-31T12:00:00",
	}

	checked := 0
	for _, base := range bases {
		for _, frac := range fractions {
			for _, zone := range zones {
				s := base + frac + zone
				tNano, errNano := time.Parse(time.RFC3339Nano, s)
				t3339, err3339 := time.Parse(time.RFC3339, s)
				checked++

				// Parse-success must agree: if they ever disagreed, an input
				// could exist that only the fallback handles.
				if (errNano == nil) != (err3339 == nil) {
					t.Fatalf("layouts disagree on %q: RFC3339Nano err=%v, RFC3339 err=%v; the fallback would no longer be unreachable", s, errNano, err3339)
				}
				// When both succeed they must yield the identical instant, so
				// the fallback would also be behaviourally redundant.
				if errNano == nil && !tNano.Equal(t3339) {
					t.Fatalf("layouts disagree on the instant for %q: RFC3339Nano=%v, RFC3339=%v", s, tNano, t3339)
				}
				// parseMtime, which tries RFC3339Nano first, must return that
				// same instant whenever the input is valid.
				if errNano == nil {
					if got := parseMtime(s); !got.Equal(tNano) {
						t.Fatalf("parseMtime(%q) = %v; want %v", s, got, tNano)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no inputs checked; the grid is empty")
	}
}
