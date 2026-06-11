// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
)

// ---------------------------------------------------------------------------
// Helpers for Copy/Move/DirMove tests
// ---------------------------------------------------------------------------

// newTestFsWithRoot returns an Fs backed by fc with the given root.
func newTestFsWithRoot(t *testing.T, c *fakeClient, root string, readOnly bool) *Fs {
	t.Helper()
	return &Fs{
		name:     "ocufs",
		root:     root,
		client:   c,
		readOnly: readOnly,
	}
}

// fakeObjectInfoAt returns a minimal fs.ObjectInfo at a given remote under the
// given Fs. Used as the src argument to Copy/Move.
type fakeObjectInfoAt struct {
	parentFs fs.Info
	remote   string
	size     int64
	mtime    time.Time
}

func (o *fakeObjectInfoAt) Fs() fs.Info                                            { return o.parentFs }
func (o *fakeObjectInfoAt) String() string                                         { return o.remote }
func (o *fakeObjectInfoAt) Remote() string                                         { return o.remote }
func (o *fakeObjectInfoAt) ModTime(ctx context.Context) time.Time                  { return o.mtime }
func (o *fakeObjectInfoAt) Size() int64                                            { return o.size }
func (o *fakeObjectInfoAt) Hash(ctx context.Context, ty hash.Type) (string, error) { return "", nil }
func (o *fakeObjectInfoAt) Storable() bool                                         { return true }

// ---------------------------------------------------------------------------
// TestCopyCallsCopyFile — Copy maps onto CopyFile with the correct src/dst paths.
// ---------------------------------------------------------------------------

// TestCopyCallsCopyFile verifies that Fs.Copy calls the client's CopyFile with
// the correct (sourcePath, destinationPath) derived from the source Object's
// path and the destination remote, and returns a uuid-less *Object for the
// destination.
func TestCopyCallsCopyFile(t *testing.T) {
	c := &fakeClient{}
	// Capture the args passed to CopyFile.
	var gotSrc, gotDst string
	c.copyFileResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		gotSrc = srcPath
		gotDst = dstPath
		return &brokerrpc.AckResponse{}, nil
	}
	// ReadMetadata result for the fallback resolve when ModTime is called.
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				UUID:  "resolved-copy-uuid",
				Size:  512,
				Path:  path,
				Mtime: "2026-05-01T00:00:00Z",
			},
		}, nil
	}

	f := newTestFsWithRoot(t, c, "/", false)

	// Build a source Object (as if returned by List — uuid pre-set).
	srcObj := &Object{
		fs:     f,
		path:   "/docs/src.txt",
		remote: "docs/src.txt",
		uuid:   "src-uuid-001",
		size:   512,
	}

	dstRemote := "docs/dst.txt"
	got, err := f.Copy(context.Background(), srcObj, dstRemote)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if got == nil {
		t.Fatal("Copy returned nil object")
	}

	// Assert CopyFile was called exactly once.
	if c.copyFileCount != 1 {
		t.Errorf("CopyFile called %d times, want 1", c.copyFileCount)
	}

	// Assert correct source and destination paths.
	if gotSrc != "/docs/src.txt" {
		t.Errorf("CopyFile sourcePath = %q, want %q", gotSrc, "/docs/src.txt")
	}
	if gotDst != "/docs/dst.txt" {
		t.Errorf("CopyFile destinationPath = %q, want %q", gotDst, "/docs/dst.txt")
	}

	// The returned Object must be uuid-LESS (CopyFile returns only an ack —
	// no uuid is available from the ack; the design decision 2 fallback
	// resolves it lazily on first access).
	dstObj, ok := got.(*Object)
	if !ok {
		t.Fatalf("Copy returned %T, want *Object", got)
	}
	if dstObj.uuid != "" {
		t.Errorf("Copy returned Object with uuid=%q, want empty (ack-only path)", dstObj.uuid)
	}
	if dstObj.Remote() != dstRemote {
		t.Errorf("Copy returned Object.Remote()=%q, want %q", dstObj.Remote(), dstRemote)
	}

	// Triggering ModTime should fire the defensive resolve (ReadMetadata).
	mtime := got.ModTime(context.Background())
	if mtime.IsZero() {
		t.Error("ModTime after resolve is zero; the fallback resolve did not populate it")
	}
	if c.readMetadataCount != 1 {
		t.Errorf("ReadMetadata called %d times after Copy, want 1 (defensive resolve)", c.readMetadataCount)
	}
}

// ---------------------------------------------------------------------------
// TestMoveCallsMoveFile — Move maps onto MoveFile with correct src/dst paths.
// ---------------------------------------------------------------------------

// TestMoveCallsMoveFile verifies that Fs.Move calls MoveFile with the correct
// paths and returns a uuid-less *Object for the destination.
func TestMoveCallsMoveFile(t *testing.T) {
	c := &fakeClient{}
	var gotSrc, gotDst string
	c.moveFileResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		gotSrc = srcPath
		gotDst = dstPath
		return &brokerrpc.AckResponse{}, nil
	}

	f := newTestFsWithRoot(t, c, "/data", false)

	srcObj := &Object{
		fs:     f,
		path:   "/data/a/file.bin",
		remote: "a/file.bin",
		uuid:   "mv-src-uuid",
		size:   1024,
	}

	dstRemote := "b/file.bin"
	got, err := f.Move(context.Background(), srcObj, dstRemote)
	if err != nil {
		t.Fatalf("Move: %v", err)
	}
	if got == nil {
		t.Fatal("Move returned nil object")
	}

	if c.moveFileCount != 1 {
		t.Errorf("MoveFile called %d times, want 1", c.moveFileCount)
	}
	if gotSrc != "/data/a/file.bin" {
		t.Errorf("MoveFile sourcePath = %q, want %q", gotSrc, "/data/a/file.bin")
	}
	if gotDst != "/data/b/file.bin" {
		t.Errorf("MoveFile destinationPath = %q, want %q", gotDst, "/data/b/file.bin")
	}

	dstObj, ok := got.(*Object)
	if !ok {
		t.Fatalf("Move returned %T, want *Object", got)
	}
	if dstObj.uuid != "" {
		t.Errorf("Move returned Object with uuid=%q, want empty (ack-only path)", dstObj.uuid)
	}
	if dstObj.Remote() != dstRemote {
		t.Errorf("Move returned Object.Remote()=%q, want %q", dstObj.Remote(), dstRemote)
	}
}

// ---------------------------------------------------------------------------
// TestDirMoveCallsMoveDirectory — DirMove maps onto MoveDirectory.
// ---------------------------------------------------------------------------

// TestDirMoveCallsMoveDirectory verifies that Fs.DirMove calls MoveDirectory
// with the correct source and destination paths.
func TestDirMoveCallsMoveDirectory(t *testing.T) {
	c := &fakeClient{}
	var gotSrc, gotDst string
	c.moveDirectoryResult = func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
		gotSrc = srcPath
		gotDst = dstPath
		return &brokerrpc.AckResponse{}, nil
	}

	f := newTestFsWithRoot(t, c, "/", false)

	// srcFs must be the same Fs (same filesystem_id scope).
	err := f.DirMove(context.Background(), f, "src/dir", "dst/dir")
	if err != nil {
		t.Fatalf("DirMove: %v", err)
	}

	if c.moveDirectoryCount != 1 {
		t.Errorf("MoveDirectory called %d times, want 1", c.moveDirectoryCount)
	}
	if gotSrc != "/src/dir" {
		t.Errorf("MoveDirectory sourcePath = %q, want %q", gotSrc, "/src/dir")
	}
	if gotDst != "/dst/dir" {
		t.Errorf("MoveDirectory destinationPath = %q, want %q", gotDst, "/dst/dir")
	}
}

// ---------------------------------------------------------------------------
// TestReadOnlyBlocksCopyMoveDir — read-only guard fires before any client call.
// ---------------------------------------------------------------------------

// TestReadOnlyBlocksCopyMoveDir verifies that Copy, Move, and DirMove on a
// read-only Fs return fs.ErrorPermissionDenied and make zero client calls.
func TestReadOnlyBlocksCopyMoveDir(t *testing.T) {
	c := &fakeClient{}
	f := newTestFsWithRoot(t, c, "/", true) // read-only

	srcObj := &Object{
		fs:     f,
		path:   "/file.txt",
		remote: "file.txt",
		uuid:   "ro-uuid",
		size:   100,
	}

	// Copy on read-only.
	_, err := f.Copy(context.Background(), srcObj, "dst.txt")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Copy on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Move on read-only.
	_, err = f.Move(context.Background(), srcObj, "dst.txt")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Move on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// DirMove on read-only.
	err = f.DirMove(context.Background(), f, "src/dir", "dst/dir")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("DirMove on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// ALL mutating client calls must be 0 (guards fired before any RPC, BE-02).
	total := c.totalMutatingCalls()
	if total != 0 {
		t.Errorf("total mutating calls on read-only Fs for Copy/Move/DirMove = %d, want 0", total)
	}
}

// ---------------------------------------------------------------------------
// TestFeaturesAdvertisesCopyMoveDir — Features() includes the implemented ops.
// ---------------------------------------------------------------------------

// TestFeaturesAdvertisesCopyMoveDir verifies that Features() returns non-nil
// Copy, Move, and DirMove function pointers (they are wired now), and that
// PutStream is NOT advertised (design decision 1 — rclone spools unknown-size
// content and re-calls Put with a known size, so declared_size_bytes is always
// real; the backend needs no unknown-total upload path).
func TestFeaturesAdvertisesCopyMoveDir(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false)
	feats := f.Features()
	if feats == nil {
		t.Fatal("Features() returned nil")
	}
	if feats.Copy == nil {
		t.Error("Features().Copy is nil, want non-nil (Fs.Copy is implemented)")
	}
	if feats.Move == nil {
		t.Error("Features().Move is nil, want non-nil (Fs.Move is implemented)")
	}
	if feats.DirMove == nil {
		t.Error("Features().DirMove is nil, want non-nil (Fs.DirMove is implemented)")
	}
	if feats.PutStream != nil {
		t.Error("Features().PutStream is non-nil; PutStreamer must NOT be advertised (design decision 1)")
	}
}

// ---------------------------------------------------------------------------
// TestListDirectoryAllUnionPage — the double's ListDirectoryAll returns a union
// page (file arm + directory arm) keyed on `mtime` so the decoded mtime is
// non-zero and the assertion is not vacuous.
// ---------------------------------------------------------------------------

// TestListDirectoryAllUnionPage verifies that the consolidated double returns
// a []ListDirEntry union page with a file arm and a directory arm, that both
// arms decode a non-zero mtime from the `mtime` wire key, and that List
// correctly classifies each arm.
func TestListDirectoryAllUnionPage(t *testing.T) {
	c := &fakeClient{}
	wantFileMtime := "2026-06-01T12:00:00Z"
	wantDirMtime := "2026-05-15T08:00:00Z"

	c.listDirectoryAllResult = func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
		// Return one file arm and one directory arm — the pinned listDirectory
		// union (D6). Both use the `mtime` wire key as the tolerant struct
		// currently decodes (design decision 5 from 03-02).
		return []brokerrpc.ListDirEntry{
			{File: &brokerrpc.FilesystemFile{
				Path:  "/root/file.bin",
				Size:  2048,
				UUID:  "union-file-uuid",
				MIME:  "application/octet-stream",
				Mtime: wantFileMtime,
			}},
			{Directory: &brokerrpc.Directory{
				Path:  "/root/subdir",
				Mtime: wantDirMtime,
			}},
		}, nil
	}

	f := newTestFsWithRoot(t, c, "/", false)
	entries, err := f.List(context.Background(), "root")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2 (one file + one dir)", len(entries))
	}

	// First entry: file arm → *Object with non-zero mtime.
	obj, ok := entries[0].(*Object)
	if !ok {
		t.Fatalf("entries[0] is %T, want *Object", entries[0])
	}
	if obj.mtime.IsZero() {
		t.Error("file entry mtime is zero; the `mtime` wire key must decode to a non-zero time")
	}
	if obj.uuid != "union-file-uuid" {
		t.Errorf("file entry uuid = %q, want %q", obj.uuid, "union-file-uuid")
	}

	// Second entry: directory arm → fs.Directory with non-zero mtime.
	dir, ok := entries[1].(fs.Directory)
	if !ok {
		t.Fatalf("entries[1] is %T, want fs.Directory", entries[1])
	}
	if dir.ModTime(context.Background()).IsZero() {
		t.Error("directory entry mtime is zero; the `mtime` wire key must decode to a non-zero time")
	}
}

// ---------------------------------------------------------------------------
// TestPutKnownSizeNoUnknownTotal — Put with a real size calls Upload with a
// non-negative declared_size_bytes; the double must reject a negative size.
// ---------------------------------------------------------------------------

// TestPutKnownSizeRejectsNegative verifies that the double rejects a negative
// declared_size_bytes on Upload, proving the unknown-total path is not
// exercised (design decision 1, D5: declared_size_bytes is REQUIRED with a
// real size; a negative size could never succeed against a conforming broker).
func TestPutKnownSizeRejectsNegative(t *testing.T) {
	c := &fakeClient{}
	// Wire the Upload stub to reject a negative declared_size_bytes, simulating
	// broker rejection per D5 (size_exceeded / invalid_argument if -1 were sent).
	c.uploadResult = func(ctx context.Context, path string, src io.Reader, totalBytes int64) error {
		if totalBytes < 0 {
			return errors.New("Upload: negative declared_size_bytes is not permitted (D5)")
		}
		return nil
	}

	f := newTestFsWithRoot(t, c, "/", false)

	// Positive case: a real size must succeed.
	src := &fakeObjectInfo{remote: "good.txt", size: 42}
	_, err := f.Put(context.Background(), nil, src)
	// Upload is called with size=42; stub returns nil.
	if err != nil {
		t.Errorf("Put with positive size: %v", err)
	}

	// Note: rclone guarantees src.Size() >= 0 when calling Put, so a negative
	// size would be a rclone bug upstream. We verify the double catches it.
	// To exercise the double's guard, call Upload directly with -1.
	err = c.Upload(context.Background(), "/neg.txt", nil, -1)
	if err == nil {
		t.Error("Upload with negative declared_size_bytes should return an error (D5 guard)")
	}
}
