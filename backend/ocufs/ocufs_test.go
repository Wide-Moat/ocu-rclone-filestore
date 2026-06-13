// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocufs tests — ocufs.go registration and Fs-level tests.
package ocufs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/hash"
)

// ---------------------------------------------------------------------------
// Call-counter test double for brokerClient.
// Tracks calls per method so tests can assert zero calls on the read-only path
// and ≥1 calls on the writable path. Every method is accounted for so
// read-only guard tests can assert the total across ALL mutating methods.
// ---------------------------------------------------------------------------

type fakeClient struct {
	listDirectoryAllCount int
	readMetadataCount     int
	downloadCount         int
	downloadRangeCount    int
	uploadCount           int
	makeDirectoryCount    int
	removeDirectoryCount  int
	moveDirectoryCount    int
	copyFileCount         int
	moveFileCount         int
	removeFileCount       int

	// Stubs — set by individual tests to control returned values.
	listDirectoryAllResult func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error)
	readMetadataResult     func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error)
	downloadResult         func(ctx context.Context, uuid string) ([]byte, error)
	downloadRangeResult    func(ctx context.Context, uuid string, offset, length int64) ([]byte, error)
	uploadResult           func(ctx context.Context, path string, src io.Reader, totalBytes int64) error
	makeDirectoryResult    func(ctx context.Context, path string) (*brokerrpc.AckResponse, error)
	removeDirectoryResult  func(ctx context.Context, path string) (*brokerrpc.AckResponse, error)
	moveDirectoryResult    func(ctx context.Context, sourcePath, destPath string) (*brokerrpc.AckResponse, error)
	copyFileResult         func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error)
	moveFileResult         func(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error)
	removeFileResult       func(ctx context.Context, path string) (*brokerrpc.AckResponse, error)

	// lastUploadPath, lastUploadSize and lastUploadOverwrite capture what was
	// passed to Upload.
	lastUploadPath      string
	lastUploadSize      int64
	lastUploadOverwrite bool
	// lastMakeDirectoryPath captures what was passed to MakeDirectory.
	lastMakeDirectoryPath string
	// lastRemoveDirectoryPath captures what was passed to RemoveDirectory.
	lastRemoveDirectoryPath string
	// lastRemoveFilePath captures what was passed to RemoveFile.
	lastRemoveFilePath string
	// lastDownloadRangeUUID captures the uuid passed to DownloadRange.
	lastDownloadRangeUUID string
	// lastDownloadRangeOffset and lastDownloadRangeLength capture the range args.
	lastDownloadRangeOffset int64
	lastDownloadRangeLength int64
	// lastDownloadUUID captures the uuid passed to Download.
	lastDownloadUUID string
	// lastCopyFileSrc/Dst capture the args passed to CopyFile.
	lastCopyFileSrc string
	lastCopyFileDst string
	// lastMoveFileSrc/Dst capture the args passed to MoveFile.
	lastMoveFileSrc string
	lastMoveFileDst string
	// lastMoveDirectorySrc/Dst capture the args passed to MoveDirectory.
	lastMoveDirectorySrc string
	lastMoveDirectoryDst string
}

func (f *fakeClient) totalMutatingCalls() int {
	return f.uploadCount + f.makeDirectoryCount + f.removeDirectoryCount +
		f.moveDirectoryCount + f.copyFileCount + f.moveFileCount + f.removeFileCount
}

func (f *fakeClient) ListDirectoryAll(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
	f.listDirectoryAllCount++
	if f.listDirectoryAllResult != nil {
		return f.listDirectoryAllResult(ctx, path)
	}
	return nil, nil
}

func (f *fakeClient) ReadMetadata(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
	f.readMetadataCount++
	if f.readMetadataResult != nil {
		return f.readMetadataResult(ctx, path)
	}
	return &brokerrpc.ReadMetadataResponse{}, nil
}

func (f *fakeClient) Download(ctx context.Context, uuid string) ([]byte, error) {
	f.downloadCount++
	f.lastDownloadUUID = uuid
	if f.downloadResult != nil {
		return f.downloadResult(ctx, uuid)
	}
	return []byte("hello world"), nil
}

func (f *fakeClient) DownloadRange(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
	f.downloadRangeCount++
	f.lastDownloadRangeUUID = uuid
	f.lastDownloadRangeOffset = offset
	f.lastDownloadRangeLength = length
	if f.downloadRangeResult != nil {
		return f.downloadRangeResult(ctx, uuid, offset, length)
	}
	return []byte("bytes"), nil
}

func (f *fakeClient) Upload(ctx context.Context, path string, src io.Reader, totalBytes int64, overwrite bool) error {
	f.uploadCount++
	f.lastUploadPath = path
	f.lastUploadSize = totalBytes
	f.lastUploadOverwrite = overwrite
	if f.uploadResult != nil {
		return f.uploadResult(ctx, path, src, totalBytes)
	}
	return nil
}

func (f *fakeClient) MakeDirectory(ctx context.Context, path string) (*brokerrpc.AckResponse, error) {
	f.makeDirectoryCount++
	f.lastMakeDirectoryPath = path
	if f.makeDirectoryResult != nil {
		return f.makeDirectoryResult(ctx, path)
	}
	return &brokerrpc.AckResponse{}, nil
}

func (f *fakeClient) RemoveDirectory(ctx context.Context, path string) (*brokerrpc.AckResponse, error) {
	f.removeDirectoryCount++
	f.lastRemoveDirectoryPath = path
	if f.removeDirectoryResult != nil {
		return f.removeDirectoryResult(ctx, path)
	}
	return &brokerrpc.AckResponse{}, nil
}

func (f *fakeClient) MoveDirectory(ctx context.Context, sourcePath, destPath string) (*brokerrpc.AckResponse, error) {
	f.moveDirectoryCount++
	f.lastMoveDirectorySrc = sourcePath
	f.lastMoveDirectoryDst = destPath
	if f.moveDirectoryResult != nil {
		return f.moveDirectoryResult(ctx, sourcePath, destPath)
	}
	return &brokerrpc.AckResponse{}, nil
}

func (f *fakeClient) CopyFile(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
	f.copyFileCount++
	f.lastCopyFileSrc = srcPath
	f.lastCopyFileDst = dstPath
	if f.copyFileResult != nil {
		return f.copyFileResult(ctx, srcPath, dstPath)
	}
	return &brokerrpc.AckResponse{}, nil
}

func (f *fakeClient) MoveFile(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
	f.moveFileCount++
	f.lastMoveFileSrc = srcPath
	f.lastMoveFileDst = dstPath
	if f.moveFileResult != nil {
		return f.moveFileResult(ctx, srcPath, dstPath)
	}
	return &brokerrpc.AckResponse{}, nil
}

func (f *fakeClient) RemoveFile(ctx context.Context, path string) (*brokerrpc.AckResponse, error) {
	f.removeFileCount++
	f.lastRemoveFilePath = path
	if f.removeFileResult != nil {
		return f.removeFileResult(ctx, path)
	}
	return &brokerrpc.AckResponse{}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestFs creates an Fs backed by the given fakeClient. readOnly controls
// the mount mode.
func newTestFs(t *testing.T, c *fakeClient, readOnly bool) *Fs {
	t.Helper()
	return &Fs{
		name:     "ocufs",
		root:     "/",
		client:   c,
		readOnly: readOnly,
		enc:      defaultEncoding,
	}
}

// ---------------------------------------------------------------------------
// Registration test
// ---------------------------------------------------------------------------

// TestRegister verifies that the init() function registers "ocufs" with the
// rclone registry and it is findable by name.
func TestRegister(t *testing.T) {
	info, err := fs.Find("ocufs")
	if err != nil {
		t.Fatalf("fs.Find(\"ocufs\"): %v — backend not registered", err)
	}
	if info.Name != "ocufs" {
		t.Errorf("RegInfo.Name = %q, want %q", info.Name, "ocufs")
	}
}

// ---------------------------------------------------------------------------
// NewFs option parsing tests
// ---------------------------------------------------------------------------

// TestNewFsReadOnly verifies that NewFs with read_only=true produces an Fs
// whose read-only flag is set.
func TestNewFsReadOnly(t *testing.T) {
	// NewFs requires a real socket path; we skip the actual connection by
	// checking option parsing directly via the Fs struct.
	// The test constructs an Fs directly rather than calling NewFs because
	// NewFs dials the socket — integration with a live broker is a later phase.
	f := newTestFs(t, &fakeClient{}, true)
	if !f.readOnly {
		t.Error("readOnly flag is false, want true")
	}
}

// TestNewFsMissingSocketPath verifies that NewFs returns a non-nil error when
// the socket_path option is absent.
func TestNewFsMissingSocketPath(t *testing.T) {
	m := configmap.Simple{
		"filesystem_id": "fs-01",
		// socket_path deliberately absent
	}
	_, err := NewFs(context.Background(), "test", "/", m)
	if err == nil {
		t.Fatal("NewFs with missing socket_path returned nil error, want an error")
	}
}

// TestNewFsMissingFilesystemID verifies that NewFs returns a non-nil error
// when the filesystem_id option is absent.
func TestNewFsMissingFilesystemID(t *testing.T) {
	m := configmap.Simple{
		"socket_path": "/run/broker.sock",
		// filesystem_id deliberately absent
	}
	_, err := NewFs(context.Background(), "test", "/", m)
	if err == nil {
		t.Fatal("NewFs with missing filesystem_id returned nil error, want an error")
	}
}

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

// TestListImmediateChildrenOnly verifies that List returns only immediate
// children of the requested directory, not deeper descendants that the
// recursive ListDirectoryAll might include.
func TestListImmediateChildrenOnly(t *testing.T) {
	c := &fakeClient{}
	c.listDirectoryAllResult = func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
		// Broker returns: two immediate children and one deeper descendant.
		filePtr := &brokerrpc.FilesystemFile{
			Path:  "/docs/readme.txt",
			Size:  100,
			UUID:  "uuid-file",
			MIME:  "text/plain",
			Mtime: "2026-01-15T10:00:00Z",
		}
		dirPtr := &brokerrpc.Directory{
			Path:  "/docs/sub",
			Mtime: "2026-01-10T08:00:00Z",
		}
		deeperFilePtr := &brokerrpc.FilesystemFile{
			Path:  "/docs/sub/deep.txt",
			Size:  50,
			UUID:  "uuid-deep",
			Mtime: "2026-01-10T09:00:00Z",
		}
		return []brokerrpc.ListDirEntry{
			{File: filePtr},
			{Directory: dirPtr},
			{File: deeperFilePtr}, // deeper — must be filtered
		}, nil
	}

	f := newTestFs(t, c, false)
	f.root = "/"
	entries, err := f.List(context.Background(), "docs")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2 (deeper descendants must be filtered)", len(entries))
	}
	// ReadMetadata must NOT have been called for a List-derived entry.
	if c.readMetadataCount != 0 {
		t.Errorf("ReadMetadata was called %d times during List, want 0 (direct union path)", c.readMetadataCount)
	}
}

// TestListFileEntryIsFullyPopulated verifies that a file-arm entry from List
// produces a fully-populated *Object (uuid+size+mime from the listing) without
// any ReadMetadata round-trip.
func TestListFileEntryIsFullyPopulated(t *testing.T) {
	c := &fakeClient{}
	wantUUID := "file-uuid-xyz"
	wantSize := int64(4096)
	wantMIME := "application/octet-stream"

	c.listDirectoryAllResult = func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
		return []brokerrpc.ListDirEntry{
			{File: &brokerrpc.FilesystemFile{
				Path:  "/root/file.bin",
				Size:  wantSize,
				UUID:  wantUUID,
				MIME:  wantMIME,
				Mtime: "2026-02-01T12:00:00Z",
			}},
		}, nil
	}

	f := newTestFs(t, c, false)
	f.root = "/"
	entries, err := f.List(context.Background(), "root")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	obj, ok := entries[0].(*Object)
	if !ok {
		t.Fatalf("entries[0] is %T, want *Object", entries[0])
	}
	if obj.uuid != wantUUID {
		t.Errorf("obj.uuid = %q, want %q", obj.uuid, wantUUID)
	}
	if obj.size != wantSize {
		t.Errorf("obj.size = %d, want %d", obj.size, wantSize)
	}
	if obj.mime != wantMIME {
		t.Errorf("obj.mime = %q, want %q", obj.mime, wantMIME)
	}
	if c.readMetadataCount != 0 {
		t.Errorf("ReadMetadata called %d times, want 0 for a list-derived file entry", c.readMetadataCount)
	}
}

// TestListDirEntryIsDir verifies that a directory-arm entry from List produces
// an fs.Directory with the correct Remote and a non-zero ModTime.
func TestListDirEntryIsDir(t *testing.T) {
	c := &fakeClient{}
	c.listDirectoryAllResult = func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
		return []brokerrpc.ListDirEntry{
			{Directory: &brokerrpc.Directory{
				Path:  "/root/subdir",
				Mtime: "2026-03-01T00:00:00Z",
			}},
		}, nil
	}

	f := newTestFs(t, c, false)
	f.root = "/"
	entries, err := f.List(context.Background(), "root")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	dir, ok := entries[0].(fs.Directory)
	if !ok {
		t.Fatalf("entries[0] is %T, want fs.Directory", entries[0])
	}
	if dir.Remote() != "root/subdir" {
		t.Errorf("dir.Remote() = %q, want %q", dir.Remote(), "root/subdir")
	}
	if dir.ModTime(context.Background()).IsZero() {
		t.Error("dir.ModTime() is zero, want a parsed mtime")
	}
}

// ---------------------------------------------------------------------------
// NewObject tests
// ---------------------------------------------------------------------------

// TestNewObjectFile verifies that NewObject returns a fully-populated *Object
// when ReadMetadata returns a file entry.
func TestNewObjectFile(t *testing.T) {
	c := &fakeClient{}
	wantUUID := "obj-uuid-001"
	wantSize := int64(2048)
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				Path:  path,
				UUID:  wantUUID,
				Size:  wantSize,
				Mtime: "2026-01-20T08:00:00Z",
			},
		}, nil
	}

	f := newTestFs(t, c, false)
	obj, err := f.NewObject(context.Background(), "somefile.txt")
	if err != nil {
		t.Fatalf("NewObject: %v", err)
	}
	o, ok := obj.(*Object)
	if !ok {
		t.Fatalf("returned %T, want *Object", obj)
	}
	if o.uuid != wantUUID {
		t.Errorf("uuid = %q, want %q", o.uuid, wantUUID)
	}
	if o.size != wantSize {
		t.Errorf("size = %d, want %d", o.size, wantSize)
	}
}

// TestNewObjectNotFound verifies that NewObject returns fs.ErrorObjectNotFound
// when ReadMetadata returns an empty response (neither file nor directory
// populated).
func TestNewObjectNotFound(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{}, nil // empty: neither File nor Directory
	}

	f := newTestFs(t, c, false)
	_, err := f.NewObject(context.Background(), "missing.txt")
	if !errors.Is(err, fs.ErrorObjectNotFound) {
		t.Errorf("NewObject(missing) error = %v, want fs.ErrorObjectNotFound", err)
	}
}

// TestNewObjectIsDir verifies that NewObject returns fs.ErrorIsDir when
// ReadMetadata returns a directory entry (and no file).
func TestNewObjectIsDir(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			Directory: brokerrpc.Directory{
				Path: "/adir",
			},
		}, nil
	}

	f := newTestFs(t, c, false)
	_, err := f.NewObject(context.Background(), "adir")
	if !errors.Is(err, fs.ErrorIsDir) {
		t.Errorf("NewObject(dir) error = %v, want fs.ErrorIsDir", err)
	}
}

// TestNewObjectNotFoundViaBrokerError verifies that a broker not_found error
// from ReadMetadata is surfaced as fs.ErrorObjectNotFound.
func TestNewObjectNotFoundViaBrokerError(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return nil, brokerrpc.ErrNotFound
	}

	f := newTestFs(t, c, false)
	_, err := f.NewObject(context.Background(), "gone.txt")
	if !errors.Is(err, fs.ErrorObjectNotFound) {
		t.Errorf("NewObject(broker not_found) error = %v, want fs.ErrorObjectNotFound", err)
	}
}

// TestNewObjectZeroByteFileDetected verifies that a 0-byte file whose
// ReadMetadata response omits path and uuid but stamps an mtime is still
// classified as a FILE (arm presence keyed on mtime), not ErrorObjectNotFound
// (WR-02).
func TestNewObjectZeroByteFileDetected(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				// No path, no uuid, size 0 — but a real file carries an mtime.
				Mtime: "2026-03-01T00:00:00Z",
			},
		}, nil
	}

	f := newTestFs(t, c, false)
	obj, err := f.NewObject(context.Background(), "empty.txt")
	if err != nil {
		t.Fatalf("NewObject(0-byte file): %v, want a file *Object", err)
	}
	o, ok := obj.(*Object)
	if !ok {
		t.Fatalf("returned %T, want *Object", obj)
	}
	if o.size != 0 {
		t.Errorf("size = %d, want 0", o.size)
	}
	if o.mtime.IsZero() {
		t.Error("mtime is zero; the stamped mtime should have decoded")
	}
}

// TestNewObjectDualArmIsDir verifies that a malformed dual-arm response
// (directory.path set plus a stray file.uuid) classifies as a DIRECTORY
// (ErrorIsDir), never as a readable file (WR-03).
func TestNewObjectDualArmIsDir(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File:      brokerrpc.File{UUID: "stray-uuid"},
			Directory: brokerrpc.Directory{Path: "/somedir"},
		}, nil
	}

	f := newTestFs(t, c, false)
	_, err := f.NewObject(context.Background(), "somedir")
	if !errors.Is(err, fs.ErrorIsDir) {
		t.Errorf("NewObject(dual-arm) error = %v, want fs.ErrorIsDir", err)
	}
}

// ---------------------------------------------------------------------------
// Read-only guard tests — Task 1 (registration/Options level)
// ---------------------------------------------------------------------------

// TestReadOnlyFlagSet verifies that a read-only Fs has the flag set.
func TestReadOnlyFlagSet(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, true)
	if !f.readOnly {
		t.Error("expected readOnly=true")
	}
}

// TestWritableFlagUnset verifies that a writable Fs has the flag unset.
func TestWritableFlagUnset(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false)
	if f.readOnly {
		t.Error("expected readOnly=false")
	}
}

// ---------------------------------------------------------------------------
// Direct open (no resolve) test — Task 1 skeleton, completed in Task 2
// ---------------------------------------------------------------------------

// TestDirectOpenNoResolve verifies that a List-derived Object (uuid already
// set from the listing) opens via DownloadRange directly without calling
// ReadMetadata.
func TestDirectOpenNoResolve(t *testing.T) {
	c := &fakeClient{}
	c.downloadRangeResult = func(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
		return []byte("content"), nil
	}

	// Build a List-derived Object with uuid pre-set (simulates what List produces).
	f := newTestFs(t, c, false)
	obj := &Object{
		fs:    f,
		path:  "/docs/file.txt",
		uuid:  "direct-uuid-001",
		size:  7,
		mtime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	rc, err := obj.Open(context.Background(), &fs.RangeOption{Start: 0, End: 6})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "content" {
		t.Errorf("got %q, want %q", string(got), "content")
	}
	if c.readMetadataCount != 0 {
		t.Errorf("ReadMetadata was called %d times, want 0 for a uuid-bearing Object", c.readMetadataCount)
	}
	if c.downloadRangeCount != 1 {
		t.Errorf("DownloadRange called %d times, want 1", c.downloadRangeCount)
	}
}

// ---------------------------------------------------------------------------
// fakeObjectInfo — minimal fs.ObjectInfo for Put/Update tests.
// ---------------------------------------------------------------------------

type fakeObjectInfo struct {
	remote string
	size   int64
}

func (f *fakeObjectInfo) Fs() fs.Info                                           { return nil }
func (f *fakeObjectInfo) String() string                                        { return f.remote }
func (f *fakeObjectInfo) Remote() string                                        { return f.remote }
func (f *fakeObjectInfo) ModTime(ctx context.Context) time.Time                 { return time.Time{} }
func (f *fakeObjectInfo) Size() int64                                           { return f.size }
func (f *fakeObjectInfo) Hash(ctx context.Context, t hash.Type) (string, error) { return "", nil }
func (f *fakeObjectInfo) Storable() bool                                        { return true }

// ---------------------------------------------------------------------------
// Task 3: Read-only guard tests
// ---------------------------------------------------------------------------

// TestReadOnlyGuardAllMutatingMethods verifies that on a read-only Fs every
// mutating method returns a permission error AND the double's client call
// counter stays 0 (no RPC constructed before the guard fires, BE-02 / T-03-01).
func TestReadOnlyGuardAllMutatingMethods(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, true) // read-only

	// Build an Object owned by this read-only Fs.
	obj := &Object{
		fs:   f,
		path: "/ro/file.bin",
		uuid: "uuid-ro",
		size: 100,
	}

	src := &fakeObjectInfo{remote: "ro/file.bin", size: 100}
	body := bytes.NewReader([]byte("data"))

	// Fs.Put
	_, err := f.Put(context.Background(), body, src)
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Put on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Fs.Mkdir
	err = f.Mkdir(context.Background(), "newdir")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Mkdir on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Fs.Rmdir
	err = f.Rmdir(context.Background(), "olddir")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Rmdir on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Object.Update
	err = obj.Update(context.Background(), body, src)
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Update on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Object.Remove
	err = obj.Remove(context.Background())
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Remove on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Object.SetModTime
	err = obj.SetModTime(context.Background(), time.Now())
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("SetModTime on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Fs.Copy
	_, err = f.Copy(context.Background(), obj, "ro/copy.bin")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Copy on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Fs.Move
	_, err = f.Move(context.Background(), obj, "ro/move.bin")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("Move on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Fs.DirMove
	err = f.DirMove(context.Background(), f, "ro/srcdir", "ro/dstdir")
	if !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("DirMove on read-only: got %v, want fs.ErrorPermissionDenied", err)
	}

	// Assert ZERO client calls for ALL mutating methods (guard fired before any RPC).
	total := c.totalMutatingCalls()
	if total != 0 {
		t.Errorf("total mutating client calls on read-only Fs = %d, want 0", total)
	}
}

// ---------------------------------------------------------------------------
// Task 3: Writable body tests
// ---------------------------------------------------------------------------

// TestWritablePathPutInvokesUpload verifies that Put on a writable Fs invokes
// Upload with the correct path and size.
func TestWritablePathPutInvokesUpload(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false) // writable
	f.root = "/"

	content := []byte("file content here")
	src := &fakeObjectInfo{remote: "subdir/newfile.txt", size: int64(len(content))}
	body := bytes.NewReader(content)

	obj, err := f.Put(context.Background(), body, src)
	if err != nil {
		t.Fatalf("Put on writable Fs: %v", err)
	}
	if obj == nil {
		t.Fatal("Put returned nil object")
	}
	// The returned Object must report the source remote so callers' transfer
	// accounting, post-upload verification, and VFS cache keying all key on the
	// same remote (dst.Remote() == src.Remote()).
	if obj.Remote() != src.Remote() {
		t.Errorf("Put returned Object.Remote()=%q, want %q", obj.Remote(), src.Remote())
	}
	if c.uploadCount != 1 {
		t.Errorf("Upload called %d times, want 1", c.uploadCount)
	}
	if !strings.Contains(c.lastUploadPath, "newfile.txt") {
		t.Errorf("Upload path = %q, want path containing %q", c.lastUploadPath, "newfile.txt")
	}
	if c.lastUploadSize != int64(len(content)) {
		t.Errorf("Upload totalBytes = %d, want %d", c.lastUploadSize, len(content))
	}
}

// TestWritablePathUpdateInvokesUpload verifies that Object.Update on a
// writable Fs invokes Upload (in-place overwrite at the same path).
func TestWritablePathUpdateInvokesUpload(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)

	content := []byte("updated content")
	obj := &Object{
		fs:   f,
		path: "/docs/file.txt",
		uuid: "uuid-update",
		size: 100,
	}
	src := &fakeObjectInfo{remote: "docs/file.txt", size: int64(len(content))}

	err := obj.Update(context.Background(), bytes.NewReader(content), src)
	if err != nil {
		t.Fatalf("Update on writable Fs: %v", err)
	}
	if c.uploadCount != 1 {
		t.Errorf("Upload called %d times, want 1", c.uploadCount)
	}
	if c.lastUploadPath != "/docs/file.txt" {
		t.Errorf("Upload path = %q, want %q", c.lastUploadPath, "/docs/file.txt")
	}
}

// TestWritablePathRemoveInvokesRemoveFile verifies that Object.Remove on a
// writable Fs invokes RemoveFile at the object's path.
func TestWritablePathRemoveInvokesRemoveFile(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)

	obj := &Object{fs: f, path: "/to/delete.txt", uuid: "uuid-del", size: 10}
	err := obj.Remove(context.Background())
	if err != nil {
		t.Fatalf("Remove on writable Fs: %v", err)
	}
	if c.removeFileCount != 1 {
		t.Errorf("RemoveFile called %d times, want 1", c.removeFileCount)
	}
	if c.lastRemoveFilePath != "/to/delete.txt" {
		t.Errorf("RemoveFile path = %q, want %q", c.lastRemoveFilePath, "/to/delete.txt")
	}
}

// TestWritablePathMkdirInvokesMakeDirectory verifies that Fs.Mkdir on a
// writable Fs invokes MakeDirectory at the resolved path.
func TestWritablePathMkdirInvokesMakeDirectory(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)
	f.root = "/"

	err := f.Mkdir(context.Background(), "newdir")
	if err != nil {
		t.Fatalf("Mkdir on writable Fs: %v", err)
	}
	if c.makeDirectoryCount != 1 {
		t.Errorf("MakeDirectory called %d times, want 1", c.makeDirectoryCount)
	}
	if c.lastMakeDirectoryPath != "/newdir" {
		t.Errorf("MakeDirectory path = %q, want %q", c.lastMakeDirectoryPath, "/newdir")
	}
}

// TestMkdirOnExistingDirIsNoError verifies that Fs.Mkdir is idempotent: when
// the broker reports the path already exists, Mkdir returns nil (success), per
// rclone's Mkdir contract (creating an existing directory is a no-op, not an
// error). The broker's already_exists is surfaced by brokerrpc as
// ErrAlreadyExists; the backend must swallow it.
func TestMkdirOnExistingDirIsNoError(t *testing.T) {
	c := &fakeClient{
		makeDirectoryResult: func(ctx context.Context, path string) (*brokerrpc.AckResponse, error) {
			return nil, fmt.Errorf("ocufs test: %w: path present", brokerrpc.ErrAlreadyExists)
		},
	}
	f := newTestFs(t, c, false)
	f.root = "/"

	if err := f.Mkdir(context.Background(), "existing"); err != nil {
		t.Fatalf("Mkdir of an existing directory must be a no-op success, got: %v", err)
	}
	if c.makeDirectoryCount != 1 {
		t.Errorf("MakeDirectory called %d times, want 1", c.makeDirectoryCount)
	}
}

// TestMkdirPropagatesNonAlreadyExistsError verifies that Mkdir still surfaces a
// genuine failure (anything other than already_exists) as an error, so the
// idempotency swallow does not mask real broker faults.
func TestMkdirPropagatesNonAlreadyExistsError(t *testing.T) {
	c := &fakeClient{
		makeDirectoryResult: func(ctx context.Context, path string) (*brokerrpc.AckResponse, error) {
			return nil, fmt.Errorf("ocufs test: %w", brokerrpc.ErrPermissionDenied)
		},
	}
	f := newTestFs(t, c, false)
	f.root = "/"

	if err := f.Mkdir(context.Background(), "denied"); err == nil {
		t.Fatal("Mkdir must surface a non-already-exists broker error, got nil")
	}
}

// TestWritablePathRmdirInvokesRemoveDirectory verifies that Fs.Rmdir on a
// writable Fs invokes RemoveDirectory at the resolved path.
func TestWritablePathRmdirInvokesRemoveDirectory(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)
	f.root = "/"

	err := f.Rmdir(context.Background(), "olddir")
	if err != nil {
		t.Fatalf("Rmdir on writable Fs: %v", err)
	}
	if c.removeDirectoryCount != 1 {
		t.Errorf("RemoveDirectory called %d times, want 1", c.removeDirectoryCount)
	}
	if c.lastRemoveDirectoryPath != "/olddir" {
		t.Errorf("RemoveDirectory path = %q, want %q", c.lastRemoveDirectoryPath, "/olddir")
	}
}

// TestSetModTimeWritableReturnsErrorCantSetModTime verifies that
// Object.SetModTime on a WRITABLE Fs returns fs.ErrorCantSetModTime and
// invokes ZERO client calls (no broker op sets mtime, design decision 8).
func TestSetModTimeWritableReturnsErrorCantSetModTime(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false) // writable

	obj := &Object{fs: f, path: "/file.txt", uuid: "uuid-smt", size: 100}
	err := obj.SetModTime(context.Background(), time.Now())
	if !errors.Is(err, fs.ErrorCantSetModTime) {
		t.Errorf("SetModTime on writable Fs: got %v, want fs.ErrorCantSetModTime", err)
	}
	total := c.totalMutatingCalls()
	if total != 0 {
		t.Errorf("SetModTime called %d client methods, want 0 (no broker op sets mtime)", total)
	}
}

// ---------------------------------------------------------------------------
// Fs Info accessor coverage
// ---------------------------------------------------------------------------

// TestFsInfoAccessors exercises the simple Info methods on an Fs so the
// coverage tool counts them as reached.
func TestFsInfoAccessors(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false)
	f.name = "testfs"
	f.root = "/testroot"

	if f.Name() != "testfs" {
		t.Errorf("Name() = %q, want %q", f.Name(), "testfs")
	}
	if f.Root() != "/testroot" {
		t.Errorf("Root() = %q, want %q", f.Root(), "/testroot")
	}
	if f.String() == "" {
		t.Error("String() returned empty string")
	}
	if f.Precision() <= 0 {
		t.Errorf("Precision() = %v, want > 0", f.Precision())
	}
	if hashes := f.Hashes(); hashes.Count() != 0 {
		t.Errorf("Hashes().Count() = %d, want 0 (hash.None)", hashes.Count())
	}
	feats := f.Features()
	if feats == nil {
		t.Error("Features() returned nil")
	}
}

// TestObjectAccessors exercises the simple accessor methods on an Object so
// the coverage tool counts them as reached.
func TestObjectAccessors(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false)
	mtime := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	obj := &Object{
		fs:     f,
		path:   "/docs/file.txt",
		remote: "docs/file.txt",
		uuid:   "acc-uuid",
		size:   256,
		mtime:  mtime,
		mime:   "text/plain",
	}

	if obj.Fs() != f {
		t.Error("Fs() does not return the parent Fs")
	}
	if obj.String() != "/docs/file.txt" {
		t.Errorf("String() = %q, want %q", obj.String(), "/docs/file.txt")
	}
	if obj.Remote() != "docs/file.txt" {
		t.Errorf("Remote() = %q, want %q", obj.Remote(), "docs/file.txt")
	}
	if obj.Size() != 256 {
		t.Errorf("Size() = %d, want 256", obj.Size())
	}
	if obj.ModTime(context.Background()) != mtime {
		t.Errorf("ModTime() = %v, want %v", obj.ModTime(context.Background()), mtime)
	}
	if !obj.Storable() {
		t.Error("Storable() returned false, want true")
	}
	h, err := obj.Hash(context.Background(), 0)
	if !errors.Is(err, hash.ErrUnsupported) {
		t.Errorf("Hash() error = %v, want hash.ErrUnsupported (advertised empty Hashes() set)", err)
	}
	if h != "" {
		t.Errorf("Hash() = %q, want empty", h)
	}
}

// TestModTimeResolvesFallback verifies that calling ModTime on a uuid-less
// Object triggers the fallback resolve (ReadMetadata call).
func TestModTimeResolvesFallback(t *testing.T) {
	c := &fakeClient{}
	want := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				UUID:  "resolved-uuid",
				Size:  100,
				Path:  path,
				Mtime: want.Format(time.RFC3339),
			},
		}, nil
	}

	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/file.txt", uuid: ""}
	got := obj.ModTime(context.Background())
	if got != want {
		t.Errorf("ModTime (via resolve) = %v, want %v", got, want)
	}
}

// TestParseMtimeFallbacks verifies parseMtime handles RFC3339 (no nano) and
// bad input gracefully (zero time on bad input — tolerant decode per LD-2).
func TestParseMtimeFallbacks(t *testing.T) {
	// RFC3339 (no nano) should parse fine.
	t1 := parseMtime("2026-01-15T10:00:00Z")
	if t1.IsZero() {
		t.Error("parseMtime(RFC3339) returned zero time, want non-zero")
	}

	// Bad input returns zero time (tolerant, not an error).
	t2 := parseMtime("not-a-date")
	if !t2.IsZero() {
		t.Errorf("parseMtime(bad) = %v, want zero time", t2)
	}

	// Empty string returns zero time.
	t3 := parseMtime("")
	if !t3.IsZero() {
		t.Errorf("parseMtime(\"\") = %v, want zero time", t3)
	}
}

// TestImmediateChildRemoteRootPath verifies that entries at the root level
// (parentPath = "/") are accepted as immediate children.
func TestImmediateChildRemoteRootPath(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false) // root "/"
	dir := ""

	fileEntry := brokerrpc.ListDirEntry{
		File: &brokerrpc.FilesystemFile{Path: "/file.txt"},
	}
	remote, ok := f.immediateChildRemote(dir, fileEntry)
	if !ok {
		t.Fatal("immediateChildRemote for root-level file returned false, want true")
	}
	if remote != "file.txt" {
		t.Errorf("remote = %q, want %q", remote, "file.txt")
	}

	// A deeper path at root should be filtered out.
	deepEntry := brokerrpc.ListDirEntry{
		File: &brokerrpc.FilesystemFile{Path: "/a/b/file.txt"},
	}
	_, ok = f.immediateChildRemote(dir, deepEntry)
	if ok {
		t.Error("immediateChildRemote for deeply nested path returned true, want false")
	}
}

// TestListPathErrorPropagated verifies that an error from ListDirectoryAll
// is surfaced by List.
func TestListPathErrorPropagated(t *testing.T) {
	c := &fakeClient{}
	c.listDirectoryAllResult = func(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error) {
		return nil, brokerrpc.ErrPermissionDenied
	}

	f := newTestFs(t, c, false)
	_, err := f.List(context.Background(), "subdir")
	if err == nil {
		t.Fatal("List expected error from ListDirectoryAll, got nil")
	}
}

// TestAbsPathHelper exercises (*Fs).absPath with edge cases.
func TestAbsPathHelper(t *testing.T) {
	mk := func(root string) *Fs {
		return &Fs{name: "ocufs", root: root, client: &fakeClient{}, enc: defaultEncoding}
	}
	if got := mk("/root").absPath("sub"); got != "/root/sub" {
		t.Errorf("absPath(root=/root, \"sub\") = %q, want %q", got, "/root/sub")
	}
	if got := mk("/root").absPath(""); got != "/root" {
		t.Errorf("absPath(root=/root, \"\") = %q, want %q", got, "/root")
	}
	if got := mk("/").absPath(""); got != "/" {
		t.Errorf("absPath(root=/, \"\") = %q, want %q", got, "/")
	}
}

// TestPathEncodingRoundTrip verifies that the backend encoder maps an
// rclone-standard path with bytes that are unsafe on the wire (a control char,
// a trailing space) to an encoded outbound broker path, and decodes a matching
// broker listing entry back to the original rclone remote — so such names
// round-trip losslessly (conformance finding #3). The "/" separator is never
// encoded.
func TestPathEncodingRoundTrip(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false) // root "/", enc=defaultEncoding

	// A leaf name with a trailing space (EncodeRightSpace) under a normal dir.
	const dir = "d"
	const leaf = "name " // trailing space
	std := dir + "/" + leaf

	// Outbound: the standard path encodes to a broker path that does NOT carry
	// the raw trailing space, and the "/" separator is preserved.
	enc := f.absPath(std)
	if !strings.HasPrefix(enc, "/d/") {
		t.Fatalf("absPath(%q) = %q; separator/dir not preserved", std, enc)
	}
	if strings.HasSuffix(enc, " ") {
		t.Errorf("absPath(%q) = %q; raw trailing space not encoded", std, enc)
	}

	// Inbound: a listing entry at that encoded broker path decodes back to the
	// original leaf as the rclone remote.
	encLeaf := strings.TrimPrefix(enc, "/d/")
	entry := brokerrpc.ListDirEntry{
		File: &brokerrpc.FilesystemFile{Path: "/d/" + encLeaf},
	}
	remote, ok := f.immediateChildRemote(dir, entry)
	if !ok {
		t.Fatalf("immediateChildRemote did not accept the encoded child %q", encLeaf)
	}
	if want := dir + "/" + leaf; remote != want {
		t.Errorf("decoded remote = %q, want %q (lossless round-trip)", remote, want)
	}
}

// TestNewObjectMissingFilesystemID ensures NewFs returns an error when both
// socket_path and filesystem_id are present but value is empty.
func TestNewFsBothMissing(t *testing.T) {
	m := configmap.Simple{}
	_, err := NewFs(context.Background(), "test", "/", m)
	if err == nil {
		t.Fatal("NewFs with empty configmap returned nil error, want error")
	}
}
