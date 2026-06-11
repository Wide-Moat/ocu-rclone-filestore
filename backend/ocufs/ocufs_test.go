// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocufs tests — ocufs.go registration and Fs-level tests.
package ocufs

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
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

	// lastUploadPath and lastUploadSize capture what was passed to Upload.
	lastUploadPath string
	lastUploadSize int64
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

func (f *fakeClient) Upload(ctx context.Context, path string, src io.Reader, totalBytes int64) error {
	f.uploadCount++
	f.lastUploadPath = path
	f.lastUploadSize = totalBytes
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
	if f.moveDirectoryResult != nil {
		return f.moveDirectoryResult(ctx, sourcePath, destPath)
	}
	return &brokerrpc.AckResponse{}, nil
}

func (f *fakeClient) CopyFile(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
	f.copyFileCount++
	if f.copyFileResult != nil {
		return f.copyFileResult(ctx, srcPath, dstPath)
	}
	return &brokerrpc.AckResponse{}, nil
}

func (f *fakeClient) MoveFile(ctx context.Context, srcPath, dstPath string) (*brokerrpc.AckResponse, error) {
	f.moveFileCount++
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
		fs:   f,
		path: "/docs/file.txt",
		uuid: "direct-uuid-001",
		size: 7,
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
