// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocufs tests — object.go Open range/seek table, fallback resolve.
package ocufs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
)

// ---------------------------------------------------------------------------
// Open range + seek table (design decision 3, pinned in object_test.go)
// ---------------------------------------------------------------------------

// openCallRecord records the exact (uuid, offset, length) passed to the fake.
type openCallRecord struct {
	uuid   string
	offset int64
	length int64
	full   bool // true = Download called instead of DownloadRange
}

// fakeOpenClient is a minimal brokerClient that only implements the download
// methods, for the Open range/seek table tests.
type fakeOpenClient struct {
	fakeClient
	calls []openCallRecord
}

func (f *fakeOpenClient) DownloadRange(ctx context.Context, uuid string, offset, length int64) (io.ReadCloser, error) {
	f.calls = append(f.calls, openCallRecord{uuid: uuid, offset: offset, length: length})
	// Return a reader of the expected length so the test can verify byte count.
	return io.NopCloser(bytes.NewReader(make([]byte, length))), nil
}

func (f *fakeOpenClient) Download(ctx context.Context, uuid string) (io.ReadCloser, error) {
	f.calls = append(f.calls, openCallRecord{uuid: uuid, full: true})
	return io.NopCloser(bytes.NewReader(make([]byte, 1000))), nil
}

// objectWithSize is a helper that builds a List-derived Object with a known
// size and uuid (no resolve needed).
func objectWithSize(t *testing.T, size int64) (*Object, *fakeOpenClient) {
	t.Helper()
	c := &fakeOpenClient{}
	f := &Fs{name: "ocufs", root: "/", client: c, readOnly: false}
	obj := &Object{
		fs:    f,
		path:  "/test/file.bin",
		uuid:  "test-uuid-range",
		size:  size,
		mtime: time.Now(),
	}
	return obj, c
}

// TestOpenRangeTable exercises the full range/seek option table for an
// object of size 1000. The inclusive-End off-by-one and the SeekOption case
// are pinned explicitly (design decision 3).
func TestOpenRangeTable(t *testing.T) {
	const size = int64(1000)

	tests := []struct {
		name         string
		opt          fs.OpenOption
		wantOffset   int64
		wantLength   int64
		wantFullRead bool
	}{
		{
			name:       "RangeOption first 100 bytes inclusive-End off-by-one",
			opt:        &fs.RangeOption{Start: 0, End: 99},
			wantOffset: 0,
			wantLength: 100, // End-Start+1 = 100
		},
		{
			name:       "RangeOption second 100 bytes",
			opt:        &fs.RangeOption{Start: 100, End: 199},
			wantOffset: 100,
			wantLength: 100,
		},
		{
			name:       "RangeOption from 100 to end (End=-1)",
			opt:        &fs.RangeOption{Start: 100, End: -1},
			wantOffset: 100,
			wantLength: 900, // size - offset = 1000 - 100
		},
		{
			name:       "RangeOption last 100 bytes (Start=-1, End=100)",
			opt:        &fs.RangeOption{Start: -1, End: 100},
			wantOffset: 900, // size - End = 1000 - 100
			wantLength: 100,
		},
		{
			name:       "SeekOption from 100",
			opt:        &fs.SeekOption{Offset: 100},
			wantOffset: 100,
			wantLength: 900, // size - offset = 1000 - 100
		},
		{
			name:         "No option — full read",
			opt:          nil,
			wantFullRead: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obj, c := objectWithSize(t, size)

			var opts []fs.OpenOption
			if tc.opt != nil {
				opts = append(opts, tc.opt)
			}

			rc, err := obj.Open(context.Background(), opts...)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			_ = rc.Close()

			if len(c.calls) != 1 {
				t.Fatalf("expected 1 download call, got %d", len(c.calls))
			}
			call := c.calls[0]
			if tc.wantFullRead {
				if !call.full {
					t.Errorf("expected full Download call, got ranged call (offset=%d length=%d)", call.offset, call.length)
				}
			} else {
				if call.full {
					t.Errorf("expected DownloadRange call, got full Download")
				}
				if call.offset != tc.wantOffset {
					t.Errorf("offset = %d, want %d", call.offset, tc.wantOffset)
				}
				if call.length != tc.wantLength {
					t.Errorf("length = %d, want %d", call.length, tc.wantLength)
				}
			}
		})
	}
}

// TestOpenMandatoryUnsupportedOption verifies that an unknown option whose
// Mandatory() returns true causes Open to return an error.
type mandatoryOption struct{}

func (mandatoryOption) Header() (string, string) { return "X-Custom", "value" }
func (mandatoryOption) Mandatory() bool          { return true }
func (mandatoryOption) String() string           { return "MandatoryOption" }

func TestOpenMandatoryUnsupportedOption(t *testing.T) {
	obj, _ := objectWithSize(t, 1000)
	_, err := obj.Open(context.Background(), mandatoryOption{})
	if err == nil {
		t.Fatal("Open with unsupported mandatory option returned nil error, want error")
	}
}

// TestOpenNonMandatoryUnknownOptionIgnored verifies that an unknown option
// whose Mandatory() is false is silently ignored and Open succeeds.
type nonMandatoryOption struct{}

func (nonMandatoryOption) Header() (string, string) { return "X-Custom", "value" }
func (nonMandatoryOption) Mandatory() bool          { return false }
func (nonMandatoryOption) String() string           { return "NonMandatoryOption" }

func TestOpenNonMandatoryUnknownOptionIgnored(t *testing.T) {
	obj, _ := objectWithSize(t, 1000)
	rc, err := obj.Open(context.Background(), nonMandatoryOption{})
	if err != nil {
		t.Fatalf("Open with non-mandatory unknown option: %v", err)
	}
	_ = rc.Close()
}

// ---------------------------------------------------------------------------
// Fallback resolve → open path (design decision 1)
// ---------------------------------------------------------------------------

// TestFallbackResolveOnOpen verifies that an Object constructed WITHOUT a uuid
// (the ack-only create/copy shape) first calls ReadMetadata to learn the uuid,
// then calls DownloadRange with that uuid. The call ORDER is asserted.
func TestFallbackResolveOnOpen(t *testing.T) {
	c := &fakeClient{}
	resolvedUUID := "resolved-uuid-from-meta"
	var callOrder []string

	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		callOrder = append(callOrder, "ReadMetadata")
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				UUID: resolvedUUID,
				Size: 512,
				Path: path,
			},
		}, nil
	}
	c.downloadRangeResult = func(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
		callOrder = append(callOrder, "DownloadRange:"+uuid)
		return make([]byte, length), nil
	}

	f := &Fs{name: "ocufs", root: "/", client: c, readOnly: false}
	// Construct Object WITHOUT uuid (ack-only shape).
	obj := &Object{
		fs:   f,
		path: "/ack/file.bin",
		uuid: "", // intentionally empty
		size: 512,
	}

	rc, err := obj.Open(context.Background(), &fs.RangeOption{Start: 0, End: 99})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	_ = got

	if len(callOrder) < 2 {
		t.Fatalf("expected at least 2 calls (ReadMetadata + DownloadRange), got %d: %v", len(callOrder), callOrder)
	}
	if callOrder[0] != "ReadMetadata" {
		t.Errorf("first call = %q, want ReadMetadata", callOrder[0])
	}
	if callOrder[1] != "DownloadRange:"+resolvedUUID {
		t.Errorf("second call = %q, want DownloadRange with resolved uuid %q", callOrder[1], resolvedUUID)
	}
	// Verify the uuid is now set on the Object (idempotent after resolve).
	if obj.uuid != resolvedUUID {
		t.Errorf("after resolve, obj.uuid = %q, want %q", obj.uuid, resolvedUUID)
	}
}

// TestFallbackResolveNotFound verifies that when the fallback ReadMetadata
// returns a not-found error, Open surfaces fs.ErrorObjectNotFound.
func TestFallbackResolveNotFound(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return nil, brokerrpc.ErrNotFound
	}

	f := &Fs{name: "ocufs", root: "/", client: c, readOnly: false}
	obj := &Object{
		fs:   f,
		path: "/gone.bin",
		uuid: "", // uuid-less, triggers resolve
		size: 0,
	}

	_, err := obj.Open(context.Background())
	if !errors.Is(err, fs.ErrorObjectNotFound) {
		t.Errorf("Open with not-found resolve error = %v, want fs.ErrorObjectNotFound", err)
	}
}

// TestOpenEmptyUUIDAfterResolve verifies that when resolve() succeeds but
// leaves the uuid empty (a file arm with no uuid), Open returns a clear
// diagnostic error and issues NO Download/DownloadRange call (WR-04).
func TestOpenEmptyUUIDAfterResolve(t *testing.T) {
	c := &fakeClient{}
	// resolve() succeeds and classifies as a file (substantive mtime/size) but
	// the uuid field is empty.
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				Path:  path,
				Size:  10,
				Mtime: "2026-04-01T00:00:00Z",
				// UUID intentionally empty.
			},
		}, nil
	}
	downloadCalled := false
	c.downloadResult = func(ctx context.Context, uuid string) ([]byte, error) {
		downloadCalled = true
		return nil, nil
	}
	c.downloadRangeResult = func(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
		downloadCalled = true
		return nil, nil
	}

	f := &Fs{name: "ocufs", root: "/", client: c, readOnly: false}
	obj := &Object{fs: f, path: "/no-uuid.bin", uuid: ""}

	_, err := obj.Open(context.Background())
	if err == nil {
		t.Fatal("Open with empty uuid after resolve: got nil error, want a diagnostic")
	}
	if downloadCalled {
		t.Error("Open issued a Download/DownloadRange with an empty uuid; want none")
	}
}

// TestListDerivedObjectOpenNoResolve verifies that a List-derived Object
// (uuid already set) opens via DownloadRange WITHOUT calling ReadMetadata.
func TestListDerivedObjectOpenNoResolve(t *testing.T) {
	c := &fakeClient{}
	c.downloadRangeResult = func(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
		return make([]byte, length), nil
	}

	f := &Fs{name: "ocufs", root: "/", client: c, readOnly: false}
	obj := &Object{
		fs:    f,
		path:  "/docs/file.txt",
		uuid:  "list-uuid-xyz",
		size:  200,
		mtime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	rc, err := obj.Open(context.Background(), &fs.RangeOption{Start: 0, End: 49})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rc.Close() }()

	if c.readMetadataCount != 0 {
		t.Errorf("ReadMetadata was called %d times, want 0 for a uuid-bearing Object", c.readMetadataCount)
	}
	if c.downloadRangeCount != 1 {
		t.Errorf("DownloadRange called %d times, want 1", c.downloadRangeCount)
	}
	if c.lastDownloadRangeUUID != "list-uuid-xyz" {
		t.Errorf("DownloadRange uuid = %q, want %q", c.lastDownloadRangeUUID, "list-uuid-xyz")
	}
	if c.lastDownloadRangeOffset != 0 {
		t.Errorf("DownloadRange offset = %d, want 0", c.lastDownloadRangeOffset)
	}
	if c.lastDownloadRangeLength != 50 { // End(49) - Start(0) + 1 = 50
		t.Errorf("DownloadRange length = %d, want 50 (inclusive-End)", c.lastDownloadRangeLength)
	}
}

// TestAckOnlySizeResolvesDefensively verifies that Size() on an ack-only
// Object (uuid empty, size 0 — the only state in which the held size can be
// false) triggers the same defensive resolve ModTime uses, and that the
// resolve is idempotent: once the uuid lands, further Size() calls cost zero
// wire calls.
func TestAckOnlySizeResolvesDefensively(t *testing.T) {
	c := &fakeClient{}
	const wantSize = int64(512)
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				UUID:  "size-resolve-uuid",
				Size:  wantSize,
				Path:  path,
				Mtime: "2026-01-01T00:00:00Z",
			},
		}, nil
	}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/ack/file.bin", uuid: "", size: 0}

	if got := obj.Size(); got != wantSize {
		t.Errorf("Size() on an ack-only Object = %d, want %d (the defensive resolve must run)", got, wantSize)
	}
	if c.readMetadataCount != 1 {
		t.Errorf("ReadMetadata called %d times, want exactly 1", c.readMetadataCount)
	}
	if got := obj.Size(); got != wantSize {
		t.Errorf("second Size() = %d, want %d", got, wantSize)
	}
	if c.readMetadataCount != 1 {
		t.Errorf("ReadMetadata called %d times after the second Size(), want 1 (resolve is idempotent once uuid lands)", c.readMetadataCount)
	}
}

// TestResolvedSizeStaysWireFree verifies the guard the other way: an Object
// that already carries a uuid or a non-zero size answers Size() with zero wire
// calls — the hot Put/Move/Copy paths gain no round-trip.
func TestResolvedSizeStaysWireFree(t *testing.T) {
	c := &fakeClient{}
	f := newTestFs(t, c, false)

	withUUID := &Object{fs: f, path: "/a.bin", uuid: "u", size: 0}
	if got := withUUID.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0 (a resolved 0-byte file reports 0)", got)
	}
	withSize := &Object{fs: f, path: "/b.bin", uuid: "", size: 42}
	if got := withSize.Size(); got != 42 {
		t.Errorf("Size() = %d, want 42 (the carried size is truthful)", got)
	}
	if c.readMetadataCount != 0 {
		t.Errorf("ReadMetadata called %d times, want 0", c.readMetadataCount)
	}
}

// TestAckOnlySizeResolveIsBounded verifies that the resolve issued from
// Size() carries a deadline. The fs.Object interface gives Size() no context
// and the shared broker HTTP client sets no global timeout, so an unbounded
// context here would let a stalled broker connection wedge kernel getattr
// forever; the bound must live at this call site.
func TestAckOnlySizeResolveIsBounded(t *testing.T) {
	c := &fakeClient{}
	deadlineSeen := false
	var deadline time.Time
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		deadline, deadlineSeen = ctx.Deadline()
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{UUID: "u", Size: 1, Path: path, Mtime: "2026-01-01T00:00:00Z"},
		}, nil
	}
	f := newTestFs(t, c, false)
	obj := &Object{fs: f, path: "/ack/slow.bin", uuid: "", size: 0}

	before := time.Now()
	_ = obj.Size()
	if c.readMetadataCount != 1 {
		t.Fatalf("ReadMetadata called %d times from Size(), want 1 (the defensive resolve must run)", c.readMetadataCount)
	}
	if !deadlineSeen {
		t.Fatal("the resolve context carries no deadline; a stalled broker connection would wedge getattr forever")
	}
	if max := before.Add(sizeResolveTimeout + 5*time.Second); deadline.After(max) {
		t.Errorf("resolve deadline %v exceeds sizeResolveTimeout bound (max %v)", deadline, max)
	}
}

// TestObjectMimeTypeSurfacesBrokerMime verifies that *Object implements
// fs.MimeTyper and serves the broker-declared MIME type. Features()
// advertises ReadMimeType, so without the optional interface the declared
// mime carried on every constructor path is dead weight and rclone silently
// falls back to extension guessing — wrong for any extension-less file.
func TestObjectMimeTypeSurfacesBrokerMime(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				Path:  path,
				UUID:  "mime-uuid",
				Size:  4,
				Mtime: "2026-01-01T00:00:00Z",
				MIME:  "application/x-custom",
			},
		}, nil
	}
	f := newTestFs(t, c, false)

	obj, err := f.NewObject(context.Background(), "binfile") // extension-less
	if err != nil {
		t.Fatalf("NewObject: %v", err)
	}
	if _, ok := obj.(fs.MimeTyper); !ok {
		t.Fatal("*Object does not implement fs.MimeTyper; the advertised ReadMimeType capability is false")
	}
	if got := fs.MimeType(context.Background(), obj); got != "application/x-custom" {
		t.Errorf("fs.MimeType = %q, want the broker-declared %q (extension guessing must not win)", got, "application/x-custom")
	}
}

// TestObjectMimeTypeEmptyFallsBackToExtension verifies the rclone convention
// for an unknown MIME: MimeType returns the empty string, and fs.MimeType
// then falls back to extension-based guessing.
func TestObjectMimeTypeEmptyFallsBackToExtension(t *testing.T) {
	f := newTestFs(t, &fakeClient{}, false)
	obj := &Object{
		fs:     f,
		path:   "/x.txt",
		remote: "x.txt",
		uuid:   "u",
		size:   1,
		mime:   "", // broker declared nothing
	}
	got := fs.MimeType(context.Background(), obj)
	if !strings.HasPrefix(got, "text/plain") {
		t.Errorf("fs.MimeType with empty broker mime = %q, want the extension fallback (text/plain...)", got)
	}
}

// TestObjectResolveConcurrentNoRace hammers ModTime, Size, and Open concurrently
// on a single uuid-less (ack-only) Object. resolve() and the accessors all touch
// the lazily-resolved fields, so without mu this fans a data race that -race
// flags; with mu the run is clean. The point of this test IS the -race run.
func TestObjectResolveConcurrentNoRace(t *testing.T) {
	c := &fakeClient{}
	c.readMetadataResult = func(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error) {
		return &brokerrpc.ReadMetadataResponse{
			File: brokerrpc.File{
				UUID:  "resolved-uuid",
				Size:  128,
				Path:  path,
				Mtime: "2026-01-01T00:00:00Z",
			},
		}, nil
	}
	f := newTestFs(t, c, false)

	// A single ack-only Object shared across goroutines: uuid empty forces the
	// first accessor to resolve() and race the others reading the fields.
	obj := &Object{fs: f, path: "/docs/file.bin"}

	const workers = 24
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_ = obj.ModTime(context.Background())
			case 1:
				_ = obj.Size()
			default:
				if rc, err := obj.Open(context.Background()); err == nil {
					_, _ = io.ReadAll(rc)
					_ = rc.Close()
				}
			}
		}(i)
	}
	wg.Wait()
}
