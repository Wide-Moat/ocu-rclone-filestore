// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocufs tests — object.go Open range/seek table, fallback resolve.
package ocufs

import (
	"context"
	"errors"
	"io"
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

func (f *fakeOpenClient) DownloadRange(ctx context.Context, uuid string, offset, length int64) ([]byte, error) {
	f.calls = append(f.calls, openCallRecord{uuid: uuid, offset: offset, length: length})
	// Return a slice of the expected length so the test can verify byte count.
	return make([]byte, length), nil
}

func (f *fakeOpenClient) Download(ctx context.Context, uuid string) ([]byte, error) {
	f.calls = append(f.calls, openCallRecord{uuid: uuid, full: true})
	return make([]byte, 1000), nil
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
			rc.Close()

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
	rc.Close()
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
	defer rc.Close()
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
	defer rc.Close()

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
