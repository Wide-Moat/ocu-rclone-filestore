// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"
)

// Object implements fs.Object for the ocufs backend. It represents a single
// file in the broker-managed filesystem.
//
// An Object is normally constructed with all fields populated (uuid, size,
// mtime, mime) from either a listing entry (via List/objectFromFile) or a
// ReadMetadata response (via NewObject). In the ack-only create/copy/upload
// path the Object may arrive without a uuid; resolve() is the defensive
// fallback that fetches uuid+size from ReadMetadata on the first access that
// needs them.
type Object struct {
	fs     *Fs
	remote string // rclone-relative path (one segment or more, no leading /)
	path   string // absolute broker path (leading /)
	uuid   string // broker-minted handle (D7); empty on ack-only Objects
	size   int64
	mtime  time.Time
	mode   string
	sha    string
	mime   string
}

// ---------------------------------------------------------------------------
// fs.DirEntry — common to fs.Object and fs.Directory
// ---------------------------------------------------------------------------

// Fs returns the parent Fs.
func (o *Object) Fs() fs.Info { return o.fs }

// String returns a human-readable description.
func (o *Object) String() string { return o.path }

// Remote returns the rclone-relative path for this object.
func (o *Object) Remote() string { return o.remote }

// ModTime returns the modification time of the object. For a List- or
// NewObject-built Object the mtime is already populated. For a uuid-less
// ack-only Object it calls resolve() to fetch it.
func (o *Object) ModTime(ctx context.Context) time.Time {
	if o.uuid == "" {
		_ = o.resolve(ctx) // best-effort; return whatever we have
	}
	return o.mtime
}

// Size returns the size of the object in bytes.
func (o *Object) Size() int64 { return o.size }

// ---------------------------------------------------------------------------
// fs.ObjectInfo
// ---------------------------------------------------------------------------

// Hash returns the hash of the object for the given type. The broker carries
// a `sha` field (D6 field-name reconciliation pending — sha vs checksum_md5);
// we return "" for all types until the hash type and wire key are confirmed.
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return "", nil
}

// Storable returns true — all Objects returned by the backend can be stored.
func (o *Object) Storable() bool { return true }

// ---------------------------------------------------------------------------
// fs.Object mutating methods
// ---------------------------------------------------------------------------

// SetModTime sets the modification time on the object. No broker operation
// sets mtime; this method always returns fs.ErrorCantSetModTime with ZERO
// client calls (design decision 8). On a read-only Fs the read-only guard
// fires first (BE-02).
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	if o.fs.readOnly {
		return fs.ErrorPermissionDenied
	}
	return fs.ErrorCantSetModTime
}

// Update writes new content in to the object, overwriting it in place.
// Returns fs.ErrorPermissionDenied on a read-only Fs (BE-02).
//
// After upload the uuid is cleared so the next access re-resolves via the
// defensive lazy fallback (the Upload response carries no metadata on the
// current wire contract).
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	if o.fs.readOnly {
		return fs.ErrorPermissionDenied
	}
	if err := o.fs.client.Upload(ctx, o.path, in, src.Size()); err != nil {
		return fmt.Errorf("ocufs: Update %q: %w", o.path, err)
	}
	// Clear uuid so the next access triggers the defensive fallback resolve
	// (the upload ack carries no metadata). Update size optimistically from
	// src to keep Size() meaningful until the fallback runs.
	o.uuid = ""
	o.size = src.Size()
	return nil
}

// Remove deletes the object from the filesystem. Returns
// fs.ErrorPermissionDenied on a read-only Fs (BE-02).
func (o *Object) Remove(ctx context.Context) error {
	if o.fs.readOnly {
		return fs.ErrorPermissionDenied
	}
	if _, err := o.fs.client.RemoveFile(ctx, o.path); err != nil {
		return fmt.Errorf("ocufs: Remove %q: %w", o.path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Open — with RangeOption/SeekOption handling and inclusive-End conversion
// ---------------------------------------------------------------------------

// Open opens the file for reading. It first calls resolve() (a no-op for a
// List/NewObject-built Object that already has a uuid) to handle the ack-only
// create/copy/upload case. Then it converts any RangeOption or SeekOption to
// an (offset, length) pair and calls DownloadRange (or Download for a full
// read), returning the bytes wrapped in an io.NopCloser (design decision 3).
//
// RangeOption.End is inclusive; the off-by-one conversion is: length =
// End - Start + 1. fs.RangeOption.Decode handles all four range forms
// (suffix, open-ended, explicit, full-read) consistently.
//
// An unknown option whose Mandatory() reports true and which Open does not
// handle returns an error. Non-mandatory unknown options are silently ignored.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	if err := o.resolve(ctx); err != nil {
		return nil, err
	}

	var (
		haveRange bool
		offset    int64
		length    int64
		fullRead  = true
	)

	for _, opt := range options {
		switch v := opt.(type) {
		case *fs.SeekOption:
			// SeekOption: offset to end.
			offset = v.Offset
			length = o.size - offset
			if length < 0 {
				length = 0
			}
			haveRange = true
			fullRead = false
		case *fs.RangeOption:
			// RangeOption.Decode handles all four forms and returns the
			// inclusive-End conversion (length = End - Start + 1).
			off, limit := v.Decode(o.size)
			offset = off
			if limit == -1 {
				// "to end" sentinel from Decode: read from offset to EOF.
				length = o.size - offset
				if length < 0 {
					length = 0
				}
			} else {
				length = limit
			}
			haveRange = true
			fullRead = false
		default:
			if opt.Mandatory() {
				return nil, fmt.Errorf("ocufs: Open: unsupported mandatory option %T", opt)
			}
			// Non-mandatory unknown option: silently ignore.
		}
	}
	_ = haveRange // used implicitly via fullRead

	var (
		data []byte
		err  error
	)
	if fullRead {
		data, err = o.fs.client.Download(ctx, o.uuid)
	} else {
		data, err = o.fs.client.DownloadRange(ctx, o.uuid, offset, length)
	}
	if err != nil {
		return nil, err // propagate unwrapped for rclone's retry layer
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// ---------------------------------------------------------------------------
// resolve — defensive lazy uuid fallback (design decision 1)
// ---------------------------------------------------------------------------

// resolve populates uuid+size+mtime+mode+sha from ReadMetadata when the
// Object was constructed without a uuid (the ack-only create/copy/upload
// case). It is a no-op once uuid is already set (idempotent).
//
// Returns fs.ErrorObjectNotFound only when ReadMetadata itself reports
// not-found or returns an empty response (no File and no Directory).
// For a List- or NewObject-built Object the uuid is already present, so
// resolve is always a no-op on the hot path — no extra round-trip.
func (o *Object) resolve(ctx context.Context) error {
	if o.uuid != "" {
		return nil // already resolved; idempotent
	}

	resp, err := o.fs.client.ReadMetadata(ctx, o.path)
	if err != nil {
		if errors.Is(err, brokerrpc.ErrNotFound) {
			return fs.ErrorObjectNotFound
		}
		return fmt.Errorf("ocufs: resolve %q: %w", o.path, err)
	}
	if resp == nil || (resp.File.UUID == "" && resp.File.Path == "" && resp.Directory.Path == "") {
		return fs.ErrorObjectNotFound
	}
	if resp.File.UUID == "" && resp.Directory.Path != "" {
		// Path resolves to a directory — not a file.
		return fs.ErrorIsDir
	}

	o.uuid = resp.File.UUID
	o.size = resp.File.Size
	o.mtime = parseMtime(resp.File.Mtime)
	o.mode = resp.File.Mode
	o.sha = resp.File.SHA
	o.mime = resp.File.MIME
	return nil
}
