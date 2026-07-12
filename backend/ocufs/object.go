// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
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

	// mu guards the lazily-resolved fields below. resolve() writes them on the
	// ack-only fallback path and ModTime/Open/Update read or clear them; rclone
	// may drive those methods concurrently for one Object, so every access to a
	// mu-guarded field goes through mu.
	mu    sync.Mutex
	uuid  string // broker-minted handle (D7); empty on ack-only Objects
	size  int64
	mtime time.Time
	mode  string
	sha   string
	mime  string
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
	o.mu.Lock()
	empty := o.uuid == ""
	o.mu.Unlock()
	if empty {
		_ = o.resolve(ctx) // best-effort; return whatever we have
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.mtime
}

// sizeResolveTimeout bounds the defensive metadata resolve issued from
// Size(). The fs.Object interface gives Size no context to inherit a deadline
// from, and the shared broker HTTP client deliberately sets no global timeout
// (a client-wide timeout would also bound body reads and abort long streaming
// downloads mid-transfer) — so the bound has to live at this call site, or a
// TCP-level broker stall would wedge kernel getattr forever.
const sizeResolveTimeout = 30 * time.Second

// Size returns the size of the object in bytes. For an ack-only Object that
// carries neither a uuid nor a size (uuid == "" && size == 0 — the only state
// in which the held size can be false), it triggers the same defensive
// resolve ModTime uses, so a false 0 is never reported: the FUSE getattr
// after a rename reads Size() BEFORE ModTime(), and an unresolved 0 here
// would be stamped into the kernel attr cache, making an immediate read
// return empty content for a non-empty file. The size != 0 guard keeps the
// Put/Move/Copy hot paths wire-free (their carried size is truthful: the
// broker commits an upload only when the streamed byte count matches the
// declared one, and a server-side copy/move preserves byte count).
func (o *Object) Size() int64 {
	o.mu.Lock()
	unresolved := o.uuid == "" && o.size == 0
	o.mu.Unlock()
	if unresolved {
		// Bounded by construction (see sizeResolveTimeout): no caller context
		// exists on this interface and the shared client carries no deadline.
		ctx, cancel := context.WithTimeout(context.Background(), sizeResolveTimeout)
		defer cancel()
		_ = o.resolve(ctx) // best-effort; return whatever we have
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.size
}

// ---------------------------------------------------------------------------
// fs.ObjectInfo
// ---------------------------------------------------------------------------

// Hash returns the hash of the object for the given type. The broker carries
// a `sha` field (D6 field-name reconciliation pending — sha vs checksum_md5);
// until the hash type and wire key are confirmed we advertise an empty
// Hashes() set and report hash.ErrUnsupported here, so a caller that requests
// a hash anyway reads "unsupported" rather than "the hash is the empty string."
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Storable returns true — all Objects returned by the backend can be stored.
func (o *Object) Storable() bool { return true }

// MimeType returns the broker-declared MIME type for the object,
// implementing the optional fs.MimeTyper interface that the advertised
// ReadMimeType feature promises. The mime is decoded and stored on every
// constructor path (listing entries and metadata lookups); on the ack-only
// path (a uuid-less Put/Copy/Move object with no mime yet) it triggers the
// same defensive resolve() ModTime uses, since rclone may call MimeType
// independently of ModTime/Size. Once mime is known (or resolve fails), an
// empty string is the correct "unknown" answer per rclone convention — the
// core then falls back to extension-based guessing.
func (o *Object) MimeType(ctx context.Context) string {
	o.mu.Lock()
	unresolved := o.uuid == "" && o.mime == ""
	o.mu.Unlock()
	if unresolved {
		// rclone calls MimeType independently of ModTime/Size (e.g. serve
		// http/webdav content-type detection), so an ack-only object built by
		// Put/Copy/Move must resolve here too, exactly as ModTime does, or the
		// first MIME lookup falls back to extension guessing instead of the
		// broker-declared type.
		_ = o.resolve(ctx) // best-effort; return whatever we have
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.mime
}

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
// overwrite=true: the upload replaces the existing object atomically broker-side
// in a single fileUpload, rather than the guest issuing a remove-then-upload
// that would leave a non-atomic window in which the path does not exist.
//
// After upload the uuid is cleared so the next access re-resolves via the
// defensive lazy fallback (the Upload response carries no metadata on the
// current wire contract).
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	if o.fs.readOnly {
		return fs.ErrorPermissionDenied
	}
	if err := o.fs.client.Upload(ctx, o.path, in, src.Size(), true); err != nil {
		return fmt.Errorf("ocufs: Update %q: %w", o.path, mapBrokerError(err))
	}
	// Clear uuid so the next access triggers the defensive fallback resolve
	// (the upload ack carries no metadata). Update size optimistically from
	// src to keep Size() meaningful until the fallback runs.
	o.mu.Lock()
	o.uuid = ""
	o.size = src.Size()
	o.mu.Unlock()
	return nil
}

// Remove deletes the object from the filesystem. Returns
// fs.ErrorPermissionDenied on a read-only Fs (BE-02).
func (o *Object) Remove(ctx context.Context) error {
	if o.fs.readOnly {
		return fs.ErrorPermissionDenied
	}
	if _, err := o.fs.client.RemoveFile(ctx, o.path); err != nil {
		return fmt.Errorf("ocufs: Remove %q: %w", o.path, mapBrokerError(err))
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
	// Snapshot the resolved handle and size under the lock: resolve() and a
	// concurrent Update() write these fields, so read them once into locals and
	// operate on the snapshot for the rest of Open.
	o.mu.Lock()
	uuid := o.uuid
	size := o.size
	o.mu.Unlock()

	// resolve() can succeed while leaving uuid empty (a file arm whose uuid
	// field is not populated). Download addresses by uuid, so guard here and
	// emit a clear diagnostic instead of issuing Download with an empty handle
	// and relying on the broker to reject it (WR-04).
	if uuid == "" {
		return nil, fmt.Errorf("ocufs: Open %q: resolved metadata carries no uuid handle", o.path)
	}

	var (
		offset   int64
		length   int64
		fullRead = true
	)

	for _, opt := range options {
		switch v := opt.(type) {
		case *fs.SeekOption:
			// SeekOption: offset to end.
			offset = v.Offset
			length = size - offset
			if length < 0 {
				length = 0
			}
			fullRead = false
		case *fs.RangeOption:
			// RangeOption.Decode handles all four forms and returns the
			// inclusive-End conversion (length = End - Start + 1).
			off, limit := v.Decode(size)
			offset = off
			if limit == -1 {
				// "to end" sentinel from Decode: read from offset to EOF.
				length = size - offset
				if length < 0 {
					length = 0
				}
			} else {
				length = limit
			}
			fullRead = false
		default:
			if opt.Mandatory() {
				return nil, fmt.Errorf("ocufs: Open: unsupported mandatory option %T", opt)
			}
			// Non-mandatory unknown option: silently ignore.
		}
	}

	var (
		rc  io.ReadCloser
		err error
	)
	if fullRead {
		rc, err = o.fs.client.Download(ctx, uuid)
	} else {
		rc, err = o.fs.client.DownloadRange(ctx, uuid, offset, length)
	}
	if err != nil {
		return nil, err // propagate unwrapped for rclone's retry layer
	}
	// Return the broker stream directly: VFS reads bytes as they arrive rather
	// than the backend buffering the whole object into memory first. The caller
	// (rclone's VFS) closes the reader, which releases the underlying HTTP body.
	return rc, nil
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
	o.mu.Lock()
	if o.uuid != "" {
		o.mu.Unlock()
		return nil // already resolved; idempotent
	}
	o.mu.Unlock()

	// Fetch outside the lock: ReadMetadata is a broker round-trip and must not
	// hold mu (a concurrent Size()/ModTime() would otherwise block on the wire).
	resp, err := o.fs.client.ReadMetadata(ctx, o.path)
	if err != nil {
		if errors.Is(err, brokerrpc.ErrNotFound) {
			return fs.ErrorObjectNotFound
		}
		return fmt.Errorf("ocufs: resolve %q: %w", o.path, err)
	}
	// Discriminate on ARM PRESENCE via the SAME helper NewObject uses, so the
	// two surfaces cannot desync (WR-02/WR-03/WR-05). A real file always carries
	// an mtime, so a 0-byte file with empty path/uuid still classifies as a
	// file; a directory arm with a stray file uuid still classifies as a dir.
	switch classifyReadMetadata(resp) {
	case metaArmDirectory:
		// Path resolves to a directory — not a file.
		return fs.ErrorIsDir
	case metaArmAbsent:
		return fs.ErrorObjectNotFound
	}

	o.mu.Lock()
	// A concurrent resolve() may have populated uuid while we were on the wire;
	// the first writer wins and this is a harmless idempotent overwrite with the
	// same broker-sourced values.
	o.uuid = resp.File.UUID
	o.size = resp.File.Size
	o.mtime = parseMtime(resp.File.Mtime)
	o.mode = resp.File.Mode
	o.sha = resp.File.SHA
	o.mime = resp.File.MIME
	o.mu.Unlock()
	return nil
}
