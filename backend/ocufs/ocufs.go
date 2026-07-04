// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocufs is the rclone backend for the Open Computer Use file-store
// broker. It maps rclone's Fs/Object surface onto the broker's file-operations
// RPC through the brokerrpc package. The backend:
//
//   - Holds no backend credential and constructs no AuthorizationMetadata;
//     auth/intent are stamped centrally by brokerrpc (SEC-25, SEC-73).
//   - Reaches storage only through the brokerClient interface, which wraps
//     *brokerrpc.Client; no object-store client is linked (T-03-04).
//   - Enforces read-only mounts by returning a permission error at the TOP
//     of every mutating method before any client call (BE-02, T-03-01).
//   - Maps listDirectory union entries DIRECTLY to fully-populated Objects
//     (file arm) or fs.Dir (directory arm) without a ReadMetadata round-trip
//     on the hot path (D6, design decision 7).
package ocufs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/encoder"
)

// regInfo is the package-level RegInfo registered with rclone's registry.
var regInfo *fs.RegInfo

func init() {
	regInfo = &fs.RegInfo{
		Name:        "ocufs",
		Description: "Open Computer Use file-store broker (guest-side mount)",
		NewFs:       NewFs,
		Options:     fsOptions,
	}
	fs.Register(regInfo)
}

// Fs implements fs.Fs for the ocufs backend.
type Fs struct {
	name     string
	root     string
	client   brokerClient
	readOnly bool
	enc      encoder.MultiEncoder
}

// NewFs constructs an Fs from the provided config. It validates that the
// required options (service_url, filesystem_id, auth_token, ca_cert_pem) are
// present, then constructs the brokerClient from the real brokerrpc.Client
// bound to the broker's HTTPS service endpoint.
//
// The Fs constructs no AuthorizationMetadata. Auth/intent are stamped centrally
// by brokerrpc. NewFs does NOT dial the broker synchronously — the first RPC
// call does. The orchestrator/realpoint/cmd rewire that emits these option keys
// is a later phase; here NewFs only consumes them.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	var opts Options
	if err := configstruct.Set(m, &opts); err != nil {
		return nil, fmt.Errorf("ocufs: parse options: %w", err)
	}
	if opts.ServiceURL == "" {
		return nil, fmt.Errorf("ocufs: service_url is required")
	}
	if opts.FilesystemID == "" {
		return nil, fmt.Errorf("ocufs: filesystem_id is required")
	}
	if opts.AuthToken == "" {
		return nil, fmt.Errorf("ocufs: auth_token is required")
	}
	if opts.CACertPEM == "" {
		return nil, fmt.Errorf("ocufs: ca_cert_pem is required")
	}

	c, err := brokerrpc.New(opts.ServiceURL, opts.FilesystemID, opts.AuthToken, []byte(opts.CACertPEM))
	if err != nil {
		return nil, fmt.Errorf("ocufs: create broker client: %w", err)
	}

	return &Fs{
		name:     name,
		root:     root,
		client:   c, // *brokerrpc.Client satisfies brokerClient directly
		readOnly: opts.ReadOnly,
		enc:      opts.Enc,
	}, nil
}

// ---------------------------------------------------------------------------
// fs.Info implementation
// ---------------------------------------------------------------------------

// Name returns the remote name (the config section name passed to NewFs).
func (f *Fs) Name() string { return f.name }

// Root returns the root path for this Fs instance.
func (f *Fs) Root() string { return f.root }

// String returns a human-readable description.
func (f *Fs) String() string { return fmt.Sprintf("ocufs:%s", f.root) }

// Precision returns the ModTime precision for this backend. The broker
// encodes mtime as RFC3339 strings which carry second-level precision at
// minimum; we report time.Second as the safe lower bound. A later broker
// confirmation may raise this to time.Millisecond or time.Nanosecond once
// the mtime format is pinned (LD-2).
func (f *Fs) Precision() time.Duration { return time.Second }

// Hashes returns the set of hash types supported by the backend. The broker
// wire contract currently carries a `sha` field (D6 field-name reconciliation
// pending — sha vs checksum_md5). We report hash.None for now and document
// the gap; a later phase will wire the confirmed hash type.
func (f *Fs) Hashes() hash.Set { return hash.NewHashSet() }

// Features returns the optional interface features this Fs implements.
//
// Copy, Move, and DirMove are advertised now that their bodies are implemented
// (03-02). PutStream is intentionally NOT advertised: rclone spools an
// unknown-size source upstream and re-calls Put with a known size, so the
// backend never needs an unknown-total upload path, and declared_size_bytes is
// always a real size (D5, design decision 1 from 03-02).
//
// ListR (recursive listing) is not advertised here. Fs.List implements a
// depth-1 filter over the recursive ListDirectoryAll call, which is sufficient
// for rclone's VFS recursion. A dedicated ListR surface is deferred.
func (f *Fs) Features() *fs.Features {
	return (&fs.Features{
		ReadMimeType:            true,
		CanHaveEmptyDirectories: true,
		Copy:                    f.Copy,
		Move:                    f.Move,
		DirMove:                 f.DirMove,
		// PutStream intentionally absent — see comment above.
	}).Fill(context.Background(), f)
}

// ---------------------------------------------------------------------------
// fs.Fs core methods
// ---------------------------------------------------------------------------

// List returns the immediate children of dir. It calls ListDirectoryAll (which
// performs recursive broker paging) and then DEFENSIVELY filters the results
// to entries that are exactly one path segment below dir — dropping deeper
// descendants that the recursive op may include. This ensures List always
// returns depth-1 results as required by rclone (design decision 6).
//
// Each surviving entry is classified by the pinned union arm (D6, decision 7):
//   - file arm (entry.File != nil): a FULLY-POPULATED *Object built directly
//     from the FilesystemFile (uuid+size+mime+mtime). No ReadMetadata needed.
//   - directory arm (entry.Directory != nil): fs.NewDir(remote, mtime).
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	dirPath := f.absPath(dir)

	// Stream the recursive listing and filter to depth-1 as each page arrives,
	// so the full recursive tree is never held in memory just to surface the
	// immediate children (design decision 6). Only the surviving depth-1 slice
	// grows — as required by rclone's List contract, which returns a slice.
	var entries fs.DirEntries
	err := f.client.ListDirectoryStream(ctx, dirPath, func(entry brokerrpc.ListDirEntry) error {
		remote, ok := f.immediateChildRemote(dir, entry)
		if !ok {
			return nil // deeper descendant — filtered per design decision 6
		}
		switch {
		case entry.File != nil:
			entries = append(entries, objectFromFile(f, remote, entry.File))
		case entry.Directory != nil:
			mtime := parseMtime(entry.Directory.Mtime)
			entries = append(entries, fs.NewDir(remote, mtime))
		}
		// Both arms nil: tolerate silently (unknown union variant from future
		// broker field pin — stays tolerant per D6).
		return nil
	})
	if err != nil {
		// rclone's List contract: listing a directory that does not exist must
		// return fs.ErrorDirNotFound, so the VFS can distinguish a missing
		// directory from a transport failure. The broker reports a missing path
		// with not_found; map it to the typed sentinel (mirrors NewObject's
		// not_found → fs.ErrorObjectNotFound mapping).
		if errors.Is(err, brokerrpc.ErrNotFound) {
			return nil, fs.ErrorDirNotFound
		}
		return nil, fmt.Errorf("ocufs: List %q: %w", dirPath, err)
	}
	return entries, nil
}

// NewObject returns the Object at remote or an error sentinel if not found or
// if the path resolves to a directory. It calls ReadMetadata as a point
// lookup (design decision 2 — ReadMetadata stays a point lookup, NOT an
// enumeration mechanism).
//
// Returns:
//   - a fully-populated *Object when the response carries a File.
//   - fs.ErrorIsDir when the response carries a Directory (and no File).
//   - fs.ErrorObjectNotFound when neither arm is populated or when the broker
//     returns not_found.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	p := f.absPath(remote)
	resp, err := f.client.ReadMetadata(ctx, p)
	if err != nil {
		if errors.Is(err, brokerrpc.ErrNotFound) {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, fmt.Errorf("ocufs: NewObject %q: %w", p, err)
	}
	if resp == nil {
		return nil, fs.ErrorObjectNotFound
	}
	// Discriminate file vs directory vs absent on ARM PRESENCE, via the shared
	// helper that NewObject and resolve() both use so they cannot desync
	// (WR-02/WR-03/WR-05). A real file always carries an mtime, so a 0-byte
	// file with empty path/uuid is still detected as a file (not not-found).
	switch classifyReadMetadata(resp) {
	case metaArmFile:
		return &Object{
			fs:    f,
			path:  p,
			uuid:  resp.File.UUID,
			size:  resp.File.Size,
			mtime: parseMtime(resp.File.Mtime),
			mode:  resp.File.Mode,
			sha:   resp.File.SHA,
			mime:  resp.File.MIME,
		}, nil
	case metaArmDirectory:
		return nil, fs.ErrorIsDir
	default:
		return nil, fs.ErrorObjectNotFound
	}
}

// Put writes the content of in to the remote path, returning the resulting
// Object. On a read-only Fs it returns fs.ErrorPermissionDenied immediately
// before any client call (BE-02).
//
// The Upload op requires a real declared_size_bytes (D5); rclone guarantees
// src.Size() >= 0 when calling Put from outside an Fs. The returned Object is
// uuid-less (Upload returns no metadata); the defensive lazy resolve() fallback
// in Object.Open will fetch the uuid on first access.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	if f.readOnly {
		return nil, fs.ErrorPermissionDenied
	}
	dstPath := f.absPath(src.Remote())
	// overwrite=false: Put is the create-new write path, so a colliding
	// destination is a conflict rather than a silent in-place replacement.
	if err := f.client.Upload(ctx, dstPath, in, src.Size(), false); err != nil {
		return nil, fmt.Errorf("ocufs: Put %q: %w", dstPath, mapBrokerError(err))
	}
	// The upload response carries no metadata on the current wire contract;
	// the returned Object is uuid-less. Object.resolve() is the defensive
	// fallback: it fetches uuid+size on the first access that needs them.
	// Documented in plan 03-01 SUMMARY as a known follow-up.
	return &Object{
		fs:     f,
		path:   dstPath,
		remote: src.Remote(),
		size:   src.Size(),
	}, nil
}

// Mkdir creates a directory at dir. Returns fs.ErrorPermissionDenied
// immediately on a read-only Fs (BE-02).
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	if f.readOnly {
		return fs.ErrorPermissionDenied
	}
	p := f.absPath(dir)
	_, err := f.client.MakeDirectory(ctx, p)
	if err != nil {
		// rclone's Mkdir contract is idempotent: creating a directory that
		// already exists is a successful no-op, not an error. The broker
		// signals an existing path with already_exists; swallow that and
		// report success so repeated/own-root Mkdir calls behave as rclone
		// (and its standard backend tests) expect.
		if errors.Is(err, brokerrpc.ErrAlreadyExists) {
			return nil
		}
		return fmt.Errorf("ocufs: Mkdir %q: %w", p, mapBrokerError(err))
	}
	return nil
}

// Rmdir removes the directory at dir. Returns fs.ErrorPermissionDenied
// immediately on a read-only Fs (BE-02).
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	if f.readOnly {
		return fs.ErrorPermissionDenied
	}
	p := f.absPath(dir)
	_, err := f.client.RemoveDirectory(ctx, p)
	if err != nil {
		return fmt.Errorf("ocufs: Rmdir %q: %w", p, mapBrokerError(err))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

// absPath joins the Fs root with an rclone-relative path and returns the clean
// absolute path the broker addresses. The rclone-side path is in standard
// encoding; FromStandardPath maps it to the on-wire encoding so a name with
// control characters, invalid UTF-8, or trailing space/period round-trips
// losslessly (the "/" separator is preserved). An empty rel is the root.
func (f *Fs) absPath(rel string) string {
	std := f.root
	if rel != "" {
		std = path.Join(f.root, rel)
	}
	return cleanPath(f.enc.FromStandardPath(std))
}

// cleanPath ensures the path begins with "/" and has no trailing slash
// (except for "/" itself which stays "/").
func cleanPath(p string) string {
	p = path.Clean("/" + p)
	return p
}

// immediateChildRemote returns the rclone remote string for an entry if the
// entry is an immediate child of dir under the Fs root, and false otherwise.
// This is the depth-1 filter implementing design decision 6: List must return
// only entries that are exactly one path segment below dir. The broker entry
// path is on-wire encoded; the returned remote is decoded back to standard
// encoding (ToStandardPath) so rclone sees the original file name.
func (f *Fs) immediateChildRemote(dir string, entry brokerrpc.ListDirEntry) (string, bool) {
	var entryPath string
	switch {
	case entry.File != nil:
		entryPath = entry.File.Path
	case entry.Directory != nil:
		entryPath = entry.Directory.Path
	default:
		return "", false
	}
	entryPath = cleanPath(entryPath)
	parentPath := f.absPath(dir)

	// An entry equal to the directory being listed is that directory itself, not
	// a child. Without this guard a root listing whose entries include an entry
	// with Path "/" (== parentPath for the root) would fall through the special
	// case below and surface the directory inside its own listing with an empty
	// remote. Reject self before the child checks.
	if entryPath == parentPath {
		return "", false
	}

	// The entry must sit directly below parentPath.
	if !strings.HasPrefix(entryPath, parentPath+"/") {
		// Special case: parentPath is "/" — all top-level entries are candidates.
		if parentPath != "/" || strings.Count(strings.TrimPrefix(entryPath, "/"), "/") > 0 {
			return "", false
		}
	}

	// Strip the parent prefix to get the path-relative segment(s).
	rel := strings.TrimPrefix(entryPath, parentPath)
	rel = strings.TrimPrefix(rel, "/")

	// An immediate child has no "/" in the remaining segment.
	if strings.Contains(rel, "/") {
		return "", false
	}

	// Decode the on-wire segment back to standard encoding for the rclone remote.
	rel = f.enc.ToStandardPath(rel)

	// Build the rclone remote: dir/name (or just name at the root).
	if dir == "" {
		return rel, true
	}
	return path.Join(dir, rel), true
}

// objectFromFile builds a fully-populated *Object directly from a
// FilesystemFile listing entry. No ReadMetadata round-trip is needed because
// the file arm of the listDirectory union carries the full set of fields
// (uuid+size+mime+mtime) as per the pinned D6 contract.
func objectFromFile(f *Fs, remote string, ff *brokerrpc.FilesystemFile) *Object {
	return &Object{
		fs:    f,
		path:  ff.Path,
		uuid:  ff.UUID,
		size:  ff.Size,
		mtime: parseMtime(ff.Mtime),
		mode:  ff.Mode,
		sha:   ff.SHA,
		mime:  ff.MIME,
		// remote is the rclone-relative path (used by Remote()).
		remote: remote,
	}
}

// metaArm is the classification of a ReadMetadata union response: which arm
// (file, directory, or neither) the response carries.
type metaArm int

const (
	metaArmAbsent    metaArm = iota // neither arm present → not found
	metaArmFile                     // file arm present → an *Object
	metaArmDirectory                // directory arm present, no file → ErrorIsDir
)

// classifyMetaArms is the single discrimination predicate shared by NewObject
// and resolve(). It decides file-vs-directory-vs-absent by ARM PRESENCE rather
// than by guessing from value emptiness, which avoids two desync hazards:
//
//   - WR-02: a legitimate 0-byte file whose response omits path and whose uuid
//     is not yet reconciled would have size/path/uuid all zero; including the
//     mtime (always stamped for a real file) in the file-arm presence test
//     keeps it classified as a file instead of not-found.
//   - WR-03: a malformed dual-arm response (directory arm set plus a stray file
//     uuid) must surface as a directory, not a readable file. The file arm only
//     wins when the directory arm is absent.
//
// The arguments are the presence-relevant fields of the file arm and the path
// of the directory arm; the wrappers below adapt each wire type (File via
// ReadMetadataResponse, FilesystemFile via listing) onto this one predicate so
// the two surfaces apply identical rules (WR-05).
func classifyMetaArms(filePath, fileUUID, fileMtime string, fileSize int64, dirPath string) metaArm {
	// A SUBSTANTIVE file signal is path, mtime, or size — fields a real file
	// always carries (mtime is always stamped, closing the 0-byte gap of
	// WR-02). A bare uuid is NOT treated as substantive on its own: in a
	// malformed dual-arm response (directory path set plus a stray file uuid),
	// a lone uuid must not override a present directory arm (WR-03).
	fileSubstantive := filePath != "" || fileMtime != "" || fileSize != 0
	fileArm := fileSubstantive || fileUUID != ""
	dirArm := dirPath != ""
	switch {
	case dirArm && !fileSubstantive:
		// Directory arm present and the file arm carries no substantive signal
		// (at most a stray uuid) → directory wins.
		return metaArmDirectory
	case fileArm:
		// File arm present (substantive, or uuid with no competing directory) →
		// a file. File wins over a directory only when it is substantive.
		return metaArmFile
	default:
		return metaArmAbsent
	}
}

// classifyReadMetadata classifies a ReadMetadataResponse (whose file arm is a
// brokerrpc.File) via the shared predicate.
func classifyReadMetadata(resp *brokerrpc.ReadMetadataResponse) metaArm {
	if resp == nil {
		return metaArmAbsent
	}
	return classifyMetaArms(
		resp.File.Path, resp.File.UUID, resp.File.Mtime, resp.File.Size,
		resp.Directory.Path,
	)
}

// parseMtime parses an mtime string using RFC3339Nano (falling back to
// RFC3339). A parse failure returns the zero time rather than failing the
// operation, per the tolerant-decoding discipline and LD-2 pending
// broker confirmation of the wire format.
func parseMtime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{} // unknown time; tolerant decode
}
