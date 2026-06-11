// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"context"
	"fmt"

	"github.com/rclone/rclone/fs"
)

// Copy copies src to the remote dstRemote, returning the destination Object.
// Returns fs.ErrorPermissionDenied immediately on a read-only Fs before any
// client call (BE-02, T-03-07). The source path is derived from the src
// Object's broker path; the destination path is built from the Fs root and
// dstRemote.
//
// CopyFile returns only an AckResponse (no File body), so no uuid is available
// from the ack. The returned Object is uuid-less; the defensive lazy resolve()
// in Object.ModTime/Open will fetch uuid+size via ReadMetadata on first access
// (design decision 2 from 03-02 — distinct from the direct List path where
// uuid arrives in the listing entry).
func (f *Fs) Copy(ctx context.Context, src fs.Object, dstRemote string) (fs.Object, error) {
	if f.readOnly {
		return nil, fs.ErrorPermissionDenied
	}

	// Derive the source broker path from the src Object's stored path.
	srcPath := ""
	if srcObj, ok := src.(*Object); ok {
		srcPath = srcObj.path
	} else {
		// src is not an *Object from this backend; reconstruct the path from
		// the source's remote string relative to the same root.
		srcPath = absPath(f.root, src.Remote())
	}
	dstPath := absPath(f.root, dstRemote)

	if _, err := f.client.CopyFile(ctx, srcPath, dstPath); err != nil {
		return nil, fmt.Errorf("ocufs: Copy %q → %q: %w", srcPath, dstPath, err)
	}

	// Build a uuid-less destination Object. The broker ack carries no File
	// body, so no uuid is available from the ack. resolve() is the defensive
	// fallback that fetches uuid+size on the first access that needs them.
	return &Object{
		fs:     f,
		path:   dstPath,
		remote: dstRemote,
	}, nil
}

// Move moves src to the remote dstRemote, returning the destination Object.
// Returns fs.ErrorPermissionDenied immediately on a read-only Fs before any
// client call (BE-02, T-03-07).
//
// MoveFile returns only an AckResponse (no File body), so the returned Object
// is uuid-less and relies on the defensive lazy resolve() for first access.
func (f *Fs) Move(ctx context.Context, src fs.Object, dstRemote string) (fs.Object, error) {
	if f.readOnly {
		return nil, fs.ErrorPermissionDenied
	}

	srcPath := ""
	if srcObj, ok := src.(*Object); ok {
		srcPath = srcObj.path
	} else {
		srcPath = absPath(f.root, src.Remote())
	}
	dstPath := absPath(f.root, dstRemote)

	if _, err := f.client.MoveFile(ctx, srcPath, dstPath); err != nil {
		return nil, fmt.Errorf("ocufs: Move %q → %q: %w", srcPath, dstPath, err)
	}

	return &Object{
		fs:     f,
		path:   dstPath,
		remote: dstRemote,
	}, nil
}

// DirMove moves the directory at srcRemote under srcFs to dstRemote under
// this Fs. Returns fs.ErrorPermissionDenied immediately on a read-only Fs
// before any client call (BE-02, T-03-07). Returns fs.ErrorCantDirMove if
// srcFs is not the same backend type as this Fs.
//
// Cross-Fs moves are not supported: the broker's moveDirectory op is scoped to
// a single filesystem_id, so both the source and destination must be the same
// ocufs Fs instance.
func (f *Fs) DirMove(ctx context.Context, srcFs fs.Fs, srcRemote, dstRemote string) error {
	if f.readOnly {
		return fs.ErrorPermissionDenied
	}

	// Validate that the source Fs is an ocufs Fs. Cross-backend DirMove is
	// not supported; rclone falls back to copy+delete when this returns an error.
	if _, ok := srcFs.(*Fs); !ok {
		return fs.ErrorCantDirMove
	}

	srcPath := absPath(f.root, srcRemote)
	dstPath := absPath(f.root, dstRemote)

	if _, err := f.client.MoveDirectory(ctx, srcPath, dstPath); err != nil {
		return fmt.Errorf("ocufs: DirMove %q → %q: %w", srcPath, dstPath, err)
	}
	return nil
}
