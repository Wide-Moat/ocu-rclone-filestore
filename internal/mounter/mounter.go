// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mounter is the seam between the loaded guest mount config and the
// VFS mount it will eventually drive.
//
// This package declares the interface and a not-implemented sentinel only. The
// concrete mount that binds a [mountcfg.Config] to a live VFS is built in a
// later phase; until then the no-op implementation returns [ErrNotImplemented]
// so every call site fails closed on an explicit, matchable error.
package mounter

import (
	"errors"

	// Anchor the pinned rclone module as a direct dependency without
	// registering a backend or invoking any mount path. The core fs package
	// carries no backend registration on its own; the real mount wiring lands
	// in a later phase. This blank import keeps rclone in the module graph as a
	// direct, exact-tag dependency rather than a prunable indirect one.
	_ "github.com/rclone/rclone/fs"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// ErrNotImplemented is returned by the seam until the real mount lands. Call
// sites match it with errors.Is so the not-implemented path stays distinct from
// any future operational error.
var ErrNotImplemented = errors.New("mounter: not implemented")

// Mounter binds a validated guest mount config to the VFS mounts it describes.
// The single method takes the loaded config so the seam is typed end to end.
type Mounter interface {
	// Mount realizes every entry in cfg as a live mount and blocks until the
	// mounts are torn down, returning the terminal error (nil on clean
	// shutdown). The current implementation is a seam returning
	// ErrNotImplemented.
	Mount(cfg *mountcfg.Config) error
}

// NotImplemented is the seam implementation. It satisfies Mounter and returns
// ErrNotImplemented for every config, so the entrypoint fails closed until the
// real mount is built.
type NotImplemented struct{}

// Mount returns ErrNotImplemented unconditionally.
func (NotImplemented) Mount(_ *mountcfg.Config) error {
	return ErrNotImplemented
}

// New returns the current seam implementation. It exists so the entrypoint
// depends on a constructor rather than a concrete type and need not change when
// the real mount replaces the seam.
func New() Mounter {
	return NotImplemented{}
}
