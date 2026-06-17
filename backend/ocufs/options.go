// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/encoder"
)

// defaultEncoding is the path encoding the backend applies on the wire. The
// broker addresses objects by an absolute "/"-separated path and uses "/" as
// the only separator, so paths must round-trip every other byte unchanged.
// We encode the bytes that are unsafe or ambiguous in a path component —
// control characters, an invalid-UTF-8 byte sequence, and the trailing
// space/dot that some path consumers strip — so a file whose name contains
// them is stored and retrieved losslessly. "/" itself is NOT encoded: it is
// the structural separator and the broker expects it literally.
const defaultEncoding = encoder.EncodeCtl |
	encoder.EncodeInvalidUtf8 |
	encoder.EncodeBackSlash |
	encoder.EncodeDoubleQuote |
	encoder.EncodeRightSpace |
	encoder.EncodeRightPeriod

// Options carries the per-mount configuration for the ocufs backend. Fields
// are populated by configstruct.Set from the configmap supplied to NewFs.
//
// ServiceURL, FilesystemID, AuthToken and CACertPEM are required; NewFs returns
// an error when any is absent. ReadOnly is optional and defaults to false.
//
// ServiceURL is the broker's HTTPS endpoint reached over TLS. AuthToken is the
// static session credential carried on every request. CACertPEM is the trust
// anchor for the inspecting edge. FilesystemID is the session-scoped scope
// handle carried on every request; the guest never derives scope from a uuid.
type Options struct {
	// ReadOnly mounts the filesystem in read-only mode. Every mutating method
	// (Put, Update, Remove, Mkdir, Rmdir, Copy, Move, DirMove, SetModTime)
	// returns a permission error at the top of the method without invoking any
	// broker RPC (BE-02, T-03-01).
	ReadOnly bool `config:"read_only"`

	// ServiceURL is the broker's HTTPS service endpoint. Required.
	ServiceURL string `config:"service_url"`

	// FilesystemID is the session-scoped filesystem handle. It is the sole
	// scope carried on every broker request; the guest never derives scope
	// from a uuid (D7). Required.
	FilesystemID string `config:"filesystem_id"`

	// AuthToken is the static session credential carried as the Authorization
	// header on every request. Read once; never refreshed. Required.
	AuthToken string `config:"auth_token"`

	// CACertPEM is the PEM trust anchor for the inspecting edge's TLS
	// certificate. Required.
	CACertPEM string `config:"ca_cert_pem"`

	// Enc is the path encoding applied on the wire so file names containing
	// control characters, invalid UTF-8, or trailing space/period round-trip
	// losslessly through the broker (defaultEncoding). Standard rclone backend
	// option; rarely overridden.
	Enc encoder.MultiEncoder `config:"encoding"`
}

// fsOptions is the fs.Options slice declared in the RegInfo. configstruct.Set
// populates an Options struct from a configmap using the field tags above.
var fsOptions = fs.Options{
	{
		Name:     "read_only",
		Help:     "Mount as read-only. Every mutating method returns a permission error before any RPC (BE-02).",
		Default:  false,
		Advanced: false,
	},
	{
		Name:     "service_url",
		Help:     "Broker HTTPS service endpoint reached over TLS.",
		Default:  "",
		Required: true,
	},
	{
		Name:     "filesystem_id",
		Help:     "Session-scoped filesystem identifier carried on every broker request.",
		Default:  "",
		Required: true,
	},
	{
		Name:      "auth_token",
		Help:      "Static session credential carried as the Authorization header on every request.",
		Default:   "",
		Required:  true,
		Sensitive: true,
	},
	{
		Name:     "ca_cert_pem",
		Help:     "PEM trust anchor for the inspecting edge's TLS certificate.",
		Default:  "",
		Required: true,
	},
	{
		Name:     "encoding",
		Help:     "The encoding for the backend. Encodes path bytes that are unsafe or ambiguous (control chars, invalid UTF-8, trailing space/period) so file names round-trip losslessly through the broker.",
		Default:  defaultEncoding,
		Advanced: true,
	},
}
