// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

import "fmt"

// mountArray names the array a mount entry belongs to, so error messages can
// point an operator at the exact entry that failed a rule.
type mountArray string

const (
	arrayMounts         mountArray = "mounts"
	arrayReadonlyMounts mountArray = "readonly_mounts"
)

// ErrSchemaVersion reports a schema_version that does not match the interface
// version pattern.
type ErrSchemaVersion struct {
	Value string
}

func (e *ErrSchemaVersion) Error() string {
	return fmt.Sprintf("schema_version %q does not match the required interface version pattern ^v[0-9]+(alpha|beta)?[0-9]*$", e.Value)
}

// ErrServiceURL reports a service_url that is not an https URI.
type ErrServiceURL struct {
	Value  string
	Reason string
}

func (e *ErrServiceURL) Error() string {
	return fmt.Sprintf("service_url %q is invalid: %s", e.Value, e.Reason)
}

// ErrDestination reports a mount destination that is not absolute.
type ErrDestination struct {
	Array mountArray
	Index int
	Value string
}

func (e *ErrDestination) Error() string {
	return fmt.Sprintf("%s[%d] destination %q must be an absolute path matching ^/.+", e.Array, e.Index, e.Value)
}

// ErrMountScope reports a mount that does not carry exactly one of
// filesystem_id / memory_store_id.
type ErrMountScope struct {
	Array         mountArray
	Index         int
	HasFilesystem bool
	HasMemory     bool
}

func (e *ErrMountScope) Error() string {
	switch {
	case e.HasFilesystem && e.HasMemory:
		return fmt.Sprintf("%s[%d] sets both filesystem_id and memory_store_id; exactly one is required", e.Array, e.Index)
	default:
		return fmt.Sprintf("%s[%d] sets neither filesystem_id nor memory_store_id; exactly one is required", e.Array, e.Index)
	}
}

// ErrPerms reports a dir_perms or file_perms value that is not an octal string.
type ErrPerms struct {
	Array mountArray
	Index int
	Field string
	Value string
}

func (e *ErrPerms) Error() string {
	return fmt.Sprintf("%s[%d] %s %q must be an octal string matching ^0[0-7]{3}$", e.Array, e.Index, e.Field, e.Value)
}

// ErrByteSize reports a vfs_cache_max_size that is not a valid byte-size string.
type ErrByteSize struct {
	Array mountArray
	Index int
	Value string
}

func (e *ErrByteSize) Error() string {
	return fmt.Sprintf("%s[%d] vfs_cache_max_size %q must match ^[0-9]+(B|K|M|G|T)?$", e.Array, e.Index, e.Value)
}

// ErrCacheMode reports a vfs_cache_mode outside the permitted enum.
type ErrCacheMode struct {
	Array mountArray
	Index int
	Value string
}

func (e *ErrCacheMode) Error() string {
	return fmt.Sprintf("%s[%d] vfs_cache_mode %q must be one of off/minimal/writes/full", e.Array, e.Index, e.Value)
}

// ErrWritesPosture reports a writes flag that does not match the array the mount
// belongs to (mounts require true, readonly_mounts require false). A nil flag is
// also a posture failure because the field is required.
type ErrWritesPosture struct {
	Array    mountArray
	Index    int
	Expected bool
	Missing  bool
}

func (e *ErrWritesPosture) Error() string {
	if e.Missing {
		return fmt.Sprintf("%s[%d] is missing the required writes flag (expected %t)", e.Array, e.Index, e.Expected)
	}
	return fmt.Sprintf("%s[%d] has writes=%t but %s entries require writes=%t", e.Array, e.Index, !e.Expected, e.Array, e.Expected)
}

// ErrProvisionMarker reports a provision-side credential marker present in a
// guest config. The guest variant carries no credential by construction.
type ErrProvisionMarker struct {
	Marker   string
	Location string
}

func (e *ErrProvisionMarker) Error() string {
	return fmt.Sprintf("provision-side marker %q present at %s; the guest config carries no credential material", e.Marker, e.Location)
}

// ErrDecode wraps a strict-decode failure (malformed JSON or an unknown field).
type ErrDecode struct {
	Err error
}

func (e *ErrDecode) Error() string {
	return fmt.Sprintf("strict decode failed: %v", e.Err)
}

func (e *ErrDecode) Unwrap() error { return e.Err }
