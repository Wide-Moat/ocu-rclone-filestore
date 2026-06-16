// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

import "fmt"

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
	Index int
	Value string
}

func (e *ErrDestination) Error() string {
	return fmt.Sprintf("mounts[%d] destination %q must be an absolute path matching ^/.+", e.Index, e.Value)
}

// ErrMountScope reports a mount that does not carry exactly one of
// filesystem_id / memory_store_id.
type ErrMountScope struct {
	Index         int
	HasFilesystem bool
	HasMemory     bool
}

func (e *ErrMountScope) Error() string {
	switch {
	case e.HasFilesystem && e.HasMemory:
		return fmt.Sprintf("mounts[%d] sets both filesystem_id and memory_store_id; exactly one is required", e.Index)
	default:
		return fmt.Sprintf("mounts[%d] sets neither filesystem_id nor memory_store_id; exactly one is required", e.Index)
	}
}

// ErrScopeID reports a scope id (filesystem_id or memory_store_id) that is
// present but empty. The scope XOR keys on field presence; a present id must
// still be a non-empty string.
type ErrScopeID struct {
	Index int
	Field string
}

func (e *ErrScopeID) Error() string {
	return fmt.Sprintf("mounts[%d] %s is present but empty; a scope id must be a non-empty string", e.Index, e.Field)
}

// ErrPerms reports a dir_perms or file_perms value that is not an octal string.
type ErrPerms struct {
	Index int
	Field string
	Value string
}

func (e *ErrPerms) Error() string {
	return fmt.Sprintf("mounts[%d] %s %q must be an octal string matching ^0[0-7]{3}$", e.Index, e.Field, e.Value)
}

// ErrByteSize reports a vfs_cache_max_size that is not a valid byte-size string.
type ErrByteSize struct {
	Index int
	Value string
}

func (e *ErrByteSize) Error() string {
	return fmt.Sprintf("mounts[%d] vfs_cache_max_size %q must match ^[0-9]+(B|K|M|G|T)?$", e.Index, e.Value)
}

// ErrCacheMode reports a vfs_cache_mode outside the permitted enum.
type ErrCacheMode struct {
	Index int
	Value string
}

func (e *ErrCacheMode) Error() string {
	return fmt.Sprintf("mounts[%d] vfs_cache_mode %q must be one of off/minimal/writes/full", e.Index, e.Value)
}

// ErrAuthToken reports a per-mount auth_token that is present but empty. The
// guest holds the scoped session token; an empty string is not a usable token.
type ErrAuthToken struct {
	Index int
}

func (e *ErrAuthToken) Error() string {
	return fmt.Sprintf("mounts[%d] auth_token is present but empty; the per-mount session token must be a non-empty string", e.Index)
}

// ErrReadonlyMissing reports a mount that omits the required readonly flag. The
// flag carries the RW/RO posture; absence is not a legal default.
type ErrReadonlyMissing struct {
	Index int
}

func (e *ErrReadonlyMissing) Error() string {
	return fmt.Sprintf("mounts[%d] is missing the required readonly flag", e.Index)
}

// ErrCacheDuration reports a cache_duration_s that is missing or negative. The
// field is required per mount with a minimum of 0 (an explicit 0 is legal).
type ErrCacheDuration struct {
	Index   int
	Missing bool
	Value   int
}

func (e *ErrCacheDuration) Error() string {
	if e.Missing {
		return fmt.Sprintf("mounts[%d] is missing the required cache_duration_s field", e.Index)
	}
	return fmt.Sprintf("mounts[%d] cache_duration_s %d must be >= 0", e.Index, e.Value)
}

// ErrMissingField reports a schema-required top-level field that is absent
// from the document.
type ErrMissingField struct {
	Field string
}

func (e *ErrMissingField) Error() string {
	return fmt.Sprintf("required field %q is missing", e.Field)
}

// ErrDecode wraps a strict-decode failure (malformed JSON or an unknown field).
type ErrDecode struct {
	Err error
}

func (e *ErrDecode) Error() string {
	return fmt.Sprintf("strict decode failed: %v", e.Err)
}

func (e *ErrDecode) Unwrap() error { return e.Err }
