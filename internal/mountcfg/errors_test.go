// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

import (
	"errors"
	"testing"
)

// TestErrorMessages pins the exact Error() rendering of every typed error this
// package returns. The message is the operator-facing contract: it names the
// failing field, the array, and the index so a failed load is diagnosable from
// the error alone. Each case asserts the full string, not merely that the type
// is returned.
func TestErrorMessages(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "schema version",
			err:  &ErrSchemaVersion{Value: "1.0"},
			want: `schema_version "1.0" does not match the required interface version pattern ^v[0-9]+(alpha|beta)?[0-9]*$`,
		},
		{
			name: "service url",
			err:  &ErrServiceURL{Value: "http://x", Reason: "must begin https://"},
			want: `service_url "http://x" is invalid: must begin https://`,
		},
		{
			name: "destination",
			err:  &ErrDestination{Array: arrayMounts, Index: 2, Value: "rel/path"},
			want: `mounts[2] destination "rel/path" must be an absolute path matching ^/.+`,
		},
		{
			name: "mount scope both set",
			err:  &ErrMountScope{Array: arrayMounts, Index: 0, HasFilesystem: true, HasMemory: true},
			want: `mounts[0] sets both filesystem_id and memory_store_id; exactly one is required`,
		},
		{
			name: "mount scope neither set",
			err:  &ErrMountScope{Array: arrayReadonlyMounts, Index: 1, HasFilesystem: false, HasMemory: false},
			want: `readonly_mounts[1] sets neither filesystem_id nor memory_store_id; exactly one is required`,
		},
		{
			name: "scope id empty",
			err:  &ErrScopeID{Array: arrayMounts, Index: 0, Field: "filesystem_id"},
			want: `mounts[0] filesystem_id is present but empty; a scope id must be a non-empty string`,
		},
		{
			name: "perms",
			err:  &ErrPerms{Array: arrayMounts, Index: 0, Field: "dir_perms", Value: "999"},
			want: `mounts[0] dir_perms "999" must be an octal string matching ^0[0-7]{3}$`,
		},
		{
			name: "byte size",
			err:  &ErrByteSize{Array: arrayReadonlyMounts, Index: 3, Value: "12X"},
			want: `readonly_mounts[3] vfs_cache_max_size "12X" must match ^[0-9]+(B|K|M|G|T)?$`,
		},
		{
			name: "cache mode",
			err:  &ErrCacheMode{Array: arrayMounts, Index: 0, Value: "sometimes"},
			want: `mounts[0] vfs_cache_mode "sometimes" must be one of off/minimal/writes/full`,
		},
		{
			name: "writes posture wrong value (mounts expect true)",
			err:  &ErrWritesPosture{Array: arrayMounts, Index: 0, Expected: true},
			want: `mounts[0] has writes=false but mounts entries require writes=true`,
		},
		{
			name: "writes posture wrong value (readonly expect false)",
			err:  &ErrWritesPosture{Array: arrayReadonlyMounts, Index: 0, Expected: false},
			want: `readonly_mounts[0] has writes=true but readonly_mounts entries require writes=false`,
		},
		{
			name: "writes posture missing",
			err:  &ErrWritesPosture{Array: arrayMounts, Index: 1, Expected: true, Missing: true},
			want: `mounts[1] is missing the required writes flag (expected true)`,
		},
		{
			name: "cache duration negative",
			err:  &ErrCacheDuration{Array: arrayMounts, Index: 0, Value: -5},
			want: `mounts[0] cache_duration_s -5 must be >= 0`,
		},
		{
			name: "cache duration missing",
			err:  &ErrCacheDuration{Array: arrayReadonlyMounts, Index: 2, Missing: true},
			want: `readonly_mounts[2] is missing the required cache_duration_s field`,
		},
		{
			name: "provision marker",
			err:  &ErrProvisionMarker{Marker: "auth_token", Location: "top level"},
			want: `provision-side marker "auth_token" present at top level; the guest config carries no credential material`,
		},
		{
			name: "missing field",
			err:  &ErrMissingField{Field: "mounts"},
			want: `required field "mounts" is missing`,
		},
		{
			name: "decode",
			err:  &ErrDecode{Err: errors.New("boom")},
			want: `strict decode failed: boom`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestErrDecodeUnwrap proves ErrDecode participates in the standard error chain:
// the wrapped cause is reachable via errors.Unwrap and errors.Is, so callers can
// inspect the underlying decode failure without string matching.
func TestErrDecodeUnwrap(t *testing.T) {
	cause := errors.New("unexpected EOF")
	e := &ErrDecode{Err: cause}

	if got := e.Unwrap(); !errors.Is(got, cause) {
		t.Fatalf("Unwrap() = %v, want %v", got, cause)
	}
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is could not reach the wrapped cause through ErrDecode")
	}
}
