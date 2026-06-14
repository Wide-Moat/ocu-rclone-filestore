// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// TestIsAllDigits exercises every branch of the unitless-ByteSize detector,
// including the empty-string guard (an empty value must NOT be treated as
// all-digits — it must never gain a "B" suffix and parse as a bare unit) and the
// first-non-digit short-circuit.
func TestIsAllDigits(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},       // empty: the guard returns false
		{"0", true},       // single digit
		{"1048576", true}, // multi-digit unitless integer
		{"256M", false},   // trailing unit suffix
		{"1G", false},     // leading digit, unit suffix
		{"M256", false},   // leading non-digit short-circuits
		{"12 34", false},  // embedded space is not a digit
		{"1.5", false},    // decimal point is not a digit
		{"-5", false},     // sign is not a digit
		{"00007", true},   // leading zeros are still all digits
		{"٣", false},      // non-ASCII digit rune is rejected
	}
	for _, c := range cases {
		if got := isAllDigits(c.in); got != c.want {
			t.Errorf("isAllDigits(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

// TestBuildVFSOptionsEmptySizeNotCoercedToBytes pins the contract-level reason
// the empty-string guard exists: an empty vfs_cache_max_size must not silently
// become "B" (a bare unit) — it surfaces a parse error from fs.SizeSuffix.Set
// rather than being coerced. (A validated config never carries an empty size;
// this guards a hand-built one.)
func TestBuildVFSOptionsEmptySizeNotCoercedToBytes(t *testing.T) {
	m := writableMount()
	m.VfsCacheMaxSize = ""
	if _, err := buildVFSOptions(m, false); err == nil {
		t.Error("buildVFSOptions with empty vfs_cache_max_size = nil error; want a parse error, not a silent bytes coercion")
	}
}

// TestBuildVFSOptionsBadDirPerms covers the dir_perms parse-error branch: a
// non-octal value makes vfscommon.FileMode.Set reject it and buildVFSOptions
// returns a wrapped error naming the field. A validated config never carries a
// malformed perm; this guards a hand-built one.
func TestBuildVFSOptionsBadDirPerms(t *testing.T) {
	m := writableMount()
	m.DirPerms = "8888" // not octal
	_, err := buildVFSOptions(m, false)
	if err == nil {
		t.Fatal("buildVFSOptions with bad dir_perms = nil error; want a parse error")
	}
	if !strings.Contains(err.Error(), "dir_perms") {
		t.Errorf("error %q does not name the dir_perms field", err.Error())
	}
}

// TestBuildVFSOptionsBadFilePerms covers the file_perms parse-error branch with
// a non-octal value, the sibling of the dir_perms case.
func TestBuildVFSOptionsBadFilePerms(t *testing.T) {
	m := writableMount()
	m.FilePerms = "not-octal"
	_, err := buildVFSOptions(m, false)
	if err == nil {
		t.Fatal("buildVFSOptions with bad file_perms = nil error; want a parse error")
	}
	if !strings.Contains(err.Error(), "file_perms") {
		t.Errorf("error %q does not name the file_perms field", err.Error())
	}
}

// TestBuildOcufsConfigmapMissingFilesystemID covers the buildOcufsConfigmap
// guard for a mount with no scope handle: with neither memory_store_id nor a
// non-empty filesystem_id, the configmap cannot be scoped and the call hard-
// fails rather than building an unscoped mount.
func TestBuildOcufsConfigmapMissingFilesystemID(t *testing.T) {
	m := mountcfg.Mount{Destination: "/mnt/w"} // no FilesystemID, no MemoryStoreID
	if _, err := buildOcufsConfigmap(m, false, "/run/x.sock"); err == nil {
		t.Fatal("buildOcufsConfigmap with no filesystem_id = nil error; want the required-id hard error")
	}

	empty := mountcfg.Mount{Destination: "/mnt/w", FilesystemID: ptrStr("")}
	if _, err := buildOcufsConfigmap(empty, false, "/run/x.sock"); err == nil {
		t.Fatal("buildOcufsConfigmap with empty filesystem_id = nil error; want the required-id hard error")
	}
}
