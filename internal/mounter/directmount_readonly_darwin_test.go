// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build darwin && amd64

package mounter

import (
	"slices"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// assertReadOnlyExpressed pins the darwin/amd64 build-convenience read-only
// expression: that leg honours the "ro" option string and does not take the
// linux mount(2) flag path, so read-only is carried as an option string here.
func assertReadOnlyExpressed(t *testing.T, mo fuse.MountOptions) {
	t.Helper()
	if !slices.Contains(mo.Options, "ro") {
		t.Fatalf("option strings %v do not carry \"ro\": the darwin leg expresses read-only via the option string", mo.Options)
	}
}
