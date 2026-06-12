// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build !(linux || (darwin && amd64))

package mounter

import (
	"errors"
	"testing"
)

// TestDefaultRealSeamUnsupportedFailsClosed asserts that on a platform/arch
// where the kernel mount method is unavailable, the production seam constructor
// returns the typed fail-closed error rather than a silent no-op seam (MNT-02).
// This file carries the negated build tag, so it runs exactly where the mount
// is unsupported — including the darwin/arm64 dev host.
func TestDefaultRealSeamUnsupportedFailsClosed(t *testing.T) {
	seam, err := defaultRealSeam()
	if seam != nil {
		t.Fatalf("defaultRealSeam() seam = %v; want nil on an unsupported platform", seam)
	}
	if !errors.Is(err, errMountMethodUnavailable) {
		t.Fatalf("defaultRealSeam() error = %v; want errMountMethodUnavailable", err)
	}
}
