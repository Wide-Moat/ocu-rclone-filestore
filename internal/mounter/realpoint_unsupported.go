// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build !(linux || (darwin && amd64))

package mounter

// defaultRealSeam is the fail-closed production seam constructor on a platform
// or architecture where the kernel mount method is unavailable. It returns the
// typed unsupported-platform error so the session fails closed and main exits
// non-zero — never a silent no-op mount (MNT-02). This keeps `go build ./...`
// green on every target while the binary refuses to mount where it cannot.
func defaultRealSeam() (pointMounter, error) {
	return nil, errMountMethodUnavailable
}
