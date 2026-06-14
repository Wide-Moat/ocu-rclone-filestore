// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build darwin && amd64

package mounter

import "github.com/hanwen/go-fuse/v2/fuse"

// applyReadOnly expresses a read-only mount on the darwin/amd64 build-
// convenience leg. That leg is never the production guest and does not reach
// the linux mount(2) flag path; its FUSE stack honours the "ro" option string,
// so read-only is carried as a returned option string here. The MS_RDONLY flag
// constant is linux-only, so the flag-based form lives in the linux file.
func applyReadOnly(_ *fuse.MountOptions, readOnly bool) []string {
	if !readOnly {
		return nil
	}
	return []string{"ro"}
}
