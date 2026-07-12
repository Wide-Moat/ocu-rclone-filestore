// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/cmdtest"
)

// TestMainExitsNonZeroOnError asserts main's failure path: an unknown flag makes
// mainWith return a parse error, so main prints the prefixed error to stderr and
// calls os.Exit(1). The shared helper re-execs this binary as the guarded child
// and asserts a non-zero exit carrying the "harness-init:" prefix.
func TestMainExitsNonZeroOnError(t *testing.T) {
	cmdtest.AssertMainExitsNonZero(t, "harness-init", "^TestMainExitsNonZeroOnError$", main)
}
