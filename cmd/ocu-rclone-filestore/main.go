// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-rclone-filestore is the guest-side mount binary. It parses a
// --config flag, loads and validates the guest mount config, and drives the
// mounter. Any error exits non-zero; a clean shutdown exits zero.
package main

import (
	"fmt"
	"os"
)

// main is a thin wrapper around run: it maps a non-nil run error to a non-zero
// exit code and a nil error to a zero exit. All logic lives in run so it stays
// testable without spawning a process.
func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-rclone-filestore:", err)
		os.Exit(1)
	}
}
