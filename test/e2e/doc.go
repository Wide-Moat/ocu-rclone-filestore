// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build e2e

// Package e2e holds the real end-to-end exercise for the mount binary. The
// test drives ordinary file operations against the FUSE mountpoints the compose
// harness brings up, proving the whole guest path: config -> mounter -> ocufs
// backend -> broker unix socket -> emitted bodies -> VFS -> kernel mount.
//
// The package is doubly fenced so it never affects the default test run:
//
//   - the //go:build e2e tag keeps it out of `go test ./...`, so it is not in
//     the coverage denominator and cannot move the coverage ratchet; and
//   - a runtime env gate (RCLONE_OCUFS_LIVE, mirroring the live mounter gate)
//     makes TestE2EExercise skip cleanly unless a live harness exports the
//     mountpoints and socket. Building with -tags e2e and running with the gate
//     unset is green-by-skip.
//
// The exercise sequence and every assertion are written now (wave 05-01). The
// live wave (05-02) supplies the real broker endpoint and the test-mode the
// throttle step needs, and flips the gate — it does not rewrite assertions.
package e2e
