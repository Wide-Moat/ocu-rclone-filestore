// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"os"
	"testing"
)

// TestLiveMultimount is the Phase-5 entry point: the real multimount exercise
// against a broker with /dev/fuse + SYS_ADMIN. It is gated behind
// RCLONE_OCUFS_LIVE and SKIPPED in Phase-4 CI (which has no /dev/fuse), mirroring
// the Phase-3 RCLONE_OCUFS_LIVE / fstests gate.
//
// It uses ONLY the exported mounter API (New(opts...).Mount and the With*
// options), so it compiles on darwin/arm64 with NO build tag — the kernel mount
// only runs when the gate is set on a supported host.
//
// When enabled (Phase 5) it will:
//   - mount >=2 filesystems with distinct VFS options against a live/fake broker,
//   - assert both mounts are up,
//   - assert a read-only mount rejects a write (EROFS),
//   - assert the ready-file appears only after all mounts are up,
//   - assert a SIGTERM tears down every mount.
//
// Phase-4 CI does NOT prove SC3's live round-trip; the policy is proven over the
// fake seam (04-01) and the wiring without /dev/fuse (04-02). SC3's live
// round-trip is the Phase-5 gate.
func TestLiveMultimount(t *testing.T) {
	if os.Getenv("RCLONE_OCUFS_LIVE") == "" {
		t.Skip("RCLONE_OCUFS_LIVE not set — real multimount exercise deferred to Phase 5 (compose e2e with /dev/fuse + SYS_ADMIN against a broker)")
	}

	// Phase-5 hook: the live broker wiring, the >=2-mount config, the EROFS
	// assertion on the read-only mount, the ready-file ordering check, and the
	// SIGTERM teardown land here. They are driven exclusively through the
	// exported mounter API:
	//
	//   sig := make(chan os.Signal, 1)
	//   m := New(
	//       WithReadiness(ReadinessConfig{ReadyFilePath: readyPath}),
	//       WithSignals(sig),
	//   )
	//   // The transport (service_url + per-mount auth_token + ca_cert_pem) is
	//   // carried in cfg; no socket option is needed.
	//   ... go m.Mount(cfg); assert both up; assert RO write -> EROFS;
	//   ... assert readyPath appears only after all up; sig <- SIGTERM; assert teardown.
	t.Skip("RCLONE_OCUFS_LIVE set but the Phase-5 live broker harness is not yet wired; this is the Phase-5 entry point")
}
