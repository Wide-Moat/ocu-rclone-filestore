// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

import (
	"path/filepath"
	"testing"
)

// TestDeployFixtureLoads proves the shipped deploy fixture is the single
// mount-config shape this binary loads: it must parse and validate through
// Load, hold the top-level trust anchor and a per-mount session token on every
// mount, and carry both a read-write sink and a read-only input mount. This
// both pins the fixture to the contract and covers the held-credential and
// readonly-derivation accept paths end-to-end on a real shipped file.
func TestDeployFixtureLoads(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "compose", "fixtures", "guest-config.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("deploy fixture must load through the single-shape loader, got %v", err)
	}

	if cfg.CACertPEM == "" {
		t.Fatal("deploy fixture must hold a top-level ca_cert_pem")
	}

	var sawReadWrite, sawReadOnly bool
	var roDest string
	sawRWOutputs := false
	for i, m := range cfg.Mounts {
		if m.AuthToken == "" {
			t.Fatalf("mounts[%d]: deploy fixture mount must hold a per-mount auth_token", i)
		}
		if m.Readonly == nil {
			t.Fatalf("mounts[%d]: deploy fixture mount must carry the readonly flag", i)
		}
		if *m.Readonly {
			sawReadOnly = true
			roDest = m.Destination
		} else {
			sawReadWrite = true
			if m.Destination == canonRWOutputsDest {
				sawRWOutputs = true
			}
		}
	}
	if !sawReadWrite {
		t.Fatal("deploy fixture must carry at least one read-write (readonly:false) mount")
	}
	if !sawReadOnly {
		t.Fatal("deploy fixture must carry at least one read-only (readonly:true) mount")
	}

	// Pin the canonical mountpoints so the deploy harness can never silently
	// drift off the agreed destination scheme: the read-only input mount lands
	// at the canonical uploads path and a read-write mount lands at the
	// canonical outputs path. The whole live e2e harness — the runsc entrypoint
	// mkdirs, the compose OCU_E2E_*_MOUNT env, and the exercise mounts/reads —
	// keys off these exact strings, so a drift here desyncs the harness.
	if roDest != canonRODest {
		t.Fatalf("deploy fixture read-only destination = %q, want canonical %q", roDest, canonRODest)
	}
	if !sawRWOutputs {
		t.Fatalf("deploy fixture must carry a read-write mount at the canonical outputs destination %q", canonRWOutputsDest)
	}
}

// The canonical e2e mountpoints. The deploy fixture, the runsc entrypoint, and
// the compose env must all agree on these exact strings, or the live harness
// mounts and reads at desynced paths.
const (
	canonRODest        = "/mnt/user-data/uploads/"
	canonRWOutputsDest = "/mnt/user-data/outputs/"
)
