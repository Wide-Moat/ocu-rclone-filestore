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
	for i, m := range cfg.Mounts {
		if m.AuthToken == "" {
			t.Fatalf("mounts[%d]: deploy fixture mount must hold a per-mount auth_token", i)
		}
		if m.Readonly == nil {
			t.Fatalf("mounts[%d]: deploy fixture mount must carry the readonly flag", i)
		}
		if *m.Readonly {
			sawReadOnly = true
		} else {
			sawReadWrite = true
		}
	}
	if !sawReadWrite {
		t.Fatal("deploy fixture must carry at least one read-write (readonly:false) mount")
	}
	if !sawReadOnly {
		t.Fatal("deploy fixture must carry at least one read-only (readonly:true) mount")
	}
}
