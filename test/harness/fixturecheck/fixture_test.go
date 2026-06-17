// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package fixturecheck asserts the rendered guest config — the template in the
// tree, filled with a real edge URL, a real CA PEM, and real minted weak JWTs —
// loads and validates through the production mountcfg loader and keeps the four
// canonical mount destinations and readonly flags. It proves the Task 3
// bringup-render contract without docker.
package fixturecheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/controlplane"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/fixture"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

// fixtureTemplatePath is the single-shape template the harness renders at
// bringup, relative to this test file (repo deploy/compose/fixtures).
const fixtureTemplatePath = "../../../deploy/compose/fixtures/guest-config.json"

// wantMounts is the canonical destination -> readonly map the four mounts must
// keep through rendering; the rendered config must not drift these.
var wantMounts = map[string]bool{
	"/mnt/user-data/outputs/":  false,
	"/mnt/user-data/outputs2/": false,
	"/mnt/user-data/throttle/": false,
	"/mnt/user-data/uploads/":  true,
}

func TestRenderedFixtureLoadsAndKeepsCanonicalMounts(t *testing.T) {
	raw, err := os.ReadFile(fixtureTemplatePath)
	if err != nil {
		t.Fatalf("read fixture template: %v", err)
	}

	// A real CA PEM (mountcfg requires a non-empty ca_cert_pem).
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	// Real minted weak JWTs per scope (the loader requires non-empty auth_token).
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer: "https://control-plane.test", Audience: "filestore-edge", Kid: "kid-cp",
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}
	tokens := map[string]string{}
	for _, fsid := range []string{"fsrw", "fsthrottle", "fsro"} {
		tok, mErr := cp.Mint(fsid, "read", false)
		if mErr != nil {
			t.Fatalf("mint %s: %v", fsid, mErr)
		}
		tokens[fsid] = tok
	}

	rendered, err := fixture.Render(raw, "https://edge:8450", string(ca.CertPEM()), tokens)
	if err != nil {
		t.Fatalf("render fixture: %v", err)
	}

	// Write it and load through the PRODUCTION loader, which validates the https
	// service_url, the non-empty ca_cert_pem, absolute destinations, and the
	// per-mount auth_token.
	out := filepath.Join(t.TempDir(), "guest-config.json")
	if err := os.WriteFile(out, rendered, 0o600); err != nil {
		t.Fatalf("write rendered: %v", err)
	}
	cfg, err := mountcfg.Load(out)
	if err != nil {
		t.Fatalf("rendered fixture failed the production loader: %v", err)
	}

	if cfg.ServiceURL != "https://edge:8450" {
		t.Fatalf("service_url = %q, want the edge URL", cfg.ServiceURL)
	}
	if cfg.CACertPEM == "" {
		t.Fatal("ca_cert_pem is empty after render")
	}
	if len(cfg.Mounts) != len(wantMounts) {
		t.Fatalf("rendered config has %d mounts, want %d", len(cfg.Mounts), len(wantMounts))
	}
	for _, m := range cfg.Mounts {
		wantRO, ok := wantMounts[m.Destination]
		if !ok {
			t.Fatalf("unexpected mount destination %q (canonical destinations drifted)", m.Destination)
		}
		if m.Readonly == nil {
			t.Fatalf("mount %q has a nil readonly flag after render", m.Destination)
		}
		if *m.Readonly != wantRO {
			t.Fatalf("mount %q readonly = %v, want %v", m.Destination, *m.Readonly, wantRO)
		}
		if m.AuthToken == "" {
			t.Fatalf("mount %q has an empty auth_token after render", m.Destination)
		}
	}
}
