// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const fixtureTemplate = `{
  "schema_version": "v1alpha",
  "service_url": "https://placeholder",
  "ca_cert_pem": "placeholder",
  "mounts": [
    {"destination": "/mnt/user-data/outputs/", "auth_token": "x", "filesystem_id": "fsrw", "readonly": false},
    {"destination": "/mnt/user-data/throttle/", "auth_token": "x", "filesystem_id": "fsthrottle", "readonly": false},
    {"destination": "/mnt/user-data/uploads/", "auth_token": "x", "filesystem_id": "fsro", "readonly": true}
  ]
}`

func TestRunGeneratesAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "guest-config.tmpl.json")
	if err := os.WriteFile(tmpl, []byte(fixtureTemplate), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	out := filepath.Join(dir, "shared")

	if err := run(out, "edge", 8450, tmpl); err != nil {
		t.Fatalf("run: %v", err)
	}

	// CA, per-service leaves, signing key, weak tokens, and the rendered config.
	for _, name := range []string{
		"ca.pem", "control-plane.signing.key.pem", "weak-tokens.json", "guest-config.json",
		"filestore.cert.pem", "filestore.key.pem", "edge.cert.pem", "edge.key.pem",
		"control-plane.cert.pem", "exchange.cert.pem",
	} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatalf("expected artifact %q missing: %v", name, err)
		}
	}

	// The rendered config carries the edge URL and a per-mount token.
	raw, err := os.ReadFile(filepath.Join(out, "guest-config.json"))
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("rendered config is not JSON: %v", err)
	}
	if cfg["service_url"] != "https://edge:8450" {
		t.Fatalf("service_url = %v, want the edge URL", cfg["service_url"])
	}

	// The weak-token map names every minted scope.
	tokRaw, err := os.ReadFile(filepath.Join(out, "weak-tokens.json"))
	if err != nil {
		t.Fatalf("read tokens: %v", err)
	}
	var tokens map[string]string
	if err := json.Unmarshal(tokRaw, &tokens); err != nil {
		t.Fatalf("tokens not JSON: %v", err)
	}
	for _, fsid := range []string{"fsrw", "fsthrottle", "fsro", "fsconf"} {
		if tokens[fsid] == "" {
			t.Fatalf("no weak token minted for %q", fsid)
		}
	}
}

func TestRunIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.json")
	if err := os.WriteFile(tmpl, []byte(fixtureTemplate), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	out := filepath.Join(dir, "shared")
	if err := run(out, "edge", 8450, tmpl); err != nil {
		t.Fatalf("first run: %v", err)
	}
	caFirst, err := os.ReadFile(filepath.Join(out, "ca.pem"))
	if err != nil {
		t.Fatalf("read ca after first run: %v", err)
	}
	// A second run must NOT rotate the CA (the idempotency guard).
	if err := run(out, "edge", 8450, tmpl); err != nil {
		t.Fatalf("second run: %v", err)
	}
	caSecond, err := os.ReadFile(filepath.Join(out, "ca.pem"))
	if err != nil {
		t.Fatalf("read ca after second run: %v", err)
	}
	if string(caFirst) != string(caSecond) {
		t.Fatal("the second run rotated the CA; harness-init must be idempotent")
	}
}

func TestRunRejectsMissingTemplate(t *testing.T) {
	dir := t.TempDir()
	if err := run(filepath.Join(dir, "shared"), "edge", 8450, filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("run accepted a missing fixture template")
	}
}

// TestMainWith drives the flag-parsing entry with valid flags so the success
// path is covered, and rejects an unknown flag.
func TestMainWith(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.json")
	if err := os.WriteFile(tmpl, []byte(fixtureTemplate), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	if err := mainWith([]string{"-out", filepath.Join(dir, "shared"), "-fixture-template", tmpl}); err != nil {
		t.Fatalf("mainWith: %v", err)
	}
	if err := mainWith([]string{"-nope"}); err == nil {
		t.Fatal("mainWith accepted an unknown flag")
	}
}
