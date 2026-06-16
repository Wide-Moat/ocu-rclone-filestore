// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// renderGuestConfig loads the single-shape guest config template, replaces the
// top-level service_url and ca_cert_pem, and sets each mount's auth_token to the
// weak JWT minted for that mount's filesystem_id. The destinations, readonly
// flags, and VFS knobs are preserved exactly — only the three values that cannot
// be known until bringup (the edge URL, the trust anchor, the minted tokens) are
// filled in. The result is written to outPath for the mount to read.
//
// The template is parsed into an ordered-preserving generic map so unknown
// fields (schema_version, cache knobs, perms) round-trip untouched.
func renderGuestConfig(templatePath, outPath, serviceURL, caCertPEM string, tokens map[string]string) error {
	raw, err := os.ReadFile(templatePath) //nolint:gosec // G304: templatePath is the harness fixture path, not attacker-controlled
	if err != nil {
		return fmt.Errorf("read fixture template %q: %w", templatePath, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse fixture template: %w", err)
	}

	cfg["service_url"] = serviceURL
	cfg["ca_cert_pem"] = caCertPEM

	mountsAny, ok := cfg["mounts"].([]any)
	if !ok {
		return fmt.Errorf("fixture template has no mounts array")
	}
	for i, m := range mountsAny {
		mount, ok := m.(map[string]any)
		if !ok {
			return fmt.Errorf("mount %d is not an object", i)
		}
		fsid, ok := mount["filesystem_id"].(string)
		if !ok || fsid == "" {
			return fmt.Errorf("mount %d has no filesystem_id", i)
		}
		tok, ok := tokens[fsid]
		if !ok {
			return fmt.Errorf("no minted weak JWT for mount %d filesystem_id %q", i, fsid)
		}
		mount["auth_token"] = tok
	}

	rendered, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rendered config: %w", err)
	}
	rendered = append(rendered, '\n')
	if err := os.WriteFile(outPath, rendered, 0o644); err != nil { //nolint:gosec // G306: rendered guest config on an ephemeral shared volume the mount reads
		return fmt.Errorf("write rendered config %q: %w", outPath, err)
	}
	return nil
}
