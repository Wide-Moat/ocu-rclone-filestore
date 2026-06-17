// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package fixture renders the single-shape guest config from a template at
// bringup, filling in only the three values that cannot be known ahead of time:
// the edge service_url the guest dials, the CA PEM trust anchor, and the per-
// mount weak session JWT used as auth_token. Destinations, readonly flags, and
// VFS knobs are preserved exactly. It is shared by cmd/harness-init and the
// fixture test so both render identically. Harness-only.
package fixture

import (
	"encoding/json"
	"fmt"
	"os"
)

// Render loads the single-shape guest config template, replaces the top-level
// service_url and ca_cert_pem, and sets each mount's auth_token to the weak JWT
// minted for that mount's filesystem_id (looked up in tokens). It returns the
// rendered JSON bytes. Unknown fields round-trip untouched.
func Render(templateBytes []byte, serviceURL, caCertPEM string, tokens map[string]string) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(templateBytes, &cfg); err != nil {
		return nil, fmt.Errorf("fixture: parse template: %w", err)
	}

	cfg["service_url"] = serviceURL
	cfg["ca_cert_pem"] = caCertPEM

	mountsAny, ok := cfg["mounts"].([]any)
	if !ok {
		return nil, fmt.Errorf("fixture: template has no mounts array")
	}
	for i, m := range mountsAny {
		mount, ok := m.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("fixture: mount %d is not an object", i)
		}
		fsid, ok := mount["filesystem_id"].(string)
		if !ok || fsid == "" {
			return nil, fmt.Errorf("fixture: mount %d has no filesystem_id", i)
		}
		tok, ok := tokens[fsid]
		if !ok {
			return nil, fmt.Errorf("fixture: no minted weak JWT for mount %d filesystem_id %q", i, fsid)
		}
		mount["auth_token"] = tok
	}

	rendered, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("fixture: marshal rendered config: %w", err)
	}
	return append(rendered, '\n'), nil
}

// RenderFile reads the template at templatePath, renders it, and writes the
// result to outPath.
func RenderFile(templatePath, outPath, serviceURL, caCertPEM string, tokens map[string]string) error {
	raw, err := os.ReadFile(templatePath) //nolint:gosec // G304: templatePath is the harness fixture path
	if err != nil {
		return fmt.Errorf("fixture: read template %q: %w", templatePath, err)
	}
	rendered, err := Render(raw, serviceURL, caCertPEM, tokens)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, rendered, 0o644); err != nil { //nolint:gosec // G306: rendered guest config on an ephemeral shared volume the mount reads
		return fmt.Errorf("fixture: write %q: %w", outPath, err)
	}
	return nil
}
