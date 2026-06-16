// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command conformance-bootstrap renders the rclone config the conformance
// runner uses, then the runner invokes the conformance test. It writes an ocufs
// remote dialing the edge over TLS with the new transport — service_url,
// auth_token (the minted fsconf weak JWT), filesystem_id, and the CA PEM trust
// anchor — replacing the dead unix-socket remote. It uses rclone's own config
// writer so the multi-line CA PEM is encoded in a form rclone re-reads exactly.
//
// Routing conformance THROUGH the edge (full-path parity, DD-5) exercises the
// same validate -> exchange -> inject chain the e2e exercise uses, so the
// conformance round-trips traverse the live edge rather than a transport-
// isolated shortcut. Harness-only.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configfile"
)

func main() {
	remote := flag.String("remote", "fsconf", "the rclone remote name to write")
	out := flag.String("out", "/etc/ocu/conformance-rclone.conf", "the rclone config path to render")
	serviceURL := flag.String("service-url", "https://edge:8450", "the edge service_url the remote dials")
	filesystemID := flag.String("filesystem-id", "fsconf", "the conformance scope")
	caPath := flag.String("ca", "/shared/ca.pem", "CA PEM trust anchor path")
	tokensPath := flag.String("tokens", "/shared/weak-tokens.json", "minted weak-token map written by harness-init")
	flag.Parse()

	if err := run(*remote, *out, *serviceURL, *filesystemID, *caPath, *tokensPath); err != nil {
		fmt.Fprintf(os.Stderr, "conformance-bootstrap: %v\n", err)
		os.Exit(1)
	}
}

func run(remote, out, serviceURL, filesystemID, caPath, tokensPath string) error {
	caPEM, err := os.ReadFile(caPath) //nolint:gosec // G304: harness CA path on the shared volume
	if err != nil {
		return fmt.Errorf("read CA %q: %w", caPath, err)
	}

	tokensRaw, err := os.ReadFile(tokensPath) //nolint:gosec // G304: harness token map on the shared volume
	if err != nil {
		return fmt.Errorf("read tokens %q: %w", tokensPath, err)
	}
	var tokens map[string]string
	if err := json.Unmarshal(tokensRaw, &tokens); err != nil {
		return fmt.Errorf("parse tokens: %w", err)
	}
	tok, ok := tokens[filesystemID]
	if !ok || tok == "" {
		return fmt.Errorf("no minted weak JWT for conformance scope %q", filesystemID)
	}

	// Write the remote through rclone's own config writer so the multi-line CA
	// PEM is encoded in a form rclone re-reads exactly.
	if err := os.WriteFile(out, []byte{}, 0o600); err != nil {
		return fmt.Errorf("create config %q: %w", out, err)
	}
	if err := config.SetConfigPath(out); err != nil {
		return fmt.Errorf("set config path: %w", err)
	}
	configfile.Install()
	config.FileSetValue(remote, "type", "ocufs")
	config.FileSetValue(remote, "service_url", serviceURL)
	config.FileSetValue(remote, "filesystem_id", filesystemID)
	config.FileSetValue(remote, "auth_token", tok)
	config.FileSetValue(remote, "ca_cert_pem", string(caPEM))
	config.FileSetValue(remote, "read_only", "false")
	config.SaveConfig()

	fmt.Fprintf(os.Stdout, "conformance-bootstrap: wrote remote %q dialing %s (scope %s) to %s\n", remote, serviceURL, filesystemID, out)
	return nil
}
