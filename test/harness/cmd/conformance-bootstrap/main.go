// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command conformance-bootstrap renders the rclone remote the conformance
// runner uses as a set of RCLONE_CONFIG_<REMOTE>_<KEY> environment overrides,
// emitted to a file the runner shell sources before invoking the suite. It
// configures an ocufs remote dialing the edge over TLS with the new transport —
// service_url, auth_token (the minted fsconf weak JWT), filesystem_id, and the
// CA PEM trust anchor — replacing the dead unix-socket remote.
//
// Env-var overrides are used rather than an rclone config FILE because the CA
// trust anchor is a MULTI-LINE PEM: rclone's file parser does not round-trip a
// bare multi-line value, but fs.NewFs resolves backend options from the
// RCLONE_CONFIG_* env overrides cleanly, newlines and all. Routing conformance
// THROUGH the edge (full-path parity, DD-5) exercises the same
// validate -> exchange -> inject chain the e2e exercise uses. Harness-only.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	remote := flag.String("remote", "fsconf", "the rclone remote name (uppercased into the env override prefix)")
	out := flag.String("out", "/tmp/conformance-env.sh", "the sourceable env file to write")
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

	// rclone reads backend options from RCLONE_CONFIG_<REMOTE>_<KEY>, uppercased.
	prefix := "RCLONE_CONFIG_" + strings.ToUpper(remote) + "_"
	overrides := map[string]string{
		prefix + "TYPE":          "ocufs",
		prefix + "SERVICE_URL":   serviceURL,
		prefix + "FILESYSTEM_ID": filesystemID,
		prefix + "AUTH_TOKEN":    tok,
		prefix + "CA_CERT_PEM":   string(caPEM),
		prefix + "READ_ONLY":     "false",
	}

	var b strings.Builder
	b.WriteString("# rendered by conformance-bootstrap; source before running the suite\n")
	for k, v := range overrides {
		// Single-quote the value and escape any embedded single quote so the
		// multi-line PEM survives shell sourcing intact.
		b.WriteString("export ")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(shellSingleQuote(v))
		b.WriteString("\n")
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("write env file %q: %w", out, err)
	}

	fmt.Fprintf(os.Stdout, "conformance-bootstrap: wrote %d rclone env overrides for remote %q dialing %s (scope %s) to %s\n",
		len(overrides), remote, serviceURL, filesystemID, out)
	return nil
}

// shellSingleQuote wraps s in single quotes, escaping embedded single quotes via
// the standard '\” idiom, so a multi-line value survives `source` intact.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
