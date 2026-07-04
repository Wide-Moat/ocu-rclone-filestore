// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command filestored serves the harness REST filestore peer over TLS. It hosts
// the four e2e scopes (fsrw RW, fsro RO, fsthrottle RW with a per-op ceiling,
// fsconf RW for conformance) on local-volume roots, and validates the injected
// post-exchange credential against the exchange's credential JWKS (fetched over
// TLS at startup) — no shared in-process map, so it runs as its own process. The
// fsthrottle scope carries a 2-ops/s, burst-2 per-op token bucket so an
// over-budget metadata burst is refused with the unmapped throttle status the
// guest surfaces as EIO (the SC2 signal). Harness-only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/filestore"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/serve"
)

const (
	credIssuer   = "https://exchange.test" //nolint:gosec // G101: an issuer identifier URL, not a credential
	credAudience = "filestore"

	fsRW       = "fsrw"
	fsRO       = "fsro"
	fsThrottle = "fsthrottle"
	fsConf     = "fsconf"
)

// runFn is the serving entry, seamed for tests.
var runFn = run

func main() {
	if err := mainWith(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "filestored: %v\n", err)
		os.Exit(1)
	}
}

// mainWith parses args with a local FlagSet and invokes runFn.
func mainWith(args []string) error {
	fs := flag.NewFlagSet("filestored", flag.ContinueOnError)
	addr := fs.String("addr", ":8444", "TLS listen address")
	certPath := fs.String("cert", "/shared/filestore.cert.pem", "leaf certificate PEM")
	keyPath := fs.String("key", "/shared/filestore.key.pem", "leaf private key PEM")
	caPath := fs.String("ca", "/shared/ca.pem", "CA PEM for dialing the exchange")
	credJWKSURL := fs.String("credential-jwks", "https://exchange:8447/credential-jwks", "exchange credential-JWKS URL")
	root := fs.String("root", "/workspace", "engine root; each scope lives in a subdirectory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runFn(*addr, *certPath, *keyPath, *caPath, *credJWKSURL, *root)
}

func run(addr, certPath, keyPath, caPath, credJWKSURL, root string) error {
	client, err := serve.CAClient(caPath)
	if err != nil {
		return err
	}

	// Fetch the exchange's credential JWKS so injected credentials can be
	// verified with no shared map.
	body, err := serve.FetchJWKS(context.Background(), client, credJWKSURL, 90*time.Second)
	if err != nil {
		return err
	}
	var credKeys jwtmint.JWKS
	if err := json.Unmarshal(body, &credKeys); err != nil {
		return fmt.Errorf("parse credential JWKS: %w", err)
	}

	// One local-volume directory per scope under the engine root. Objects are
	// stored FLAT under each scope root (no per-fsid nesting), so the e2e
	// broker-persistence assertions map the mount-relative path 1:1 to the path
	// under the scope root.
	scopes := []filestore.Scope{
		{FilesystemID: fsRW, Root: filepath.Join(root, fsRW), ReadOnly: false},
		{FilesystemID: fsRO, Root: filepath.Join(root, fsRO), ReadOnly: true},
		{FilesystemID: fsThrottle, Root: filepath.Join(root, fsThrottle), ReadOnly: false},
		{FilesystemID: fsConf, Root: filepath.Join(root, fsConf), ReadOnly: false},
	}
	for _, sc := range scopes {
		if mkErr := os.MkdirAll(sc.Root, 0o750); mkErr != nil {
			return fmt.Errorf("create scope root %q: %w", sc.Root, mkErr)
		}
	}

	srv, err := filestore.NewServer(filestore.Options{
		Scopes: scopes,
		Credentials: filestore.JWTCredentialValidator{
			JWKS: credKeys, Issuer: credIssuer, Audience: credAudience,
		},
		// SC2: a per-op token bucket on the throttle scope ONLY. 2 ops/s, burst 2:
		// a setup mkdir (plus its parent-dir list) fits the budget, a 6-write burst
		// overflows it, and refused ops surface as EIO at the guest while the bucket
		// refills so a caller that backs off recovers.
		PerOpThrottle: &filestore.PerOpThrottle{
			FilesystemID: fsThrottle, Rate: 2, Burst: 2,
		},
	})
	if err != nil {
		return fmt.Errorf("filestored: build server: %w", err)
	}

	tlsConf, err := serve.LoadServerTLS(certPath, keyPath)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "filestored: serving %d scopes on %s (root %s)\n", len(scopes), addr, root)
	return serve.Run(addr, tlsConf, srv.Handler())
}
