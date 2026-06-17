// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command controlplane serves the harness control-plane peer over TLS: the
// /mint endpoint that issues weak session JWTs and the JWKS the edge fetches to
// validate them. It signs with the STABLE key harness-init generated, so the
// weak JWTs baked into the guest fixture verify against the JWKS this process
// publishes. It is harness-only and never linked into the guest binary.
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/controlplane"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/serve"
)

const (
	cpIssuer   = "https://control-plane.test"
	cpAudience = "filestore-edge"
	cpKid      = "kid-cp"
)

// runFn is the serving entry, seamed so a test can substitute a stub and drive
// mainWith without binding a real port.
var runFn = run

func main() {
	if err := mainWith(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "controlplane: %v\n", err)
		os.Exit(1)
	}
}

// mainWith parses args with a local FlagSet (no global state) and invokes runFn,
// so it is callable from a test without racing the package flag set.
func mainWith(args []string) error {
	fs := flag.NewFlagSet("controlplane", flag.ContinueOnError)
	addr := fs.String("addr", ":8443", "TLS listen address")
	certPath := fs.String("cert", "/shared/control-plane.cert.pem", "leaf certificate PEM")
	keyPath := fs.String("key", "/shared/control-plane.key.pem", "leaf private key PEM")
	signingKeyPath := fs.String("signing-key", "/shared/control-plane.signing.key.pem", "the stable ES256 signing key PEM (shared with harness-init)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runFn(*addr, *certPath, *keyPath, *signingKeyPath)
}

func run(addr, certPath, keyPath, signingKeyPath string) error {
	signingKey, err := loadSigningKey(signingKeyPath)
	if err != nil {
		return err
	}
	srv, err := controlplane.NewServer(controlplane.Options{
		Issuer:     cpIssuer,
		Audience:   cpAudience,
		Kid:        cpKid,
		SigningKey: signingKey,
	})
	if err != nil {
		return fmt.Errorf("build control-plane: %w", err)
	}
	tlsConf, err := serve.LoadServerTLS(certPath, keyPath)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "controlplane: serving mint + JWKS on %s\n", addr)
	return serve.Run(addr, tlsConf, srv.Handler())
}

// loadSigningKey reads the PKCS#8 EC signing key PEM harness-init wrote.
func loadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the harness signing key on the shared volume
	if err != nil {
		return nil, fmt.Errorf("read signing key %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("signing key %q is not PEM", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key %q: %w", path, err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %q is not an EC key", path)
	}
	return ecKey, nil
}
