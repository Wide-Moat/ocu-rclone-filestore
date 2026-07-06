// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command exchange serves the harness RFC-8693 token-exchange peer over TLS. It
// validates the inbound weak session JWT against the control-plane JWKS (fetched
// over TLS at startup) and, only on success, issues the real filestore
// credential as a SECOND ES256 JWT bound to the validated filesystem_id. It
// publishes that credential key set at /credential-jwks so the filestore can
// verify issued credentials without any shared in-process map — the seam that
// lets the exchange and filestore run as separate processes. Harness-only.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/exchange"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/serve"
)

const (
	cpIssuer   = "https://control-plane.test"
	cpAudience = "filestore-edge"

	credIssuer   = "https://exchange.test" //nolint:gosec // G101: an issuer identifier URL, not a credential
	credAudience = "filestore"
	credKid      = "kid-cred"

	// CredentialJWKSPath is where the exchange publishes the verification key set
	// for the credential JWTs it issues. The filestore fetches this at startup.
	credentialJWKSPath = "/credential-jwks" //nolint:gosec // G101: a URL path, not a credential
)

// staticJWKS adapts a fixed jwtmint.JWKS to the exchange.JWKSProvider interface,
// so the exchange validates weak JWTs against the control-plane key set fetched
// once at startup.
type staticJWKS struct{ keys jwtmint.JWKS }

func (s staticJWKS) JWKS() jwtmint.JWKS { return s.keys }

// runFn is the serving entry, seamed for tests.
var runFn = run

func main() {
	if err := mainWith(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "exchange: %v\n", err)
		os.Exit(1)
	}
}

// mainWith parses args with a local FlagSet and invokes runFn.
func mainWith(args []string) error {
	fs := flag.NewFlagSet("exchange", flag.ContinueOnError)
	addr := fs.String("addr", ":8447", "TLS listen address")
	certPath := fs.String("cert", "/shared/exchange.cert.pem", "leaf certificate PEM")
	keyPath := fs.String("key", "/shared/exchange.key.pem", "leaf private key PEM")
	caPath := fs.String("ca", "/shared/ca.pem", "CA PEM for dialing the control-plane")
	cpJWKSURL := fs.String("control-plane-jwks", "https://control-plane:8443/.well-known/jwks.json", "control-plane JWKS URL")
	credKeyPath := fs.String("credential-signing-key", "/shared/exchange.credential.key.pem",
		"stable PKCS#8 EC credential signing key PEM (shared with harness-init); empty generates an ephemeral key (NOT restart-durable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runFn(*addr, *certPath, *keyPath, *caPath, *cpJWKSURL, *credKeyPath)
}

func run(addr, certPath, keyPath, caPath, cpJWKSURL, credKeyPath string) error {
	return runCtx(context.Background(), addr, certPath, keyPath, caPath, cpJWKSURL, credKeyPath, nil)
}

// runCtx is run with an explicit context (for graceful test shutdown) and an
// onReady callback that reports the bound listener address once serving starts.
// Binding through serve.RunContext lets a caller pass "127.0.0.1:0" and learn
// the real port without a separate bind-close-reuse probe that could race.
func runCtx(ctx context.Context, addr, certPath, keyPath, caPath, cpJWKSURL, credKeyPath string, onReady func(net.Addr)) error {
	client, err := serve.CAClient(caPath)
	if err != nil {
		return err
	}

	// Fetch the control-plane JWKS so the exchange can verify weak JWTs.
	body, err := serve.FetchJWKS(context.Background(), client, cpJWKSURL, 90*time.Second)
	if err != nil {
		return err
	}
	var cpKeys jwtmint.JWKS
	if err := json.Unmarshal(body, &cpKeys); err != nil {
		return fmt.Errorf("parse control-plane JWKS: %w", err)
	}

	// The credential issuer: issues bound credential JWTs, publishes their JWKS.
	// A persisted key keeps the published JWKS stable across a restart, so an
	// edge that cached an exchanged credential or a filestore that cached this
	// JWKS does not desync and reject a valid token after the exchange reboots.
	// An empty path falls back to an ephemeral generated key (test convenience),
	// which is explicitly NOT restart-durable.
	credKey, err := loadCredentialSigningKey(credKeyPath)
	if err != nil {
		return err
	}
	issuerOpts := exchange.CredentialIssuerOptions{
		Issuer: credIssuer, Audience: credAudience, Kid: credKid,
	}
	var issuer *exchange.JWTCredentialIssuer
	if credKey != nil {
		issuer, err = exchange.NewJWTCredentialIssuerFromKey(credKey, issuerOpts)
	} else {
		issuer, err = exchange.NewJWTCredentialIssuer(issuerOpts)
	}
	if err != nil {
		return fmt.Errorf("build credential issuer: %w", err)
	}

	exSrv, err := exchange.NewServer(exchange.Options{
		JWKS:        staticJWKS{keys: cpKeys},
		Issuer:      cpIssuer,
		Audience:    cpAudience,
		Credentials: issuer,
	})
	if err != nil {
		return fmt.Errorf("build exchange server: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle(exchange.ExchangePath, exSrv.Handler())
	mux.HandleFunc(credentialJWKSPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(issuer.JWKS())
	})

	tlsConf, err := serve.LoadServerTLS(certPath, keyPath)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "exchange: serving token + credential JWKS on %s\n", addr)
	return serve.RunContext(ctx, addr, tlsConf, mux, onReady)
}

// loadCredentialSigningKey reads the stable PKCS#8 EC credential signing key
// harness-init writes to the shared volume. An empty path returns (nil, nil) so
// the caller falls back to an ephemeral generated key — the only place a missing
// path is acceptable, since an ephemeral key is not restart-durable. A present
// but unreadable or malformed path is a hard error, never a silent fallback.
func loadCredentialSigningKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the harness credential signing key on the shared volume
	if err != nil {
		return nil, fmt.Errorf("read credential signing key %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("credential signing key %q is not PEM", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse credential signing key %q: %w", path, err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("credential signing key %q is not an EC key", path)
	}
	return ecKey, nil
}
