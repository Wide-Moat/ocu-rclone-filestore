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
	"encoding/json"
	"flag"
	"fmt"
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runFn(*addr, *certPath, *keyPath, *caPath, *cpJWKSURL)
}

func run(addr, certPath, keyPath, caPath, cpJWKSURL string) error {
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
	issuer, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: credIssuer, Audience: credAudience, Kid: credKid,
	})
	if err != nil {
		return fmt.Errorf("build credential issuer: %w", err)
	}

	exSrv := exchange.NewServer(exchange.Options{
		JWKS:        staticJWKS{keys: cpKeys},
		Issuer:      cpIssuer,
		Audience:    cpAudience,
		Credentials: issuer,
	})

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
	return serve.Run(addr, tlsConf, mux)
}
