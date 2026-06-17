// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command edge is the LIVE storage egress edge: a TLS serving binary that, for
// every request, runs the same validate -> strip -> exchange -> inject -> route
// chain the deployment Envoy config (deploy/compose/envoy/envoy.yaml) expresses
// and the edgeswap harness proves. It is the live realisation of that chain for
// the network e2e graph, serving the per-filesystem_id keyed credential exchange
// the stock Envoy credential_injector defers to Phase F.
//
// For each request the edge:
//  1. VALIDATES the inbound weak session JWT against the control-plane JWKS
//     (issuer, audience, signature, expiry) — 401 on failure, never forwarded.
//  2. STRIPS the weak JWT (the inbound Authorization is never copied onward).
//  3. EXCHANGES the validated token for the real filestore credential via the
//     RFC-8693 exchange peer, KEYED on the validated filesystem_id and cached
//     per scope (edgeglue.Exchanger).
//  4. INJECTS the exchanged credential as the forwarded Authorization and ROUTES
//     to the filestore upstream over TLS.
//
// It does real JWKS verification, real RFC-8693 exchange, and real strip+inject
// — it is an honest live edge, not a mock. It serves a leaf chaining to the
// local CA whose PEM the guest carries as ca_cert_pem. Harness-only.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/edgeglue"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/serve"
)

const (
	cpIssuer   = "https://control-plane.test"
	cpAudience = "filestore-edge"
)

// maxRequestBytes bounds the buffered request body the edge forwards so a
// hostile client cannot exhaust memory. It is generous relative to the e2e's
// 9 MiB large-file chunked upload.
const maxRequestBytes = 1 << 30 // 1 GiB

// edge is the live serving-edge handler. It holds the control-plane JWKS to
// verify weak JWTs, an exchanger to trade them for real credentials keyed on
// filesystem_id, and a TLS client + base URL for the filestore upstream.
type edge struct {
	jwks        jwtmint.JWKS
	exchanger   *edgeglue.Exchanger
	upstreamURL string
	upstream    *http.Client
}

func (e *edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Stage 1: VALIDATE the inbound weak session JWT.
	authz := r.Header.Get("Authorization")
	weak := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	if weak == "" || weak == authz {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	claims, err := jwtmint.Verify(weak, e.jwks, cpIssuer, cpAudience, time.Now())
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if claims.FilesystemID == "" {
		http.Error(w, "token carries no scope", http.StatusUnauthorized)
		return
	}

	// Stage 3: EXCHANGE the validated token for the real credential, keyed on the
	// validated filesystem_id. (Stage 2 STRIP is realised below by building a
	// fresh forwarded request that never copies the inbound Authorization.)
	cred, err := e.exchanger.Resolve(r.Context(), claims.FilesystemID, weak)
	if err != nil {
		http.Error(w, "exchange failed", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		http.Error(w, "read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	// Stage 2 + 4: FRESH upstream request — the inbound Authorization is NOT
	// copied (the weak JWT is stripped); the exchanged credential is INJECTED in
	// its place, then routed to the filestore.
	//nolint:gosec // G704: this IS the egress edge — forwarding the request to the
	// FIXED operator-configured filestore upstream (e.upstreamURL) is its entire
	// purpose. The host is not client-controlled (only the path is, and the
	// filestore confines every path under the scope root); this is a deliberate
	// reverse proxy in a harness, not an SSRF sink.
	up, err := http.NewRequestWithContext(r.Context(), r.Method, e.upstreamURL+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build upstream request", http.StatusBadGateway)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		up.Header.Set("Content-Type", ct)
	}
	up.Header.Set("Authorization", "Bearer "+cred)

	resp, err := e.upstream.Do(up) //nolint:gosec // G704: deliberate edge forward to the fixed filestore upstream (see above)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// runFn is the serving entry, seamed for tests.
var runFn = run

func main() {
	if err := mainWith(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "edge: %v\n", err)
		os.Exit(1)
	}
}

// mainWith parses args with a local FlagSet and invokes runFn.
func mainWith(args []string) error {
	fs := flag.NewFlagSet("edge", flag.ContinueOnError)
	addr := fs.String("addr", ":8450", "TLS listen address")
	certPath := fs.String("cert", "/shared/edge.cert.pem", "leaf certificate PEM")
	keyPath := fs.String("key", "/shared/edge.key.pem", "leaf private key PEM")
	caPath := fs.String("ca", "/shared/ca.pem", "CA PEM for dialing the peers")
	cpJWKSURL := fs.String("control-plane-jwks", "https://control-plane:8443/.well-known/jwks.json", "control-plane JWKS URL")
	exchangeURL := fs.String("exchange-url", "https://exchange:8447/token", "exchange token endpoint URL")
	upstreamURL := fs.String("upstream-url", "https://filestore:8444", "filestore upstream base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runFn(*addr, *certPath, *keyPath, *caPath, *cpJWKSURL, *exchangeURL, *upstreamURL)
}

func run(addr, certPath, keyPath, caPath, cpJWKSURL, exchangeURL, upstreamURL string) error {
	client, err := serve.CAClient(caPath)
	if err != nil {
		return err
	}

	body, err := serve.FetchJWKS(context.Background(), client, cpJWKSURL, 90*time.Second)
	if err != nil {
		return err
	}
	var cpKeys jwtmint.JWKS
	if err := json.Unmarshal(body, &cpKeys); err != nil {
		return fmt.Errorf("parse control-plane JWKS: %w", err)
	}

	exchanger, err := edgeglue.New(edgeglue.Options{ExchangeURL: exchangeURL, Client: client})
	if err != nil {
		return fmt.Errorf("build exchanger: %w", err)
	}

	h := &edge{
		jwks:        cpKeys,
		exchanger:   exchanger,
		upstreamURL: upstreamURL,
		upstream:    client,
	}

	tlsConf, err := serve.LoadServerTLS(certPath, keyPath)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "edge: serving validate->strip->exchange->inject on %s -> %s\n", addr, upstreamURL)
	return serve.Run(addr, tlsConf, h)
}
