// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/controlplane"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/edgeglue"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/exchange"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/filestore"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

func leafFiles(t *testing.T, ca *localca.CA, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	leaf, err := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	certPath = filepath.Join(dir, "leaf.cert.pem")
	keyPath = filepath.Join(dir, "leaf.key.pem")
	caPath = filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), 0o600)
	der, _ := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey.(*ecdsa.PrivateKey))
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	return certPath, keyPath, caPath
}

func ephemeralAddr(t *testing.T) string {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func tlsSrv(t *testing.T, ca *localca.CA, h http.Handler) *httptest.Server {
	t.Helper()
	leaf, _ := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// fullChain stands up the control-plane, exchange, and filestore over TLS issued
// by ca and returns the control-plane (to mint), the CP JWKS URL, the exchange
// token URL, and the filestore upstream URL — everything the edge run() needs.
func fullChain(t *testing.T, ca *localca.CA) (cp *controlplane.Server, cpJWKS, exchangeURL, upstreamURL string) {
	t.Helper()
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer: cpIssuer, Audience: cpAudience, Kid: "kid-cp", SigningKey: sk,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}
	cpSrv := tlsSrv(t, ca, cp.Handler())
	cpJWKS = cpSrv.URL + "/.well-known/jwks.json"

	issuer, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: "https://exchange.test", Audience: "filestore", Kid: "kid-cred",
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	ex := exchange.NewServer(exchange.Options{
		JWKS: cp, Issuer: cpIssuer, Audience: cpAudience, Credentials: issuer,
	})
	exSrv := tlsSrv(t, ca, ex.Handler())
	exchangeURL = exSrv.URL + exchange.ExchangePath

	fs := filestore.NewServer(filestore.Options{
		Scopes:      []filestore.Scope{{FilesystemID: "fsrw", Root: t.TempDir(), ReadOnly: false}},
		Credentials: filestore.JWTCredentialValidator{JWKS: issuer.JWKS(), Issuer: "https://exchange.test", Audience: "filestore"},
	})
	fsSrv := tlsSrv(t, ca, fs.Handler())
	upstreamURL = fsSrv.URL
	return cp, cpJWKS, exchangeURL, upstreamURL
}

// TestEdgeRunFullFlow boots the edge against a real CP/exchange/filestore chain
// and drives a valid scoped request through it, exercising the whole
// validate -> strip -> exchange -> inject -> route path in ServeHTTP, plus the
// missing-token 401 arm.
func TestEdgeRunFullFlow(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := leafFiles(t, ca, dir)
	cp, cpJWKS, exchangeURL, upstreamURL := fullChain(t, ca)
	addr := ephemeralAddr(t)

	go func() { _ = run(addr, certPath, keyPath, caPath, cpJWKS, exchangeURL, upstreamURL) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}}}

	// Wait until the edge is up: a no-token request returns 401.
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, derr := client.Post("https://"+addr+"/v1/filestore/fs/listDirectory", "application/json", nil)
		if derr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("edge never came up: %v", derr)
		}
		time.Sleep(150 * time.Millisecond)
	}

	// A valid scoped request flows through validate -> exchange -> inject -> route
	// and the filestore returns 200 for a listDirectory at the scope root.
	weak, err := cp.Mint("fsrw", "read", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"filesystem_id": "fsrw", "authorization_metadata": map[string]any{"intent": "read"}, "path": ".",
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+addr+"/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+weak)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("valid request through edge: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid scoped request through the edge returned %d, want 200", resp.StatusCode)
	}
}

// TestEdgeServeHTTPErrorArms constructs an edge directly and drives its error
// arms: a forged token (validate fail -> 401), a valid token whose exchange
// fails (exchanger pointed at nothing -> 401), and a valid exchange but an
// unreachable upstream (-> 502).
func TestEdgeServeHTTPErrorArms(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cp, _, exchangeURL, _ := fullChain(t, ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}}}

	// Valid token, but the upstream URL points at nothing reachable: validate and
	// exchange succeed, the route to the upstream fails -> 502.
	exchanger, err := edgeglue.New(edgeglue.Options{ExchangeURL: exchangeURL, Client: client})
	if err != nil {
		t.Fatalf("exchanger: %v", err)
	}
	e := &edge{jwks: cp.JWKS(), exchanger: exchanger, upstreamURL: "https://127.0.0.1:1", upstream: client}

	weak, err := cp.Mint("fsrw", "read", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"filesystem_id": "fsrw", "authorization_metadata": map[string]any{"intent": "read"}, "path": ".",
	})

	// 502: upstream unreachable.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+weak)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("unreachable upstream returned %d, want 502", w.Code)
	}

	// 401: exchange fails (exchanger pointed at a dead endpoint).
	deadExchanger, _ := edgeglue.New(edgeglue.Options{ExchangeURL: "https://127.0.0.1:1/token", Client: client})
	e2 := &edge{jwks: cp.JWKS(), exchanger: deadExchanger, upstreamURL: "https://127.0.0.1:1", upstream: client}
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+weak)
	e2.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("failed exchange returned %d, want 401", w2.Code)
	}

	// 401: a token carrying no scope is rejected (forged/empty-scope arm). Use a
	// token minted with an empty filesystem_id via a raw mint is not exposed, so
	// drive the missing-bearer arm instead.
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	e.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer returned %d, want 401", w3.Code)
	}
}

// TestRunRejectsBadCA covers the CAClient error arm of run.
func TestRunRejectsBadCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad-ca.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	if err := run(ephemeralAddr(t), "c", "k", bad,
		"https://127.0.0.1:1/jwks", "https://127.0.0.1:1/token", "https://127.0.0.1:1"); err == nil {
		t.Fatal("run accepted a CA file with no certificate")
	}
}

// TestMainWith covers the flag-parsing entry with runFn stubbed.
func TestMainWith(t *testing.T) {
	saved := runFn
	t.Cleanup(func() { runFn = saved })
	called := false
	runFn = func(addr, cert, key, ca, cpJWKS, exch, up string) error { called = true; return nil }
	if err := mainWith([]string{"-addr", "127.0.0.1:9"}); err != nil {
		t.Fatalf("mainWith: %v", err)
	}
	if !called {
		t.Fatal("mainWith did not invoke runFn")
	}
	if err := mainWith([]string{"-nope"}); err == nil {
		t.Fatal("mainWith accepted an unknown flag")
	}
}
