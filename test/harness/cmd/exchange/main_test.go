// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/serve"
)

// leafFiles writes a CA, a localhost leaf, and the CA path into a dir.
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

// startControlPlane stands up a control-plane over TLS issued by ca and returns
// its JWKS URL.
func startControlPlane(t *testing.T, ca *localca.CA) string {
	t.Helper()
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer: cpIssuer, Audience: cpAudience, Kid: "kid-cp", SigningKey: sk,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}
	leaf, _ := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	srv := httptest.NewUnstartedServer(cp.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL + "/.well-known/jwks.json"
}

func ephemeralAddr(t *testing.T) string {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestExchangeRunServesCredentialJWKS(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := leafFiles(t, ca, dir)
	cpJWKS := startControlPlane(t, ca)
	addr := ephemeralAddr(t)

	go func() { _ = run(addr, certPath, keyPath, caPath, cpJWKS, "") }()

	client, err := serve.CAClient(caPath)
	if err != nil {
		t.Fatalf("CAClient: %v", err)
	}
	body, err := serve.FetchJWKS(context.Background(), client, "https://"+addr+credentialJWKSPath, 10*time.Second)
	if err != nil {
		t.Fatalf("exchange credential JWKS never came up: %v", err)
	}
	var keys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &keys); err != nil {
		t.Fatalf("credential JWKS not JSON: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Fatal("credential JWKS published no keys")
	}
	_ = http.StatusOK
}

// TestStaticJWKSAdapter covers the staticJWKS provider adapter directly.
func TestStaticJWKSAdapter(t *testing.T) {
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer: cpIssuer, Audience: cpAudience, Kid: "kid-cp", SigningKey: sk,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}
	adapter := staticJWKS{keys: cp.JWKS()}
	if len(adapter.JWKS().Keys) != 1 {
		t.Fatalf("staticJWKS returned %d keys, want 1", len(adapter.JWKS().Keys))
	}
}

// TestRunRejectsBadCA covers the CAClient error arm of run.
func TestRunRejectsBadCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad-ca.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	if err := run(ephemeralAddr(t), "c", "k", bad, "https://127.0.0.1:1/jwks", ""); err == nil {
		t.Fatal("run accepted a CA file with no certificate")
	}
}

// TestMainWith covers the flag-parsing entry with runFn stubbed.
func TestMainWith(t *testing.T) {
	saved := runFn
	t.Cleanup(func() { runFn = saved })
	called := false
	runFn = func(addr, cert, key, ca, cpJWKS, credKey string) error { called = true; return nil }
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

// TestLoadCredentialSigningKey drives every arm of loadCredentialSigningKey: the
// empty-path ephemeral fallback, a present-and-valid PKCS#8 EC key, and the four
// failure arms (unreadable path, non-PEM bytes, parseable-but-not-PKCS#8 PEM, and
// a PKCS#8 key that is not an EC key). Each failure arm must be a hard error, not
// a silent fallback — a silent fallback would reintroduce the non-restart-durable
// ephemeral path under a configuration that asked for a persisted key.
func TestLoadCredentialSigningKey(t *testing.T) {
	dir := t.TempDir()

	// Empty path: the only acceptable (nil, nil) — the caller then generates an
	// ephemeral key. A non-nil key here would mean an empty flag silently loaded
	// something.
	if key, err := loadCredentialSigningKey(""); err != nil || key != nil {
		t.Fatalf("loadCredentialSigningKey(\"\") = (%v, %v); want (nil, nil) ephemeral fallback", key, err)
	}

	// A valid persisted PKCS#8 EC key loads and round-trips to the same key.
	want, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(want)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	validPath := filepath.Join(dir, "valid.key.pem")
	if err := os.WriteFile(validPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write valid key: %v", err)
	}
	got, err := loadCredentialSigningKey(validPath)
	if err != nil {
		t.Fatalf("loadCredentialSigningKey(valid) errored: %v", err)
	}
	if got == nil || !got.Equal(want) {
		t.Fatal("loadCredentialSigningKey did not round-trip the persisted key")
	}

	// A present-but-unreadable path is a hard error, never an ephemeral fallback.
	if _, err := loadCredentialSigningKey(filepath.Join(dir, "does-not-exist.pem")); err == nil {
		t.Fatal("loadCredentialSigningKey accepted a missing path; want a hard error")
	}

	// Bytes that are not PEM at all.
	nonPEM := filepath.Join(dir, "not-pem.key")
	if err := os.WriteFile(nonPEM, []byte("this is not pem"), 0o600); err != nil {
		t.Fatalf("write non-pem: %v", err)
	}
	if _, err := loadCredentialSigningKey(nonPEM); err == nil {
		t.Fatal("loadCredentialSigningKey accepted non-PEM bytes; want a hard error")
	}

	// PEM that decodes but is not a PKCS#8 private key.
	notPKCS8 := filepath.Join(dir, "not-pkcs8.pem")
	if err := os.WriteFile(notPKCS8, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}), 0o600); err != nil {
		t.Fatalf("write not-pkcs8: %v", err)
	}
	if _, err := loadCredentialSigningKey(notPKCS8); err == nil {
		t.Fatal("loadCredentialSigningKey accepted PEM that is not a PKCS#8 key; want a hard error")
	}

	// A valid PKCS#8 key that is not an EC key (RSA) — the credential issuer needs
	// an EC key, so a non-EC PKCS#8 key is a hard error.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa key: %v", err)
	}
	notEC := filepath.Join(dir, "not-ec.pem")
	if err := os.WriteFile(notEC, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}), 0o600); err != nil {
		t.Fatalf("write not-ec: %v", err)
	}
	if _, err := loadCredentialSigningKey(notEC); err == nil {
		t.Fatal("loadCredentialSigningKey accepted a non-EC PKCS#8 key; want a hard error")
	}
}
