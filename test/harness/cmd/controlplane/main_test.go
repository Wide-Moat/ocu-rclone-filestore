// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/serve"
)

// shared writes a CA, a "localhost" leaf, and a control-plane signing key into a
// temp dir and returns their paths plus an ephemeral listen address.
func shared(t *testing.T) (certPath, keyPath, signingPath, caPath, addr string) {
	t.Helper()
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	dir := t.TempDir()
	leaf, err := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	certPath = filepath.Join(dir, "leaf.cert.pem")
	keyPath = filepath.Join(dir, "leaf.key.pem")
	signingPath = filepath.Join(dir, "signing.key.pem")
	caPath = filepath.Join(dir, "ca.pem")
	writePEM(t, certPath, "CERTIFICATE", leaf.Certificate[0])
	writeKey(t, keyPath, leaf.PrivateKey.(*ecdsa.PrivateKey))
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	writeKey(t, signingPath, sk)
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()
	return certPath, keyPath, signingPath, caPath, addr
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writePEM(t, path, "PRIVATE KEY", der)
}

func TestControlPlaneRunServesJWKS(t *testing.T) {
	certPath, keyPath, signingPath, caPath, addr := shared(t)
	go func() { _ = run(addr, certPath, keyPath, signingPath) }()

	client, err := serve.CAClient(caPath)
	if err != nil {
		t.Fatalf("CAClient: %v", err)
	}
	if _, err := serve.FetchJWKS(context.Background(), client, "https://"+addr+"/.well-known/jwks.json", 10*time.Second); err != nil {
		t.Fatalf("control-plane JWKS never came up: %v", err)
	}
}

func TestLoadSigningKeyErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadSigningKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("loadSigningKey accepted a missing path")
	}
	notPEM := filepath.Join(dir, "not.pem")
	_ = os.WriteFile(notPEM, []byte("nope"), 0o600)
	if _, err := loadSigningKey(notPEM); err == nil {
		t.Fatal("loadSigningKey accepted a non-PEM file")
	}
}

func TestRunRejectsBadSigningKey(t *testing.T) {
	certPath, keyPath, _, _, addr := shared(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	if err := run(addr, certPath, keyPath, bad); err == nil {
		t.Fatal("run accepted a bad signing key")
	}
}

// TestRunRejectsMissingCert covers the LoadServerTLS error arm of run: a valid
// signing key but a missing leaf cert.
func TestRunRejectsMissingCert(t *testing.T) {
	_, _, signingPath, _, addr := shared(t)
	dir := t.TempDir()
	if err := run(addr, filepath.Join(dir, "nope.cert"), filepath.Join(dir, "nope.key"), signingPath); err == nil {
		t.Fatal("run accepted a missing leaf cert")
	}
}

// TestMainWith covers the flag-parsing entry with runFn stubbed, so main()'s
// argument wiring is exercised without binding a port.
func TestMainWith(t *testing.T) {
	saved := runFn
	t.Cleanup(func() { runFn = saved })
	var gotAddr string
	runFn = func(addr, cert, key, signing string) error { gotAddr = addr; return nil }
	if err := mainWith([]string{"-addr", "127.0.0.1:9", "-cert", "c", "-key", "k", "-signing-key", "s"}); err != nil {
		t.Fatalf("mainWith: %v", err)
	}
	if gotAddr != "127.0.0.1:9" {
		t.Fatalf("mainWith did not pass the addr flag, got %q", gotAddr)
	}
	if err := mainWith([]string{"-unknown-flag"}); err == nil {
		t.Fatal("mainWith accepted an unknown flag")
	}
}
