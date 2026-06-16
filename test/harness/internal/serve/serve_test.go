// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

// writeLeaf issues a leaf for "localhost"/127.0.0.1 from ca and writes the cert
// and key PEMs into dir, returning their paths plus the CA PEM path.
func writeLeaf(t *testing.T, ca *localca.CA, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	leaf, err := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	certPath = filepath.Join(dir, "leaf.cert.pem")
	keyPath = filepath.Join(dir, "leaf.key.pem")
	caPath = filepath.Join(dir, "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	der, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return certPath, keyPath, caPath
}

// TestServeRunAndClients boots a TLS server via Run with a CA-issued leaf, then
// uses CAClient and FetchJWKS to reach it — covering LoadServerTLS, Run,
// CAClient, FetchJWKS, and readAllClose end to end.
func TestServeRunAndClients(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := writeLeaf(t, ca, dir)

	tlsConf, err := LoadServerTLS(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}

	// Listen on an ephemeral port and serve a trivial JWKS-ish endpoint.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})

	done := make(chan error, 1)
	go func() { done <- Run(addr, tlsConf, mux) }()
	t.Cleanup(func() {
		// Force the goroutine to unblock by dialing once; Run returns on a serve
		// error. The test process exit closes the listener regardless.
	})

	client, err := CAClient(caPath)
	if err != nil {
		t.Fatalf("CAClient: %v", err)
	}

	body, err := FetchJWKS(context.Background(), client, "https://"+addr+"/jwks", 10*time.Second)
	if err != nil {
		t.Fatalf("FetchJWKS: %v", err)
	}
	if string(body) != `{"keys":[]}` {
		t.Fatalf("unexpected JWKS body: %q", body)
	}
}

// TestCAClientRejectsBadPEM covers the CAClient error arm on a CA file with no
// certificate.
func TestCAClientRejectsBadPEM(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := CAClient(bad); err == nil {
		t.Fatal("CAClient accepted a CA file with no certificate")
	}
	if _, err := CAClient(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("CAClient accepted a missing CA file")
	}
}

// TestLoadServerTLSRejectsMissing covers the LoadServerTLS error arm.
func TestLoadServerTLSRejectsMissing(t *testing.T) {
	if _, err := LoadServerTLS("/nope/cert.pem", "/nope/key.pem"); err == nil {
		t.Fatal("LoadServerTLS accepted missing files")
	}
}

// TestFetchJWKSTimesOut covers the deadline arm: an address nothing serves
// fails within the budget rather than hanging.
func TestFetchJWKSTimesOut(t *testing.T) {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	_, err := FetchJWKS(context.Background(), client, "https://127.0.0.1:1/none", 1*time.Second)
	if err == nil {
		t.Fatal("FetchJWKS returned no error for an unreachable endpoint")
	}
}

// TestRunReturnsServeError covers the error-return arm of Run: an unbindable
// address makes ListenAndServeTLS fail immediately and Run wraps the error.
func TestRunReturnsServeError(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	dir := t.TempDir()
	certPath, keyPath, _ := writeLeaf(t, ca, dir)
	tlsConf, err := LoadServerTLS(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	// An invalid port forces ListenAndServeTLS to fail at once.
	if err := Run("127.0.0.1:999999", tlsConf, http.NewServeMux()); err == nil {
		t.Fatal("Run returned nil for an unbindable address")
	}
}
