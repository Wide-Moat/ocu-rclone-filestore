// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// certPEMOf returns the PEM-encoded leaf certificate of an httptest TLS server.
// Feeding this into httpsTransport makes the transport trust exactly that
// server and nothing else.
func certPEMOf(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("httptest server has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// unrelatedCAPEM mints a self-signed CA certificate unrelated to any test
// server, used to prove that an edge presenting an untrusted chain is rejected.
func unrelatedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestHTTPSTransportTrustsSuppliedCA verifies that a transport built from a
// TLS server's own certificate PEM reaches that server over HTTPS and gets a
// 200 — the trust anchor flows from ca_cert_pem, not the system roots.
func TestHTTPSTransportTrustsSuppliedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tr, err := httpsTransport(certPEMOf(t, srv))
	if err != nil {
		t.Fatalf("httpsTransport: %v", err)
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

// TestHTTPSTransportRejectsEmptyAndGarbagePEM verifies the constructor errors
// when there is no usable trust anchor: an empty PEM and a non-certificate PEM
// must both fail rather than silently trusting nothing or the system roots.
func TestHTTPSTransportRejectsEmptyAndGarbagePEM(t *testing.T) {
	if _, err := httpsTransport(nil); err == nil {
		t.Error("empty PEM: expected error, got nil")
	}
	if _, err := httpsTransport([]byte{}); err == nil {
		t.Error("zero-length PEM: expected error, got nil")
	}
	if _, err := httpsTransport([]byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")); err == nil {
		t.Error("garbage PEM: expected error, got nil")
	}
	if _, err := httpsTransport([]byte("this is not a PEM block at all")); err == nil {
		t.Error("non-PEM input: expected error, got nil")
	}
}

// TestHTTPSTransportRejectsUntrustedEdge verifies that a transport trusting an
// unrelated CA refuses the TLS handshake against a server whose leaf it does
// not trust — the untrusted edge is rejected, not silently accepted.
func TestHTTPSTransportRejectsUntrustedEdge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := httpsTransport(unrelatedCAPEM(t))
	if err != nil {
		t.Fatalf("httpsTransport: %v", err)
	}
	client := &http.Client{Transport: tr}
	if _, err := client.Get(srv.URL); err == nil {
		t.Error("expected TLS handshake failure against an untrusted edge, got nil")
	}
}

// TestHTTPSTransportNonZeroTimeouts pins the transport's safety knobs: the TLS
// handshake timeout must never be zero (an unbounded handshake wedges the mount)
// and HTTP/2 must be attempted.
func TestHTTPSTransportNonZeroTimeouts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	tr, err := httpsTransport(certPEMOf(t, srv))
	if err != nil {
		t.Fatalf("httpsTransport: %v", err)
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout is zero; an unbounded handshake can wedge the mount")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 is false; the broker edge expects HTTP/2")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Error("TLSClientConfig.RootCAs is nil; the supplied CA was not installed")
	}
}
