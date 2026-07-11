// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rclone/rclone/fs"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// mintSeamServerCert mints a throwaway CA plus a 127.0.0.1 leaf signed by it,
// returning the CA PEM (what the configmap carries as ca_cert_pem) and the
// leaf as a TLS certificate for the capture server. The production seam
// threads exactly this shape: the mount config carries a CA anchor and the
// broker endpoint presents a leaf chaining to it.
func mintSeamServerCert(t *testing.T) (string, tls.Certificate) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocufs-seam-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ocufs-seam-test-broker"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	leaf, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("assemble leaf key pair: %v", err)
	}
	return string(caPEM), leaf
}

// TestProductionSeamEncodesHostileWirePaths pins F-33 at the production seam:
// the exact constructor path realpoint feeds (buildOcufsConfigmap -> the
// registry's direct info.NewFs, NOT fs.NewFs) must run the backend's declared
// path encoder. A file name carrying an invalid-UTF-8 byte and a trailing
// space is legal on Linux; without the encoder the JSON request body mutates
// it (invalid bytes become U+FFFD, the trailing space is silently strippable
// downstream), so the broker addresses a DIFFERENT path than the kernel wrote
// — a created file then fails its own lookup.
//
// The capture broker records every request body; the test asserts the wire
// bytes carry no U+FFFD mutation and no raw trailing space before the closing
// quote. At least one request must be captured — a run where the backend never
// reaches the wire would otherwise pass vacuously.
func TestProductionSeamEncodesHostileWirePaths(t *testing.T) {
	caPEM, leaf := mintSeamServerCert(t)

	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	fsid := "session_seam_fs"
	mount := mountcfg.Mount{
		Destination:     t.TempDir(),
		AuthToken:       "tok",
		FilesystemID:    &fsid,
		VfsCacheMode:    "writes",
		VfsCacheMaxSize: "256M",
		DirPerms:        "0755",
		FilePerms:       "0644",
	}

	cm, err := buildOcufsConfigmap(mount, false, srv.URL, caPEM)
	if err != nil {
		t.Fatalf("buildOcufsConfigmap: %v", err)
	}
	info, err := fs.Find("ocufs")
	if err != nil {
		t.Fatalf("ocufs backend not registered: %v", err)
	}
	// The production seam's exact construction: direct info.NewFs over the bare
	// configmap (realpoint.go), which bypasses the registry-defaults layer.
	fsObj, err := info.NewFs(context.Background(), "ocufs-seam", "", cm)
	if err != nil {
		t.Fatalf("info.NewFs over the production configmap: %v", err)
	}

	// A hostile-but-legal Linux file name: an invalid UTF-8 byte plus a
	// trailing space. The lookup itself is expected to fail (the capture
	// broker answers 404); only the wire bytes matter here.
	_, _ = fsObj.NewObject(context.Background(), "bad\xffname ")

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("the backend never reached the wire; the encoding assertion would be vacuous")
	}
	for _, b := range bodies {
		if !utf8.Valid(b) {
			t.Fatalf("wire body is not valid UTF-8: %q", b)
		}
		if bytes.Contains(b, []byte("�")) {
			t.Fatalf("wire body carries a U+FFFD mutation of the hostile name — the identity encoder ran on the production seam: %s", b)
		}
		if bytes.Contains(b, []byte("name \"")) {
			t.Fatalf("wire body carries the raw trailing space — the identity encoder ran on the production seam: %s", b)
		}
	}
}
