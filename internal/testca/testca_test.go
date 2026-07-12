// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package testca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestPEMMintsAParsableCA checks PEM returns a single parsable CA certificate
// carrying the requested common name and key usage.
func TestPEMMintsAParsableCA(t *testing.T) {
	raw, err := PEM(Options{CommonName: "example-test-ca", KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		t.Fatal("PEM output did not decode to a PEM block")
	}
	if len(rest) != 0 {
		t.Fatalf("PEM output carried %d trailing bytes; want a single certificate", len(rest))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("minted certificate is not marked IsCA")
	}
	if cert.Subject.CommonName != "example-test-ca" {
		t.Fatalf("common name = %q; want example-test-ca", cert.Subject.CommonName)
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatal("minted certificate dropped the requested CRLSign usage")
	}
}

// TestPEMHonoursANarrowerKeyUsage checks a caller that asks for only CertSign
// gets exactly that, so the two first-party callers' differing usages both hold.
func TestPEMHonoursANarrowerKeyUsage(t *testing.T) {
	raw, err := PEM(Options{CommonName: "narrow-test-ca", KeyUsage: x509.KeyUsageCertSign})
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		t.Fatal("minted certificate carried CRLSign usage the caller did not request")
	}
}
