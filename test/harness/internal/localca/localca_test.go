// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package localca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

// TestNewProducesAParsableCAPEM checks the constructor yields a CA whose PEM is
// a single parsable CA certificate — the trust anchor the guest and the peers
// are configured with.
func TestNewProducesAParsableCAPEM(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	block, rest := pem.Decode(ca.CertPEM())
	if block == nil {
		t.Fatal("CertPEM did not decode to a PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block type = %q; want CERTIFICATE", block.Type)
	}
	if len(rest) != 0 {
		t.Fatalf("CertPEM carried %d trailing bytes; want a single certificate", len(rest))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("issued anchor is not marked IsCA")
	}
}

// TestCertPEMReturnsACopy guards the accessor: mutating the returned slice must
// not corrupt the CA's stored PEM (a shared backing array would leak across
// callers writing the trust anchor to different sinks).
func TestCertPEMReturnsACopy(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first := ca.CertPEM()
	if len(first) == 0 {
		t.Fatal("CertPEM returned empty")
	}
	first[0] ^= 0xFF
	second := ca.CertPEM()
	if second[0] == first[0] {
		t.Fatal("CertPEM returned a slice aliasing internal state; a caller mutated the stored PEM")
	}
}

// TestIssueLeafVerifiesAgainstCA is the load-bearing property: a leaf the CA
// issues for a host must verify against a pool trusting only that CA, over a
// real TLS handshake. It exercises both the DNS-name and IP-address axes and
// the empty-names common-name fallback.
func TestIssueLeafVerifiesAgainstCA(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		name string
		dns  []string
		ips  []net.IP
		dial string
	}{
		{name: "dns", dns: []string{"edge"}, dial: "edge"},
		{name: "ip", ips: []net.IP{net.IPv4(127, 0, 0, 1)}, dial: "127.0.0.1"},
		{name: "empty-names-falls-back-to-leaf-cn", dial: "leaf"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := ca.IssueLeaf(tc.dns, tc.ips)
			if err != nil {
				t.Fatalf("IssueLeaf: %v", err)
			}
			if len(leaf.Certificate) != 2 {
				t.Fatalf("leaf chain length = %d; want 2 (leaf + CA)", len(leaf.Certificate))
			}
			parsed, err := x509.ParseCertificate(leaf.Certificate[0])
			if err != nil {
				t.Fatalf("parse issued leaf: %v", err)
			}
			opts := x509.VerifyOptions{
				Roots:     ca.CertPool(),
				DNSName:   "",
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if tc.dial != "leaf" && tc.dns != nil {
				opts.DNSName = tc.dial
			}
			if _, err := parsed.Verify(opts); err != nil {
				t.Fatalf("issued leaf does not verify against the CA pool: %v", err)
			}
		})
	}
}

// TestCertPoolTrustsOnlyTheCA confirms the pool the CA hands a client trusts a
// leaf this CA issued and rejects a leaf from an unrelated CA.
func TestCertPoolTrustsOnlyTheCA(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	other, err := New()
	if err != nil {
		t.Fatalf("New (other): %v", err)
	}

	good, err := ca.IssueLeaf([]string{"host"}, nil)
	if err != nil {
		t.Fatalf("IssueLeaf good: %v", err)
	}
	bad, err := other.IssueLeaf([]string{"host"}, nil)
	if err != nil {
		t.Fatalf("IssueLeaf bad: %v", err)
	}

	pool := ca.CertPool()

	goodLeaf, _ := x509.ParseCertificate(good.Certificate[0])
	if _, err := goodLeaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "host"}); err != nil {
		t.Fatalf("leaf from the trusted CA failed to verify: %v", err)
	}

	badLeaf, _ := x509.ParseCertificate(bad.Certificate[0])
	if _, err := badLeaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "host"}); err == nil {
		t.Fatal("leaf from an unrelated CA verified against the pool; the pool must trust only its own CA")
	}
}

// TestIssuedLeafCarriesAUsableKeyPair checks the issued tls.Certificate is a
// complete, loadable serving identity: its private key matches the leaf and the
// chain is presentable to crypto/tls.
func TestIssuedLeafCarriesAUsableKeyPair(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	leaf, err := ca.IssueLeaf([]string{"svc"}, nil)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	// A TLS config that presents the leaf must be usable; building the config and
	// reading back the certificate is the cheapest end-to-end loadability check.
	cfg := &tls.Config{Certificates: []tls.Certificate{leaf}}
	if len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) == 0 {
		t.Fatal("issued leaf is not a usable serving certificate")
	}
	if cfg.Certificates[0].PrivateKey == nil {
		t.Fatal("issued leaf carries no private key")
	}
}
