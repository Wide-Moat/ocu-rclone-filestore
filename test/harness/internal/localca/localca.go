// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package localca is a tiny harness-only certificate authority. It generates a
// single self-signed CA at construction, issues leaf serving certificates for
// named hosts under that CA, and exposes the CA certificate as PEM.
//
// The harness peers (filestore, control-plane, exchange) and the egress edge
// each serve TLS with a leaf this CA issues; the guest mount is told ONLY the
// edge's CA PEM as its ca_cert_pem trust anchor, so it completes the TLS
// handshake to the edge and to nothing else it is not configured to trust. The
// edge in turn dials the peers over TLS trusting the same CA. The CA is created
// once at bringup and its PEM written to a shared volume, so the guest config
// fixture can carry the trust anchor ahead of any peer starting.
//
// This is test-harness key material with no production weight: keys live only
// in the running harness process and the ephemeral compose volume.
package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// DefaultCertTTL is the validity window stamped on the CA and every leaf when a
// caller does not choose one. It is far longer than any harness run and short
// enough to be unmistakably test-only. A long-lived stand (CI, a demo left up
// past a day) overrides it via NewWithTTL so the harness PKI does not expire
// mid-run; the bringup keystone re-issues an expiring set regardless.
const DefaultCertTTL = 24 * time.Hour

// CA is a self-signed certificate authority that issues leaf serving certs. The
// zero value is unusable; construct one with New or NewWithTTL.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	// leafTTL is the validity window IssueLeaf stamps on each leaf, carried from
	// construction so every leaf's lifetime matches the CA's.
	leafTTL time.Duration
}

// New generates a fresh CA keypair and self-signed CA certificate with the
// default TTL.
func New() (*CA, error) {
	return NewWithTTL(DefaultCertTTL)
}

// NewWithTTL generates a fresh CA with an explicit validity window stamped on
// the CA and inherited by every leaf it issues. A non-positive ttl falls back to
// DefaultCertTTL so a zero-value caller cannot mint an already-expired anchor.
func NewWithTTL(ttl time.Duration) (*CA, error) {
	if ttl <= 0 {
		ttl = DefaultCertTTL
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("localca: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ocu-harness-local-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("localca: self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("localca: parse CA: %w", err)
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leafTTL: ttl,
	}, nil
}

// CertPEM returns the CA certificate in PEM form: the trust anchor a client
// (the guest, or a peer dialing another peer) is configured with.
func (c *CA) CertPEM() []byte {
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

// IssueLeaf issues a leaf serving certificate for the given DNS names and IP
// addresses, signed by the CA. The returned tls.Certificate carries the leaf
// plus the CA in its chain so a client trusting only the CA PEM can verify it.
func (c *CA) IssueLeaf(dnsNames []string, ipAddrs []net.IP) (tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("localca: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	cn := "leaf"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(c.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("localca: sign leaf: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        mustParse(der),
	}, nil
}

// CertPool returns an x509.CertPool containing only this CA, suitable for a
// client RootCAs that trusts leaves this CA issued and nothing else.
func (c *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// randomSerial draws a random positive 128-bit certificate serial number.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("localca: serial: %w", err)
	}
	return serial, nil
}

// mustParse parses a DER certificate, returning nil on failure. The DER was
// just produced by CreateCertificate above, so a parse failure cannot occur in
// practice; a nil Leaf is tolerated by crypto/tls (it re-parses lazily).
func mustParse(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}
