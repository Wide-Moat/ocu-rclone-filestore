// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package testca mints self-signed CA certificates for first-party unit tests
// that need a real trust anchor to feed a transport's ca_cert_pem. It is
// error-returning and imports only the standard crypto and encoding packages —
// never testing — so a first-party test package can wrap it in a t.Fatalf helper
// without any risk of pulling testing into a production import graph.
package testca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Options tunes the minted self-signed CA. CommonName is stamped as the subject
// CN; KeyUsage is the certificate key-usage bitmask. The zero KeyUsage is a
// valid input but rarely what a caller wants, so callers set it explicitly.
type Options struct {
	CommonName string
	KeyUsage   x509.KeyUsage
}

// PEM mints a self-signed CA certificate per o and returns it PEM-encoded. The
// certificate is valid for a one-hour window centered on now, marked IsCA with
// basic constraints set — enough for a client to append it as a trust anchor.
func PEM(o Options) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("testca: generate key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: o.CommonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              o.KeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("testca: create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
