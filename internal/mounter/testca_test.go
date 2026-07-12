// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"crypto/x509"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/testca"
)

// validCAPEM mints a self-signed CA certificate and returns it PEM-encoded.
// The mounter fixtures thread this through the ocufs configmap as ca_cert_pem;
// the transport constructor parses it with AppendCertsFromPEM at NewFs time, so
// the value must be a real certificate, not a placeholder literal. The trust
// anchor it establishes is never dialed — these tests build the Fs and assemble
// mount options without contacting any edge.
func validCAPEM(t *testing.T) string {
	t.Helper()
	raw, err := testca.PEM(testca.Options{
		CommonName: "ocufs-unit-test-ca",
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	if err != nil {
		t.Fatalf("mint CA: %v", err)
	}
	return string(raw)
}
