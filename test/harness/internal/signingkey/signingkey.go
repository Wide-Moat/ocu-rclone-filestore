// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package signingkey loads the PKCS#8 EC signing keys the harness peers read
// from the shared volume harness-init writes. Both the control-plane's session
// key and the exchange's credential key are the same PEM->PKCS#8->ECDSA parse;
// the only per-caller differences — whether an empty path may fall back to an
// ephemeral key, and the noun in the error text — are explicit parameters so
// neither is a hidden behaviour.
package signingkey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Load reads a PKCS#8 EC private key from a PEM file. When allowEmptyPath is
// true, an empty path returns (nil, nil) so the caller may fall back to an
// ephemeral generated key — the only place a missing path is acceptable, since
// an ephemeral key is not restart-durable. When allowEmptyPath is false, an
// empty path is read like any other and therefore errors. A present but
// unreadable or malformed path is always a hard error, never a silent fallback.
// label is the noun used in the error text (for example "signing key" or
// "credential signing key").
func Load(path, label string, allowEmptyPath bool) (*ecdsa.PrivateKey, error) {
	if allowEmptyPath && path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the harness signing key on the shared volume
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", label, path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s %q is not PEM", label, path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s %q: %w", label, path, err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s %q is not an EC key", label, path)
	}
	return ecKey, nil
}
