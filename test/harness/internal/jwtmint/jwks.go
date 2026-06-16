// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwtmint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWKS is a JSON Web Key Set: the published set of public keys the verifier
// selects from by kid. The control-plane peer serves this at its
// /.well-known/jwks.json endpoint; the exchange peer verifies against it.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single JSON Web Key for an EC P-256 public key (the public half of an
// ES256 signing key). X and Y are the base64url (no-pad) big-endian curve
// coordinates.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKFromPublic builds a JWK describing the given P-256 public key under the
// given kid. The coordinates are encoded base64url (no padding) as RFC 7518
// requires, each left-padded to the 32-byte P-256 coordinate width.
func JWKFromPublic(kid string, pub *ecdsa.PublicKey) JWK {
	const size = 32
	xb := make([]byte, size)
	yb := make([]byte, size)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
		X:   base64.RawURLEncoding.EncodeToString(xb),
		Y:   base64.RawURLEncoding.EncodeToString(yb),
	}
}

// Find returns the JWK with the given kid. The bool reports whether a key was
// found; the returned pointer aliases the slice element and must not be mutated.
func (s JWKS) Find(kid string) (*JWK, bool) {
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i], true
		}
	}
	return nil, false
}

// PublicKey reconstructs the ecdsa.PublicKey from the JWK coordinates. It
// rejects a JWK that is not an EC P-256 signing key or whose coordinates are not
// valid base64url, so a malformed key cannot silently verify nothing.
func (k JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" {
		return nil, fmt.Errorf("jwtmint: unsupported kty %q", k.Kty)
	}
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("jwtmint: unsupported crv %q", k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwtmint: x is not base64url: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("jwtmint: y is not base64url: %w", err)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("jwtmint: jwk coordinates are not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
