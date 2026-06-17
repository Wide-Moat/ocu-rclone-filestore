// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwtmint

import (
	"crypto/ecdh"
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

// p256CoordSize is the byte width of a single P-256 affine coordinate.
const p256CoordSize = 32

// JWKFromPublic builds a JWK describing the given P-256 public key under the
// given kid. The coordinates are encoded base64url (no padding) as RFC 7518
// requires, each left-padded to the 32-byte P-256 coordinate width.
//
// The affine coordinates are read from the key's uncompressed SEC1 encoding
// (0x04 || X || Y) obtained via crypto/ecdh, rather than the deprecated big.Int
// coordinate fields.
func JWKFromPublic(kid string, pub *ecdsa.PublicKey) JWK {
	xb, yb := coordsFromECDSA(pub)
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

// coordsFromECDSA returns the 32-byte big-endian X and Y coordinates of a P-256
// public key, sliced from its uncompressed SEC1 encoding.
func coordsFromECDSA(pub *ecdsa.PublicKey) (x, y []byte) {
	ek, err := pub.ECDH()
	if err != nil {
		// A non-P-256 key cannot occur here: the signer enforces P-256, and the
		// JWKS is only ever built from keys this package generated. Fall back to a
		// zeroed pair so the caller still produces a well-formed (if unusable) JWK
		// rather than panicking in a test helper.
		return make([]byte, p256CoordSize), make([]byte, p256CoordSize)
	}
	raw := ek.Bytes() // 0x04 || X(32) || Y(32)
	return raw[1 : 1+p256CoordSize], raw[1+p256CoordSize:]
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

// PublicKey rebuilds the ecdsa.PublicKey from the JWK coordinates. It rejects a
// JWK that is not an EC P-256 signing key or whose coordinates are not valid
// base64url or are off-curve, so a malformed key cannot silently verify nothing.
//
// On-curve validation runs through crypto/ecdh's NewPublicKey, which performs
// the point-on-curve check without the deprecated elliptic.IsOnCurve API.
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

	// Left-pad each coordinate to the fixed width and validate the point lies on
	// P-256 by parsing the uncompressed SEC1 encoding through crypto/ecdh.
	xf := leftPad(xb, p256CoordSize)
	yf := leftPad(yb, p256CoordSize)
	if xf == nil || yf == nil {
		return nil, fmt.Errorf("jwtmint: coordinate exceeds P-256 width")
	}
	uncompressed := make([]byte, 1+2*p256CoordSize)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+p256CoordSize], xf)
	copy(uncompressed[1+p256CoordSize:], yf)
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("jwtmint: jwk coordinates are not on P-256: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xf),
		Y:     new(big.Int).SetBytes(yf),
	}, nil
}

// leftPad returns b left-padded with zeros to size bytes, or nil if b is longer
// than size.
func leftPad(b []byte, size int) []byte {
	if len(b) > size {
		return nil
	}
	if len(b) == size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
