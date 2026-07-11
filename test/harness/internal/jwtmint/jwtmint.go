// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package jwtmint is a stdlib-only ES256 JWT sign/verify and JWKS helper shared
// by the test-harness control-plane and token-exchange peers. It avoids adding a
// JWT dependency by hand-rolling the RFC 7515/7518 ES256 JOSE encoding on top of
// crypto/ecdsa, crypto/x509-free base64url encoding, and encoding/json.
//
// The signed claim set is the weak session token: it carries the
// session-scoped filesystem_id plus the op-derived intent and the downloadable
// flag, and nothing else of authorizing weight. It is short-lived; the exchange
// peer validates it against the published JWKS and only then issues the real
// filestore credential.
package jwtmint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Sentinel verification errors so callers can branch on the failure class.
var (
	// ErrExpired is returned when the token's exp is at or before the
	// verification clock.
	ErrExpired = errors.New("jwtmint: token expired")
	// ErrBadSignature is returned when the ES256 signature does not verify
	// against the selected JWK.
	ErrBadSignature = errors.New("jwtmint: bad signature")
	// ErrUntrusted is returned for an unknown kid, a wrong issuer/audience, or
	// a malformed token structure: the token cannot be trusted.
	ErrUntrusted = errors.New("jwtmint: untrusted token")
)

// Claims is the weak session JWT claim set scoped {filesystem_id, intent,
// downloadable} plus the standard registered claims the verifier enforces.
type Claims struct {
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"`
	Subject      string `json:"sub,omitempty"`
	IssuedAt     int64  `json:"iat"`
	Expiry       int64  `json:"exp"`
	FilesystemID string `json:"filesystem_id"`
	// Intent is the top-level intent claim harness-minted tokens carry. The real
	// Control plane nests it under authz.intent (see Authz below); Verify falls
	// back to that nested value so a Control-minted Storage-JWT and a harness
	// token both surface the same Intent. The two claim shapes coexist: harness
	// fixtures set the top-level field, Control sets the nested one.
	Intent string `json:"intent"`
	// Authz mirrors the ocu-control StorageClaims shape: the real Control plane
	// emits the intent under an "authz" object, not at the payload top level.
	Authz struct {
		Intent string `json:"intent"`
	} `json:"authz"`
	Downloadable bool `json:"downloadable"`
}

// joseHeader is the JWS protected header for an ES256 JWT.
type joseHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// b64 is the base64url encoding without padding, as RFC 7515 requires.
var b64 = base64.RawURLEncoding

// Sign produces an ES256-signed compact JWT (header.payload.signature). The
// signature is the JOSE R||S fixed-width concatenation (two 32-byte big-endian
// integers for P-256), not an ASN.1 DER structure, per RFC 7518.
func Sign(priv *ecdsa.PrivateKey, kid string, c Claims) (string, error) {
	if priv == nil {
		return "", fmt.Errorf("jwtmint.Sign: nil private key")
	}
	if priv.Curve != elliptic.P256() {
		return "", fmt.Errorf("jwtmint.Sign: ES256 requires a P-256 key")
	}

	header := joseHeader{Alg: "ES256", Typ: "JWT", Kid: kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jwtmint.Sign: marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("jwtmint.Sign: marshal claims: %w", err)
	}

	signingInput := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("jwtmint.Sign: ecdsa sign: %w", err)
	}

	sig := encodeRS(r, s)
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// Verify parses and verifies an ES256 JWT against the JWKS, selecting the JWK by
// the header kid, then enforcing the signature, the issuer, the audience, and
// the expiry against now. The failure class is reported through the sentinel
// errors so the caller can map them to wire status codes.
func Verify(token string, jwks JWKS, expectedIss, expectedAud string, now time.Time) (Claims, error) {
	headerB64, payloadB64, sigB64, ok := splitToken(token)
	if !ok {
		return Claims{}, fmt.Errorf("%w: malformed token", ErrUntrusted)
	}

	headerJSON, err := b64.DecodeString(headerB64)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header is not base64url", ErrUntrusted)
	}
	var header joseHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Claims{}, fmt.Errorf("%w: header is not JSON", ErrUntrusted)
	}
	if header.Alg != "ES256" {
		return Claims{}, fmt.Errorf("%w: unexpected alg %q", ErrUntrusted, header.Alg)
	}

	jwk, found := jwks.Find(header.Kid)
	if !found {
		return Claims{}, fmt.Errorf("%w: unknown kid %q", ErrUntrusted, header.Kid)
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return Claims{}, fmt.Errorf("%w: jwk: %w", ErrUntrusted, err)
	}

	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature is not base64url", ErrBadSignature)
	}
	r, s, err := decodeRS(sig)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	digest := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Claims{}, ErrBadSignature
	}

	payloadJSON, err := b64.DecodeString(payloadB64)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload is not base64url", ErrUntrusted)
	}
	var c Claims
	if err := json.Unmarshal(payloadJSON, &c); err != nil {
		return Claims{}, fmt.Errorf("%w: payload is not JSON", ErrUntrusted)
	}
	// The real Control plane nests the intent under authz.intent; a harness token
	// carries it at the top level. Prefer the top-level value, fall back to the
	// nested one, so both claim shapes yield a usable Intent downstream.
	if c.Intent == "" {
		c.Intent = c.Authz.Intent
	}

	if expectedIss != "" && c.Issuer != expectedIss {
		return Claims{}, fmt.Errorf("%w: issuer %q != expected %q", ErrUntrusted, c.Issuer, expectedIss)
	}
	if expectedAud != "" && c.Audience != expectedAud {
		return Claims{}, fmt.Errorf("%w: audience %q != expected %q", ErrUntrusted, c.Audience, expectedAud)
	}
	if c.Expiry != 0 && !now.Before(time.Unix(c.Expiry, 0)) {
		return Claims{}, ErrExpired
	}

	return c, nil
}

// ExpiryUnverified reads the exp claim from a compact JWS payload WITHOUT
// verifying the signature. It is a lifetime probe, not an authorization check:
// the caller is not the token's verifier (an artifact bringup reads back a token
// it just minted; the edge reads a credential the exchange peer already verified
// when it issued it), so all this reports is when the token says it dies. It
// reuses splitToken so it decodes the payload exactly as Verify does, and never
// touches the header or signature.
//
// It errors when the token is not a three-segment compact JWS, when the payload
// is not base64url, or when the payload is not JSON. It does NOT reject a zero or
// absent exp: it returns the raw value (0 when absent) and leaves the "zero means
// unsafe" policy to the caller. Do not use it where a signature must be trusted;
// use Verify for that.
func ExpiryUnverified(token string) (int64, error) {
	_, payloadB64, _, ok := splitToken(token)
	if !ok {
		return 0, fmt.Errorf("jwtmint: not a compact JWS")
	}
	payloadJSON, err := b64.DecodeString(payloadB64)
	if err != nil {
		return 0, fmt.Errorf("jwtmint: payload is not base64url: %w", err)
	}
	var probe struct {
		Expiry int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &probe); err != nil {
		return 0, fmt.Errorf("jwtmint: payload is not JSON: %w", err)
	}
	return probe.Expiry, nil
}

// splitToken splits a compact JWS into its three base64url segments.
func splitToken(token string) (header, payload, sig string, ok bool) {
	first := -1
	second := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if first == -1 {
				first = i
			} else if second == -1 {
				second = i
			} else {
				// A third dot means this is not a compact JWS.
				return "", "", "", false
			}
		}
	}
	if first == -1 || second == -1 || first == second {
		return "", "", "", false
	}
	return token[:first], token[first+1 : second], token[second+1:], true
}

// encodeRS encodes the ECDSA (r, s) pair as the JOSE fixed-width concatenation:
// each integer left-padded with zeros to 32 bytes (the P-256 coordinate size).
func encodeRS(r, s *big.Int) []byte {
	const size = 32
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out
}

// decodeRS reverses encodeRS: it splits a 64-byte JOSE signature into r and s.
func decodeRS(sig []byte) (r, s *big.Int, err error) {
	const size = 32
	if len(sig) != 2*size {
		return nil, nil, fmt.Errorf("signature must be %d bytes, got %d", 2*size, len(sig))
	}
	r = new(big.Int).SetBytes(sig[:size])
	s = new(big.Int).SetBytes(sig[size:])
	return r, s, nil
}
