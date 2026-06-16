// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwtmint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func sampleClaims(now time.Time) Claims {
	return Claims{
		Issuer:       "https://control-plane.example",
		Audience:     "filestore-edge",
		Subject:      "session-1",
		IssuedAt:     now.Unix(),
		Expiry:       now.Add(5 * time.Minute).Unix(),
		FilesystemID: "fs-outputs",
		Intent:       "write",
		Downloadable: false,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := mustKey(t)
	now := time.Unix(1_700_000_000, 0)
	claims := sampleClaims(now)

	tok, err := Sign(priv, "kid-1", claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-1", &priv.PublicKey)}}

	got, err := Verify(tok, jwks, claims.Issuer, claims.Audience, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.FilesystemID != claims.FilesystemID || got.Intent != claims.Intent || got.Downloadable != claims.Downloadable {
		t.Fatalf("claims mismatch: got %+v want %+v", got, claims)
	}
	if got.Issuer != claims.Issuer || got.Audience != claims.Audience {
		t.Fatalf("registered claims mismatch: got %+v", got)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	priv := mustKey(t)
	now := time.Unix(1_700_000_000, 0)
	claims := sampleClaims(now)
	claims.Expiry = now.Add(-time.Second).Unix()

	tok, err := Sign(priv, "kid-1", claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-1", &priv.PublicKey)}}

	_, err = Verify(tok, jwks, claims.Issuer, claims.Audience, now)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	priv := mustKey(t)
	now := time.Unix(1_700_000_000, 0)
	claims := sampleClaims(now)

	tok, err := Sign(priv, "kid-1", claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Flip the last byte of the signature segment.
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	if sig[len(sig)-1] == 'A' {
		sig[len(sig)-1] = 'B'
	} else {
		sig[len(sig)-1] = 'A'
	}
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")

	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-1", &priv.PublicKey)}}
	_, err = Verify(tampered, jwks, claims.Issuer, claims.Audience, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyRejectsWrongKid(t *testing.T) {
	priv := mustKey(t)
	now := time.Unix(1_700_000_000, 0)
	claims := sampleClaims(now)

	tok, err := Sign(priv, "kid-signer", claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// JWKS publishes a different kid.
	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-other", &priv.PublicKey)}}
	_, err = Verify(tok, jwks, claims.Issuer, claims.Audience, now)
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("expected ErrUntrusted, got %v", err)
	}
}

func TestVerifyRejectsWrongIssuerAudience(t *testing.T) {
	priv := mustKey(t)
	now := time.Unix(1_700_000_000, 0)
	claims := sampleClaims(now)
	tok, err := Sign(priv, "kid-1", claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-1", &priv.PublicKey)}}

	if _, err := Verify(tok, jwks, "wrong-issuer", claims.Audience, now); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("wrong issuer: expected ErrUntrusted, got %v", err)
	}
	if _, err := Verify(tok, jwks, claims.Issuer, "wrong-aud", now); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("wrong audience: expected ErrUntrusted, got %v", err)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	jwks := JWKS{}
	for _, tok := range []string{"", "onlyonepart", "two.parts", "a.b.c.d"} {
		if _, err := Verify(tok, jwks, "iss", "aud", time.Now()); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("token %q: expected ErrUntrusted, got %v", tok, err)
		}
	}
}

func TestJWKRoundTrip(t *testing.T) {
	priv := mustKey(t)
	jwk := JWKFromPublic("kid-1", &priv.PublicKey)
	pub, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatalf("curve point mismatch after round trip")
	}
}

func TestJWKPublicKeyRejectsBadKeys(t *testing.T) {
	cases := []JWK{
		{Kty: "RSA", Crv: "P-256", X: "AA", Y: "AA"},
		{Kty: "EC", Crv: "P-384", X: "AA", Y: "AA"},
		{Kty: "EC", Crv: "P-256", X: "!!!", Y: "AA"},
		{Kty: "EC", Crv: "P-256", X: "AA", Y: "!!!"},
		{Kty: "EC", Crv: "P-256", X: "AA", Y: "AA"}, // not on curve
	}
	for i, jwk := range cases {
		if _, err := jwk.PublicKey(); err == nil {
			t.Fatalf("case %d: expected error for bad jwk", i)
		}
	}
}

func TestSignRejectsBadKey(t *testing.T) {
	if _, err := Sign(nil, "kid", Claims{}); err == nil {
		t.Fatalf("expected error for nil key")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p384: %v", err)
	}
	if _, err := Sign(p384, "kid", Claims{}); err == nil {
		t.Fatalf("expected error for non-P256 key")
	}
}

func TestVerifyRejectsWrongAlg(t *testing.T) {
	// Hand-build a token with alg=none-style header.
	priv := mustKey(t)
	tok, err := Sign(priv, "kid-1", sampleClaims(time.Unix(1_700_000_000, 0)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(tok, ".")
	// Replace header with an HS256 header for the same kid.
	parts[0] = b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"kid-1"}`))
	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-1", &priv.PublicKey)}}
	if _, err := Verify(strings.Join(parts, "."), jwks, "", "", time.Unix(1_700_000_000, 0)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("expected ErrUntrusted for wrong alg, got %v", err)
	}
}
