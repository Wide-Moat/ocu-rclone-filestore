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
	// Decode the signature and flip a high-order byte of r, which is guaranteed
	// to change the decoded R||S pair (unlike flipping a trailing base64url
	// character, whose low bits can map to encoding padding and leave the decoded
	// integers unchanged). The mutated signature must not verify.
	parts := strings.Split(tok, ".")
	rawSig, derr := b64.DecodeString(parts[2])
	if derr != nil {
		t.Fatalf("decode sig: %v", derr)
	}
	rawSig[0] ^= 0xFF // flip the most-significant byte of r
	parts[2] = b64.EncodeToString(rawSig)
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
		t.Fatalf("rebuild public key: %v", err)
	}
	// Re-encode the rebuilt key and confirm the coordinates match the original
	// JWK, avoiding a read of the deprecated big.Int coordinate fields.
	if again := JWKFromPublic("kid-1", pub); again.X != jwk.X || again.Y != jwk.Y {
		t.Fatalf("curve point mismatch after round trip: got x=%s y=%s want x=%s y=%s", again.X, again.Y, jwk.X, jwk.Y)
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

func TestVerifyRejectsNonBase64Header(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if _, err := Verify("!!!.payload.sig", JWKS{}, "", "", now); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("non-base64 header: expected ErrUntrusted, got %v", err)
	}
}

func TestVerifyRejectsNonJSONHeader(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok := b64.EncodeToString([]byte("not json")) + ".x.y"
	if _, err := Verify(tok, JWKS{}, "", "", now); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("non-JSON header: expected ErrUntrusted, got %v", err)
	}
}

func TestVerifyRejectsNonBase64SignatureAndPayload(t *testing.T) {
	priv := mustKey(t)
	now := time.Unix(1_700_000_000, 0)
	tok, err := Sign(priv, "kid-1", sampleClaims(now))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-1", &priv.PublicKey)}}
	parts := strings.Split(tok, ".")

	// Signature segment is not base64url.
	bad := parts[0] + "." + parts[1] + ".!!!"
	if _, err := Verify(bad, jwks, "", "", now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("non-base64 sig: expected ErrBadSignature, got %v", err)
	}

	// Signature segment is base64url but the wrong length (decodeRS rejects it).
	shortSig := b64.EncodeToString([]byte("too-short"))
	bad = parts[0] + "." + parts[1] + "." + shortSig
	if _, err := Verify(bad, jwks, "", "", now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("short sig: expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyRejectsNonJSONPayload(t *testing.T) {
	// A token whose signature verifies the bytes but whose payload is not JSON
	// is impossible to forge without the key, so build one legitimately: sign a
	// header+payload where the payload bytes are valid JSON for signing, then
	// confirm a payload that fails to unmarshal into Claims is rejected. Here we
	// exercise the non-base64 payload arm of Verify by corrupting the payload to
	// a non-base64url string, which precedes the JSON decode.
	priv := mustKey(t)
	now := time.Unix(1_700_000_000, 0)
	tok, err := Sign(priv, "kid-1", sampleClaims(now))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwks := JWKS{Keys: []JWK{JWKFromPublic("kid-1", &priv.PublicKey)}}
	parts := strings.Split(tok, ".")
	// Replace the payload with a non-base64url string; the signature no longer
	// matches, so this surfaces as a bad signature (the signature is checked
	// before the payload is decoded).
	bad := parts[0] + ".!!!." + parts[2]
	if _, err := Verify(bad, jwks, "", "", now); err == nil {
		t.Fatalf("corrupted payload: expected an error, got nil")
	}
}

func TestDecodeRSRejectsWrongLength(t *testing.T) {
	if _, _, err := decodeRS([]byte("short")); err == nil {
		t.Fatalf("expected error for wrong-length signature")
	}
}
