// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package exchange

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

// newTestJWTIssuer builds a JWTCredentialIssuer over a fresh key with a fixed
// clock so the issued token's timestamps are deterministic.
func newTestJWTIssuer(t *testing.T) (*JWTCredentialIssuer, func() time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	iss, err := NewJWTCredentialIssuerFromKey(priv, CredentialIssuerOptions{
		Issuer: "https://exchange.test", Audience: "filestore", Kid: "kid-cred", Now: clock,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss, clock
}

// TestJWTCredentialIssuerIssueVerifies is the direct coverage the credential
// issuance path lacked: Issue() must mint a non-empty compact JWT that verifies
// against the issuer's own published JWKS, carries the bound filesystem_id as
// its subject, and is not yet expired under the issuing clock.
func TestJWTCredentialIssuerIssueVerifies(t *testing.T) {
	iss, clock := newTestJWTIssuer(t)

	tok := iss.Issue("fs-outputs", "write")
	if tok == "" {
		t.Fatal("Issue returned an empty token; want a signed credential JWT")
	}

	claims, err := jwtmint.Verify(tok, iss.JWKS(), "https://exchange.test", "filestore", clock())
	if err != nil {
		t.Fatalf("issued credential did not verify against the published JWKS: %v", err)
	}
	if claims.Subject != "fs-outputs" {
		t.Errorf("credential subject = %q, want fs-outputs", claims.Subject)
	}
	if claims.FilesystemID != "fs-outputs" {
		t.Errorf("credential filesystem_id = %q, want fs-outputs", claims.FilesystemID)
	}
	if claims.Expiry <= clock().Unix() {
		t.Errorf("credential expiry %d is not in the future of the issuing clock %d", claims.Expiry, clock().Unix())
	}
}

// TestJWTCredentialIssuerIssueUniquePerScope confirms two scopes get distinct
// tokens bound to their own filesystem_id.
func TestJWTCredentialIssuerIssueUniquePerScope(t *testing.T) {
	iss, clock := newTestJWTIssuer(t)

	a := iss.Issue("fs-a", "read")
	b := iss.Issue("fs-b", "write")
	if a == b {
		t.Fatal("distinct scopes produced identical credentials")
	}
	ca, err := jwtmint.Verify(a, iss.JWKS(), "https://exchange.test", "filestore", clock())
	if err != nil {
		t.Fatalf("verify a: %v", err)
	}
	cb, err := jwtmint.Verify(b, iss.JWKS(), "https://exchange.test", "filestore", clock())
	if err != nil {
		t.Fatalf("verify b: %v", err)
	}
	if ca.FilesystemID != "fs-a" || cb.FilesystemID != "fs-b" {
		t.Errorf("scopes not bound: a=%q b=%q", ca.FilesystemID, cb.FilesystemID)
	}
}

// TestJWTCredentialIssuerExpiredRejected verifies a token issued under a fixed
// clock fails verification once the clock is advanced past its TTL — the expiry
// stamp is real, not cosmetic.
func TestJWTCredentialIssuerExpiredRejected(t *testing.T) {
	iss, clock := newTestJWTIssuer(t)
	tok := iss.Issue("fs-outputs", "write")

	future := clock().Add(defaultCredentialTTL + time.Minute)
	if _, err := jwtmint.Verify(tok, iss.JWKS(), "https://exchange.test", "filestore", future); err == nil {
		t.Fatal("an expired credential verified; want rejection past its TTL")
	}
}
