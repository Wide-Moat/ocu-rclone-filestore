// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/exchange"
)

const (
	credIssuer   = "https://exchange.test"
	credAudience = "filestore"
)

var credNow = func() time.Time { return time.Unix(1_700_000_000, 0) }

// newCredPair builds an exchange-side JWT credential issuer and the matching
// filestore-side validator over the issuer's published JWKS, sharing no map.
func newCredPair(t *testing.T) (*exchange.JWTCredentialIssuer, JWTCredentialValidator) {
	t.Helper()
	iss, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: credIssuer, Audience: credAudience, Kid: "kid-cred", Now: credNow,
	})
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	v := JWTCredentialValidator{
		JWKS: iss.JWKS(), Issuer: credIssuer, Audience: credAudience, Now: credNow,
	}
	return iss, v
}

// TestJWTCredentialValidator_RoundTrip proves a credential the exchange issues
// for a scope validates back to exactly that filesystem_id with no shared map.
func TestJWTCredentialValidator_RoundTrip(t *testing.T) {
	iss, v := newCredPair(t)
	cred := iss.Issue("fsrw", "write")
	if cred == "" {
		t.Fatal("issuer returned empty credential")
	}
	gotFSID, err := v.Validate("Bearer " + cred)
	if err != nil {
		t.Fatalf("validate issued credential: %v", err)
	}
	if gotFSID != "fsrw" {
		t.Fatalf("validated scope %q, want fsrw", gotFSID)
	}
}

// TestJWTCredentialValidator_Rejects covers the rejection arms: missing header,
// a non-bearer header, and a token signed by a DIFFERENT issuer key (unknown
// kid / bad signature) the validator's JWKS does not carry.
func TestJWTCredentialValidator_Rejects(t *testing.T) {
	_, v := newCredPair(t)

	if _, err := v.Validate(""); err == nil {
		t.Fatal("empty Authorization accepted; want rejection")
	}
	if _, err := v.Validate("Basic abc"); err == nil {
		t.Fatal("non-bearer Authorization accepted; want rejection")
	}

	// A credential from a foreign issuer (a second, independent key set) must not
	// validate against this validator's JWKS.
	foreign, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: credIssuer, Audience: credAudience, Kid: "kid-foreign", Now: credNow,
	})
	if err != nil {
		t.Fatalf("foreign issuer: %v", err)
	}
	if _, err := v.Validate("Bearer " + foreign.Issue("fsrw", "write")); err == nil {
		t.Fatal("a credential from a foreign key set validated; want rejection")
	}
}

// TestJWTCredentialValidator_RejectsExpired proves an expired credential is
// refused (the validator enforces exp against its clock).
func TestJWTCredentialValidator_RejectsExpired(t *testing.T) {
	iss, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: credIssuer, Audience: credAudience, Kid: "kid-cred",
		TTL: time.Minute, Now: func() time.Time { return credNow().Add(-2 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	v := JWTCredentialValidator{JWKS: iss.JWKS(), Issuer: credIssuer, Audience: credAudience, Now: credNow}
	if _, err := v.Validate("Bearer " + iss.Issue("fsrw", "write")); err == nil {
		t.Fatal("expired credential accepted; want rejection")
	}
}
