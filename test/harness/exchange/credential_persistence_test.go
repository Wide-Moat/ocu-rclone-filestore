// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package exchange

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// jwksFingerprint reduces an issuer's published credential JWKS to the fields a
// validator keys on — kid and the EC public coordinates. Two issuers with the
// same fingerprint publish a verification key a cached validator accepts
// interchangeably; a different fingerprint is exactly the desync that rejects an
// otherwise-valid token after a restart.
func jwksFingerprint(t *testing.T, i *JWTCredentialIssuer) string {
	t.Helper()
	ks := i.JWKS().Keys
	if len(ks) != 1 {
		t.Fatalf("JWKS has %d keys; want exactly 1", len(ks))
	}
	k := ks[0]
	return k.Kid + "|" + k.X + "|" + k.Y
}

// TestCredentialIssuerFromKeyIsRestartDurable is the reddening guard for the
// exchange signing-key persistence fix. A persisted key, re-loaded into two
// independent issuers (the stand-in for the exchange restarting against the same
// shared key), MUST publish a byte-identical JWKS — otherwise an edge or
// filestore that cached the credential JWKS desyncs and rejects a valid token.
//
// The contrasting half proves the defect was real: two issuers each generating
// their own key publish DIFFERENT JWKS, which is precisely the restart-desync
// the in-memory-only path caused.
func TestCredentialIssuerFromKeyIsRestartDurable(t *testing.T) {
	opts := CredentialIssuerOptions{Issuer: issuer, Audience: audience, Kid: "kid-cred"}

	// A single persisted key, as harness-init writes once to the shared volume.
	persisted, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate persisted key: %v", err)
	}

	// Two issuers built from that same key model two boots of the exchange that
	// both read the persisted key. Their published JWKS must match.
	boot1, err := NewJWTCredentialIssuerFromKey(persisted, opts)
	if err != nil {
		t.Fatalf("boot1 from key: %v", err)
	}
	boot2, err := NewJWTCredentialIssuerFromKey(persisted, opts)
	if err != nil {
		t.Fatalf("boot2 from key: %v", err)
	}
	if fp1, fp2 := jwksFingerprint(t, boot1), jwksFingerprint(t, boot2); fp1 != fp2 {
		t.Fatalf("persisted-key issuers publish different JWKS across restart: %q vs %q; "+
			"a restart would desync any cached validator and reject a valid token", fp1, fp2)
	}

	// The defect-proving contrast: two issuers that each generate their own key
	// (the old in-memory-only behaviour) publish different JWKS — the desync.
	gen1, err := NewJWTCredentialIssuer(opts)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	gen2, err := NewJWTCredentialIssuer(opts)
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	if fp1, fp2 := jwksFingerprint(t, gen1), jwksFingerprint(t, gen2); fp1 == fp2 {
		t.Fatalf("two generated-key issuers published the SAME JWKS %q; the test cannot "+
			"distinguish the durable path from the in-memory one", fp1)
	}
}

// TestCredentialIssuerFromKeyRejectsNil guards the construction contract: a nil
// key is a configuration error, not a silently-generated fresh key (which would
// reintroduce the non-durable path under the durable constructor's name).
func TestCredentialIssuerFromKeyRejectsNil(t *testing.T) {
	if _, err := NewJWTCredentialIssuerFromKey(nil, CredentialIssuerOptions{Kid: "k"}); err == nil {
		t.Fatal("NewJWTCredentialIssuerFromKey(nil) = nil error; want a hard error")
	}
}
