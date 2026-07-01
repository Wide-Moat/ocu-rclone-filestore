// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package exchange

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

// JWTCredentialIssuer issues the real filestore credential as a SECOND ES256
// JWT, signed by a key the exchange holds and bound to the validated
// filesystem_id. Unlike MapCredentialIssuer it shares no in-process map with
// the filestore: the filestore validates the issued JWT against the issuer's
// published JWKS, so the two can run as separate processes. This is the
// credential seam the live e2e graph rides on (the filestore main pairs this
// with a filestore.JWTCredentialValidator over the same JWKS).
//
// The issued credential carries the bound filesystem_id as its subject and a
// short expiry; the filestore re-derives the scope from the verified subject,
// never from the request body.
type JWTCredentialIssuer struct {
	priv     *ecdsa.PrivateKey
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
}

// CredentialIssuerOptions carries JWTCredentialIssuer construction parameters.
type CredentialIssuerOptions struct {
	// Issuer is stamped as the credential iss and is the value the filestore
	// validator enforces.
	Issuer string
	// Audience is stamped as the credential aud (the filestore identity).
	Audience string
	// Kid is the key id stamped in the JOSE header and published in the JWKS.
	Kid string
	// TTL overrides the default credential lifetime when non-zero.
	TTL time.Duration
	// Now, when set, fixes the clock for deterministic tests.
	Now func() time.Time
}

// defaultCredentialTTL is the lifetime stamped on an issued credential JWT. It
// is long enough that a session's exchanged credential does not expire mid-run
// yet short enough to remain unmistakably test-only.
const defaultCredentialTTL = time.Hour

// NewJWTCredentialIssuer constructs an issuer, generating a fresh P-256 signing
// key distinct from the control-plane's.
//
// A generated key is NOT restart-durable: a fresh key on every boot republishes
// a new credential JWKS, so any edge that cached an exchanged credential or any
// filestore that cached the old JWKS desyncs and rejects an otherwise-valid
// token after an independent restart. For a long-running graph, pass a stable
// persisted key via NewJWTCredentialIssuerFromKey instead.
func NewJWTCredentialIssuer(opts CredentialIssuerOptions) (*JWTCredentialIssuer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("exchange: generate credential key: %w", err)
	}
	return NewJWTCredentialIssuerFromKey(priv, opts)
}

// NewJWTCredentialIssuerFromKey constructs an issuer over a caller-supplied
// signing key. Passing the same persisted key across restarts keeps the
// published credential JWKS stable, so a restart of the exchange (or of an edge
// or filestore that caches against it) does not desync the credential seam and
// reject a valid token. The key is mirror of the control-plane's stable signing
// key: both are PKCS#8 EC keys harness-init writes once to the shared volume.
func NewJWTCredentialIssuerFromKey(priv *ecdsa.PrivateKey, opts CredentialIssuerOptions) (*JWTCredentialIssuer, error) {
	if priv == nil {
		return nil, fmt.Errorf("exchange: credential signing key must not be nil")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultCredentialTTL
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &JWTCredentialIssuer{
		priv:     priv,
		kid:      opts.Kid,
		issuer:   opts.Issuer,
		audience: opts.Audience,
		ttl:      ttl,
		now:      now,
	}, nil
}

// Issue mints a fresh credential JWT bound to filesystemID and returns its
// compact serialization. A signing failure surfaces as an empty string, which
// the exchange handler treats as no credential (the round trip fails closed).
func (i *JWTCredentialIssuer) Issue(filesystemID string) string {
	now := i.now()
	claims := jwtmint.Claims{
		Issuer:       i.issuer,
		Audience:     i.audience,
		Subject:      filesystemID,
		IssuedAt:     now.Unix(),
		Expiry:       now.Add(i.ttl).Unix(),
		FilesystemID: filesystemID,
	}
	tok, err := jwtmint.Sign(i.priv, i.kid, claims)
	if err != nil {
		return ""
	}
	return tok
}

// JWKS returns the published verification key set (the public half of the
// credential signing key under the configured kid), so the filestore validator
// can verify issued credentials without any shared secret.
func (i *JWTCredentialIssuer) JWKS() jwtmint.JWKS {
	return jwtmint.JWKS{Keys: []jwtmint.JWK{jwtmint.JWKFromPublic(i.kid, &i.priv.PublicKey)}}
}
