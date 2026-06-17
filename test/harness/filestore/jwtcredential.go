// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"fmt"
	"strings"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

// JWTCredentialValidator validates the post-exchange credential the edge
// injects when that credential is a second ES256 JWT minted by the exchange
// peer (exchange.JWTCredentialIssuer). It verifies the credential against the
// exchange's published JWKS — signature, issuer, audience, expiry — and derives
// the bound filesystem_id from the verified subject claim. Unlike
// StaticCredentialValidator it needs no shared in-process map, so the filestore
// and exchange can run as separate processes in the live e2e graph.
//
// The JWKS is read through a provider so the filestore can fetch the exchange's
// key set over the wire at startup and hold it for the run.
type JWTCredentialValidator struct {
	// JWKS is the verification key set for the issued credential JWT (the
	// exchange's published key set).
	JWKS jwtmint.JWKS
	// Issuer is the iss value the credential must carry (the exchange's issuer).
	Issuer string
	// Audience is the aud value the credential must carry (this filestore's
	// audience).
	Audience string
	// Now, when set, fixes the verification clock for deterministic tests.
	Now func() time.Time
}

// Validate verifies the injected bearer credential JWT and returns the
// filesystem_id it is bound to. A missing, malformed, or unverifiable
// credential (bad signature, unknown key, wrong issuer/audience, expired)
// yields an error the server maps to 401.
func (v JWTCredentialValidator) Validate(authzHeader string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authzHeader, prefix) {
		return "", errNoCredential
	}
	cred := strings.TrimSpace(strings.TrimPrefix(authzHeader, prefix))
	if cred == "" {
		return "", errNoCredential
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	claims, err := jwtmint.Verify(cred, v.JWKS, v.Issuer, v.Audience, now())
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoCredential, err)
	}
	if claims.FilesystemID == "" {
		return "", fmt.Errorf("%w: credential carries no filesystem_id", errNoCredential)
	}
	return claims.FilesystemID, nil
}
