// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

func newServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(Options{
		Issuer:   "https://control-plane.test",
		Audience: "filestore-edge",
		Kid:      "kid-cp",
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

func TestMintedTokenVerifiesAgainstServedJWKS(t *testing.T) {
	srv := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Fetch the JWKS exactly as the edge would.
	resp, err := http.Get(ts.URL + JWKSPath)
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	var jwks jwtmint.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	_ = resp.Body.Close()
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != "kid-cp" {
		t.Fatalf("served jwks: got %+v", jwks)
	}

	// Mint via the HTTP endpoint.
	body, _ := json.Marshal(mintRequest{FilesystemID: "fs-outputs", Intent: "write"})
	mresp, err := http.Post(ts.URL+MintPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post mint: %v", err)
	}
	if mresp.StatusCode != http.StatusOK {
		t.Fatalf("mint: got %d want 200", mresp.StatusCode)
	}
	var mr mintResponse
	if err := json.NewDecoder(mresp.Body).Decode(&mr); err != nil {
		t.Fatalf("decode mint resp: %v", err)
	}
	_ = mresp.Body.Close()

	// The minted token verifies against the served JWKS.
	now := time.Unix(1_700_000_000, 0)
	claims, err := jwtmint.Verify(mr.Token, jwks, "https://control-plane.test", "filestore-edge", now)
	if err != nil {
		t.Fatalf("verify minted token: %v", err)
	}
	if claims.FilesystemID != "fs-outputs" || claims.Intent != "write" {
		t.Fatalf("claims: got %+v", claims)
	}
}

func TestMintProgrammatic(t *testing.T) {
	srv := newServer(t)
	tok, err := srv.Mint("fs-uploads", "read", true)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	claims, err := jwtmint.Verify(tok, srv.JWKS(), "https://control-plane.test", "filestore-edge", now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.FilesystemID != "fs-uploads" || !claims.Downloadable {
		t.Fatalf("claims: got %+v", claims)
	}
}

func TestMintDefaultsIntentRead(t *testing.T) {
	srv := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	body, _ := json.Marshal(mintRequest{FilesystemID: "fs-x"})
	resp, _ := http.Post(ts.URL+MintPath, "application/json", bytes.NewReader(body))
	var mr mintResponse
	_ = json.NewDecoder(resp.Body).Decode(&mr)
	_ = resp.Body.Close()
	claims, err := jwtmint.Verify(mr.Token, srv.JWKS(), "https://control-plane.test", "filestore-edge", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Intent != "read" {
		t.Fatalf("default intent: got %q want read", claims.Intent)
	}
}

func TestMintRejectsMissingFilesystemID(t *testing.T) {
	srv := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	body, _ := json.Marshal(mintRequest{})
	resp, _ := http.Post(ts.URL+MintPath, "application/json", bytes.NewReader(body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing fsid: got %d want 400", resp.StatusCode)
	}
}

func TestMintRejectsMalformedBody(t *testing.T) {
	srv := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, _ := http.Post(ts.URL+MintPath, "application/json", strings.NewReader("{nope"))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed: got %d want 400", resp.StatusCode)
	}
}

func TestMintRejectsNonPost(t *testing.T) {
	srv := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, _ := http.Get(ts.URL + MintPath)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET mint: got %d want 405", resp.StatusCode)
	}
}

func TestJWKSRejectsNonGet(t *testing.T) {
	srv := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, _ := http.Post(ts.URL+JWKSPath, "application/json", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST jwks: got %d want 405", resp.StatusCode)
	}
}

func TestDefaultTTLAndClock(t *testing.T) {
	// No TTL and no Now => defaults apply and a token still verifies under the
	// real clock shortly after minting.
	srv, err := NewServer(Options{Issuer: "i", Audience: "a", Kid: "k"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	tok, err := srv.Mint("fs", "read", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := jwtmint.Verify(tok, srv.JWKS(), "i", "a", time.Now()); err != nil {
		t.Fatalf("verify under real clock: %v", err)
	}
}

func TestTLSServerExposesCert(t *testing.T) {
	srv := newServer(t)
	ts, der := srv.TLSServer()
	defer ts.Close()
	if len(der) == 0 {
		t.Fatalf("TLSServer returned empty cert DER")
	}
}
