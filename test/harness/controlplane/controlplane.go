// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package controlplane is a test-harness peer that mints the weak ES256 session
// JWT and publishes the verification key set.
//
// The session token is scoped {filesystem_id, intent, downloadable} and is
// short-lived; it carries no authorising weight beyond naming the scope a later
// token-exchange step may trade it for the real filestore credential. The peer
// signs with a P-256 key it holds and serves the matching public key as a JWKS
// at /.well-known/jwks.json, the endpoint an inspecting edge fetches via
// remote_jwks. A mint route issues a token for a given filesystem_id so the e2e
// fixtures have a subject token to exchange.
package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

// JWKSPath is the well-known endpoint the edge fetches the verification key set
// from.
const JWKSPath = "/.well-known/jwks.json"

// MintPath is the endpoint that issues a weak session JWT for a filesystem_id.
const MintPath = "/mint"

// defaultTokenTTL is the short lifetime stamped on a minted session token.
const defaultTokenTTL = 5 * time.Minute

// Options carries Server construction parameters.
type Options struct {
	// Issuer is stamped as the token iss and is the value the exchange peer
	// enforces. It is typically the control-plane's own URL.
	Issuer string
	// Audience is stamped as the token aud (the inspecting edge / exchange
	// identity the token is intended for).
	Audience string
	// Kid is the key id stamped in the JOSE header and published in the JWKS.
	Kid string
	// TTL overrides the default session-token lifetime when non-zero.
	TTL time.Duration
	// Now, when set, fixes the clock for deterministic tests. The zero value
	// uses time.Now.
	Now func() time.Time
}

// Server is the control-plane peer: it holds the signing key and serves the
// mint and JWKS endpoints.
type Server struct {
	priv     *ecdsa.PrivateKey
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
	mux      *http.ServeMux
}

// NewServer constructs a Server, generating a fresh P-256 signing key.
func NewServer(opts Options) (*Server, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := &Server{
		priv:     priv,
		kid:      opts.Kid,
		issuer:   opts.Issuer,
		audience: opts.Audience,
		ttl:      ttl,
		now:      now,
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc(JWKSPath, s.handleJWKS)
	s.mux.HandleFunc(MintPath, s.handleMint)
	return s, nil
}

// Handler returns the peer's HTTP handler so callers can serve it under TLS or
// drive it with httptest.
func (s *Server) Handler() http.Handler { return s.mux }

// TLSServer wraps the peer's handler in an httptest TLS server and returns the
// server plus its CA certificate PEM. The caller must Close the returned server.
func (s *Server) TLSServer() (*httptest.Server, []byte) {
	ts := httptest.NewTLSServer(s.Handler())
	return ts, ts.Certificate().Raw
}

// JWKS returns the published verification key set (the public half of the
// signing key under the configured kid).
func (s *Server) JWKS() jwtmint.JWKS {
	return jwtmint.JWKS{Keys: []jwtmint.JWK{jwtmint.JWKFromPublic(s.kid, &s.priv.PublicKey)}}
}

// Mint signs a weak session JWT scoped to the given filesystem_id, intent, and
// downloadable flag. It is the programmatic form of the mint endpoint, used by
// the e2e fixtures and the exchange-peer tests.
func (s *Server) Mint(filesystemID, intent string, downloadable bool) (string, error) {
	now := s.now()
	claims := jwtmint.Claims{
		Issuer:       s.issuer,
		Audience:     s.audience,
		Subject:      filesystemID,
		IssuedAt:     now.Unix(),
		Expiry:       now.Add(s.ttl).Unix(),
		FilesystemID: filesystemID,
		Intent:       intent,
		Downloadable: downloadable,
	}
	return jwtmint.Sign(s.priv, s.kid, claims)
}

// handleJWKS serves the verification key set.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "only GET is supported")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.JWKS())
}

// mintRequest is the JSON body of a mint request.
type mintRequest struct {
	FilesystemID string `json:"filesystem_id"`
	Intent       string `json:"intent"`
	Downloadable bool   `json:"downloadable"`
}

// mintResponse is the JSON body of a successful mint response.
type mintResponse struct {
	Token string `json:"token"`
}

// handleMint issues a weak session JWT for the requested filesystem_id.
func (s *Server) handleMint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}
	var req mintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if req.FilesystemID == "" {
		writeError(w, http.StatusBadRequest, "filesystem_id is required")
		return
	}
	intent := req.Intent
	if intent == "" {
		intent = "read"
	}
	tok, err := s.Mint(req.FilesystemID, intent, req.Downloadable)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mint failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(mintResponse{Token: tok})
}

// errorBody is the JSON shape returned for a non-2xx outcome.
type errorBody struct {
	Error string `json:"error"`
}

// writeError writes a non-2xx JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg})
}
