// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package exchange is a test-harness peer implementing the RFC-8693 token
// exchange that trades a validated weak session JWT for the real filestore
// credential.
//
// The endpoint accepts a form-encoded request with
// grant_type=urn:ietf:params:oauth:grant-type:token-exchange and the weak
// session JWT as subject_token. The core security point is that the peer
// VALIDATES the subject token against the control-plane JWKS — signature,
// issuer, audience, and expiry — before issuing anything; it is not a static
// accept-map. Only the filesystem_id carried by a token that passes
// verification is honoured, and the issued credential is bound to exactly that
// scope. A token with a bad signature, an unknown key, the wrong
// issuer/audience, or an expired exp is rejected.
package exchange

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

// grantTypeTokenExchange is the RFC-8693 grant_type the endpoint requires.
const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: this is the fixed RFC-8693 grant_type URN, not a credential

// ExchangePath is the token-exchange endpoint.
const ExchangePath = "/token"

// JWKSProvider yields the current verification key set the subject token is
// validated against. The control-plane peer satisfies this directly.
type JWKSProvider interface {
	JWKS() jwtmint.JWKS
}

// CredentialIssuer mints and records the real filestore credential bound to a
// validated filesystem_id. The filestore peer's StaticCredentialValidator map is
// the typical sink.
type CredentialIssuer interface {
	// Issue records a fresh credential value bound to filesystemID and returns
	// it. The filestore peer accepts exactly this value for that scope.
	Issue(filesystemID string) string
}

// MapCredentialIssuer issues random opaque credentials and records them into a
// shared map (the filestore peer's StaticCredentialValidator.Credentials),
// keyed by credential value to bound filesystem_id. Its Issue method runs
// concurrently from HTTP handlers, so it must be used by pointer (&MapCredentialIssuer{…})
// — the embedded mutex guards the map write against concurrent-map-write panics.
type MapCredentialIssuer struct {
	// mu guards writes to Sink so overlapping edge exchanges do not race on the
	// map. Use MapCredentialIssuer by pointer so all handlers share one mutex.
	mu sync.Mutex
	// Sink is the credential->filesystem_id map the filestore peer reads. The
	// issuer writes new entries into it under mu.
	Sink map[string]string
}

// Issue records a fresh random credential bound to filesystemID in the sink.
// The map write is mutex-guarded because Issue is called concurrently from the
// exchange HTTP handlers.
func (m *MapCredentialIssuer) Issue(filesystemID string) string {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	cred := base64.RawURLEncoding.EncodeToString(buf)
	m.mu.Lock()
	m.Sink[cred] = filesystemID
	m.mu.Unlock()
	return cred
}

// Options carries Server construction parameters.
type Options struct {
	// JWKS provides the verification key set for the subject token.
	JWKS JWKSProvider
	// Issuer is the iss value the subject token must carry.
	Issuer string
	// Audience is the aud value the subject token must carry.
	Audience string
	// Credentials issues the real filestore credential bound to the validated
	// scope.
	Credentials CredentialIssuer
	// Now, when set, fixes the verification clock for deterministic tests.
	Now func() time.Time
}

// Server is the token-exchange peer.
type Server struct {
	jwks        JWKSProvider
	issuer      string
	audience    string
	credentials CredentialIssuer
	now         func() time.Time
	mux         *http.ServeMux
}

// NewServer constructs a Server. It returns an error if the JWKS provider or
// credential issuer is missing: an exchange that cannot verify or cannot issue
// is useless and would mask a wiring bug, but a library constructor should hand
// that back to the caller rather than crash the process.
func NewServer(opts Options) (*Server, error) {
	if opts.JWKS == nil {
		return nil, errors.New("exchange.NewServer: a JWKS provider is required")
	}
	if opts.Credentials == nil {
		return nil, errors.New("exchange.NewServer: a CredentialIssuer is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := &Server{
		jwks:        opts.JWKS,
		issuer:      opts.Issuer,
		audience:    opts.Audience,
		credentials: opts.Credentials,
		now:         now,
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc(ExchangePath, s.handleExchange)
	return s, nil
}

// MustNewServer is the panic-on-error convenience wrapper for tests and wiring
// where a missing dependency is a programming error that should fail fast.
func MustNewServer(opts Options) *Server {
	s, err := NewServer(opts)
	if err != nil {
		panic(err)
	}
	return s
}

// Handler returns the peer's HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// TLSServer wraps the peer's handler in an httptest TLS server and returns the
// server plus its CA certificate DER. The caller must Close the returned server.
func (s *Server) TLSServer() (*httptest.Server, []byte) {
	ts := httptest.NewTLSServer(s.Handler())
	return ts, ts.Certificate().Raw
}

// tokenResponse is the RFC-8693 success body: the issued real credential plus
// the standard token-type marker.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
}

// handleExchange validates the subject token and, only on success, issues the
// real filestore credential bound to the validated filesystem_id.
func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "only POST is supported")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if r.PostFormValue("grant_type") != grantTypeTokenExchange {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "expected the token-exchange grant")
		return
	}
	subjectToken := r.PostFormValue("subject_token")
	if subjectToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	// The core security point: verify the weak session JWT against the published
	// JWKS before honouring anything it claims. Every verification failure class
	// — expired, bad signature, unknown key, wrong issuer/audience — collapses to
	// a single invalid_grant so a caller cannot distinguish the classes and probe
	// the verifier.
	claims, err := jwtmint.Verify(subjectToken, s.jwks.JWKS(), s.issuer, s.audience, s.now())
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject token is not valid")
		return
	}
	if claims.FilesystemID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject token carries no filesystem_id")
		return
	}

	cred := s.credentials.Issue(claims.FilesystemID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResponse{ //nolint:gosec // G117: access_token is the RFC-8693 response field name, the value is the freshly issued test credential
		AccessToken:     cred,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
	})
}

// oauthError is the RFC-6749 error response shape.
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// writeOAuthError writes an RFC-6749 error response.
func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oauthError{Error: code, ErrorDescription: desc})
}
