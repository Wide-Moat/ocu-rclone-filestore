// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package exchange

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/controlplane"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/filestore"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

const (
	issuer   = "https://control-plane.test"
	audience = "filestore-edge"
)

var fixedNow = func() time.Time { return time.Unix(1_700_000_000, 0) }

// staticJWKS adapts a fixed key set to the JWKSProvider interface.
type staticJWKS struct{ jwks jwtmint.JWKS }

func (s staticJWKS) JWKS() jwtmint.JWKS { return s.jwks }

// newPaired wires a control-plane (token source), a filestore credential sink,
// and an exchange server validating against the control-plane JWKS.
func newPaired(t *testing.T) (*controlplane.Server, map[string]string, *httptest.Server) {
	t.Helper()
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer:   issuer,
		Audience: audience,
		Kid:      "kid-cp",
		Now:      fixedNow,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}
	sink := map[string]string{}
	ex := MustNewServer(Options{
		JWKS:        cp,
		Issuer:      issuer,
		Audience:    audience,
		Credentials: &MapCredentialIssuer{Sink: sink},
		Now:         fixedNow,
	})
	ts := httptest.NewServer(ex.Handler())
	t.Cleanup(ts.Close)
	return cp, sink, ts
}

// exchangeToken performs the RFC-8693 exchange and returns the response.
func exchangeToken(t *testing.T, ts *httptest.Server, subjectToken string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	resp, err := http.PostForm(ts.URL+ExchangePath, form)
	if err != nil {
		t.Fatalf("post exchange: %v", err)
	}
	return resp
}

func TestExchangeIssuesAcceptedCredential(t *testing.T) {
	cp, sink, ts := newPaired(t)

	weak, err := cp.Mint("fs-outputs", "write", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	resp := exchangeToken(t, ts, weak)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange: got %d want 200", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	_ = resp.Body.Close()
	if tr.AccessToken == "" {
		t.Fatalf("no access token issued")
	}

	// The issued credential is in the sink, bound to the validated scope, and the
	// filestore peer accepts it for that scope.
	if sink[tr.AccessToken] != "fs-outputs" {
		t.Fatalf("credential not bound to fs-outputs: %v", sink)
	}
	fsID, verr := filestore.StaticCredentialValidator{Credentials: sink}.Validate("Bearer " + tr.AccessToken)
	if verr != nil {
		t.Fatalf("filestore rejected issued credential: %v", verr)
	}
	if fsID != "fs-outputs" {
		t.Fatalf("filestore resolved wrong scope: %q", fsID)
	}
}

func TestExchangeRejectsBadSignature(t *testing.T) {
	cp, _, ts := newPaired(t)
	weak, _ := cp.Mint("fs-outputs", "write", false)
	// Tamper the signature deterministically. Flipping the LAST base64url
	// character of the encoded signature is unreliable: the final character only
	// carries the low bits of the last signature byte, and many flips re-encode to
	// the same decoded bytes, so the tampered token sometimes still verifies.
	// Instead, decode the signature, flip a bit in a MIDDLE byte, and re-encode:
	// that always changes the decoded R||S the verifier recomputes, so the
	// negative is deterministic across runs.
	parts := strings.Split(weak, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}
	sig[len(sig)/2] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	resp := exchangeToken(t, ts, strings.Join(parts, "."))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad signature: got %d want 400", resp.StatusCode)
	}
}

func TestExchangeRejectsForeignKey(t *testing.T) {
	_, sink, ts := newPaired(t)
	// A token signed by a DIFFERENT key (a foreign control plane) must not
	// validate against the served JWKS.
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen foreign key: %v", err)
	}
	tok, err := jwtmint.Sign(foreign, "kid-cp", jwtmint.Claims{
		Issuer: issuer, Audience: audience, FilesystemID: "fs-outputs",
		Expiry: fixedNow().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sign foreign: %v", err)
	}
	resp := exchangeToken(t, ts, tok)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign key: got %d want 400", resp.StatusCode)
	}
	if len(sink) != 0 {
		t.Fatalf("foreign token must not issue a credential, sink=%v", sink)
	}
}

func TestExchangeRejectsExpired(t *testing.T) {
	cp, _, _ := newPaired(t)
	// Mint with the fixed clock, then exchange under a clock far in the future.
	weak, _ := cp.Mint("fs-outputs", "write", false)
	ex := MustNewServer(Options{
		JWKS:        cp,
		Issuer:      issuer,
		Audience:    audience,
		Credentials: &MapCredentialIssuer{Sink: map[string]string{}},
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).Add(time.Hour) },
	})
	future := httptest.NewServer(ex.Handler())
	defer future.Close()
	resp := exchangeToken(t, future, weak)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired: got %d want 400", resp.StatusCode)
	}
}

func TestExchangeRejectsWrongGrant(t *testing.T) {
	cp, _, ts := newPaired(t)
	weak, _ := cp.Mint("fs-outputs", "write", false)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("subject_token", weak)
	resp, err := http.PostForm(ts.URL+ExchangePath, form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong grant: got %d want 400", resp.StatusCode)
	}
}

func TestExchangeRejectsMissingSubjectToken(t *testing.T) {
	_, _, ts := newPaired(t)
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	resp, err := http.PostForm(ts.URL+ExchangePath, form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing subject: got %d want 400", resp.StatusCode)
	}
}

func TestExchangeRejectsNonPost(t *testing.T) {
	_, _, ts := newPaired(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+ExchangePath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET exchange: got %d want 405", resp.StatusCode)
	}
}

func TestExchangeRejectsWrongAudience(t *testing.T) {
	cp, _, _ := newPaired(t)
	// Build an exchange that expects a different audience than the token carries.
	ex := MustNewServer(Options{
		JWKS:        cp,
		Issuer:      issuer,
		Audience:    "some-other-aud",
		Credentials: &MapCredentialIssuer{Sink: map[string]string{}},
		Now:         fixedNow,
	})
	ts := httptest.NewServer(ex.Handler())
	defer ts.Close()
	weak, _ := cp.Mint("fs-outputs", "write", false)
	resp := exchangeToken(t, ts, weak)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong audience: got %d want 400", resp.StatusCode)
	}
}

func TestMapCredentialIssuerUnique(t *testing.T) {
	sink := map[string]string{}
	iss := &MapCredentialIssuer{Sink: sink}
	a := iss.Issue("fs-1", "read")
	b := iss.Issue("fs-1", "read")
	if a == b {
		t.Fatalf("issuer produced identical credentials")
	}
	if sink[a] != "fs-1" || sink[b] != "fs-1" {
		t.Fatalf("sink bindings wrong: %v", sink)
	}
}

// TestMapCredentialIssuerConcurrent proves Issue is safe under the concurrent
// calls the exchange HTTP handlers make: many goroutines issuing against one
// shared issuer must not panic on a concurrent map write. The -race run is the
// point; without the mutex this fatally races the Sink map.
func TestMapCredentialIssuerConcurrent(t *testing.T) {
	sink := map[string]string{}
	iss := &MapCredentialIssuer{Sink: sink}

	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			_ = iss.Issue(fmt.Sprintf("fs-%d", i), "read")
		}(i)
	}
	wg.Wait()

	if len(sink) != workers {
		t.Fatalf("sink has %d entries, want %d (every concurrent Issue recorded)", len(sink), workers)
	}
}

func TestNewServerErrorsOnMissingDeps(t *testing.T) {
	cases := []Options{
		{Credentials: &MapCredentialIssuer{Sink: map[string]string{}}}, // no JWKS
		{JWKS: staticJWKS{}}, // no Credentials
	}
	for i, opts := range cases {
		if _, err := NewServer(opts); err == nil {
			t.Fatalf("case %d: expected an error for a missing dependency, got nil", i)
		}
	}

	// MustNewServer panics on the same missing dependency.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("MustNewServer with a missing dependency did not panic")
			}
		}()
		_ = MustNewServer(Options{})
	}()
}

func TestNewServerDefaultsClock(t *testing.T) {
	// No Now => time.Now is used; constructing and serving must not panic.
	cp, err := controlplane.NewServer(controlplane.Options{Issuer: issuer, Audience: audience, Kid: "kid-cp"})
	if err != nil {
		t.Fatalf("cp: %v", err)
	}
	ex := MustNewServer(Options{
		JWKS:        cp,
		Issuer:      issuer,
		Audience:    audience,
		Credentials: &MapCredentialIssuer{Sink: map[string]string{}},
	})
	ts := httptest.NewServer(ex.Handler())
	defer ts.Close()
	weak, _ := cp.Mint("fs-outputs", "write", false)
	resp := exchangeToken(t, ts, weak)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("default clock exchange: got %d want 200", resp.StatusCode)
	}
}

func TestTLSServerExposesCert(t *testing.T) {
	_, _, _ = newPaired(t)
	cp, _ := controlplane.NewServer(controlplane.Options{Issuer: issuer, Audience: audience, Kid: "k"})
	ex := MustNewServer(Options{JWKS: cp, Issuer: issuer, Audience: audience, Credentials: &MapCredentialIssuer{Sink: map[string]string{}}})
	ts, der := ex.TLSServer()
	defer ts.Close()
	if len(der) == 0 {
		t.Fatalf("empty cert DER")
	}
}

// newJWTPaired wires a control-plane token source and an exchange server whose
// credential issuer mints JWT credentials (the fleet shape), so a test can
// decode the issued credential's claims.
func newJWTPaired(t *testing.T) (*controlplane.Server, *httptest.Server) {
	t.Helper()
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer:   issuer,
		Audience: audience,
		Kid:      "kid-cp",
		Now:      fixedNow,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}
	ci, err := NewJWTCredentialIssuer(CredentialIssuerOptions{
		Issuer:   "https://exchange.test",
		Audience: "filestore",
		Kid:      "kid-cred",
		Now:      fixedNow,
	})
	if err != nil {
		t.Fatalf("credential issuer: %v", err)
	}
	ex := MustNewServer(Options{
		JWKS:        cp,
		Issuer:      issuer,
		Audience:    audience,
		Credentials: ci,
		Now:         fixedNow,
	})
	ts := httptest.NewServer(ex.Handler())
	t.Cleanup(ts.Close)
	return cp, ts
}

// decodeJWTPayload base64url-decodes the payload segment of a compact JWT.
func decodeJWTPayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("credential is not a compact JWT (%d segments)", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

// TestExchangeIssuedCredentialCarriesIntent pins the ADR-0029 seam: the intent
// claim minted on the weak session JWT survives the exchange onto the issued
// real credential, so the engine's claims-bind mode sees a single-intent grant
// per mount. A weak JWT with an empty intent yields a credential whose intent
// claim is present and empty (the claims shape carries no omitempty).
func TestExchangeIssuedCredentialCarriesIntent(t *testing.T) {
	cp, ts := newJWTPaired(t)

	for _, tc := range []struct {
		name   string
		intent string
	}{
		{name: "write intent propagates", intent: "write"},
		{name: "read intent propagates", intent: "read"},
		{name: "empty intent carries an empty claim", intent: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			weak, err := cp.Mint("fsrw", tc.intent, false)
			if err != nil {
				t.Fatalf("mint weak JWT: %v", err)
			}
			resp := exchangeToken(t, ts, weak)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("exchange status = %d, want 200", resp.StatusCode)
			}
			var body struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			claims := decodeJWTPayload(t, body.AccessToken)
			// The intent claim carries no omitempty, so it is always present on
			// the issued credential — present-and-empty for an empty intent, not
			// absent. Assert presence separately from value so the empty case
			// verifies the real key-present-empty contract instead of collapsing
			// an absent key and an empty string into the same "".
			raw, present := claims["intent"]
			if !present {
				t.Fatalf("issued credential omits the intent claim; the exchange must always carry it (present-and-empty for an empty intent)")
			}
			got, _ := raw.(string)
			if got != tc.intent {
				t.Fatalf("issued credential intent = %q, want %q (the exchange must carry the weak JWT's minted claim)", got, tc.intent)
			}
		})
	}
}
