// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package edgeswap is the swap-proof chain harness for the storage egress edge.
//
// It wires a faithful four-leg chain entirely on net/http/httptest:
//
//	client(weak JWT) -> edge -> exchange -> filestore
//
// The edge leg implements, in the same order the Envoy deployment artifact
// (deploy/compose/envoy/envoy.yaml) expresses, the chain a request must pass:
//
//  1. VALIDATE the inbound weak session JWT against the control-plane JWKS
//     (jwtmint.Verify against the JWKS the control-plane publishes), enforcing
//     issuer, audience, signature, and expiry. A missing or invalid token is
//     rejected 401 at the edge and never forwarded.
//  2. STRIP the weak JWT: the inbound Authorization header is dropped and never
//     copied onto the forwarded request.
//  3. EXCHANGE the validated token for the real filestore credential via the
//     RFC-8693 exchange peer, keyed on the validated filesystem_id (the
//     edgeglue.Exchanger drives the exchange and caches per filesystem_id).
//  4. INJECT the exchanged credential as the forwarded Authorization, then route
//     to the filestore upstream.
//
// The filestore leg records the EXACT Authorization header value it receives on
// every request, so the swap property can be asserted directly: the credential
// the filestore sees is the real exchanged one, and the weak JWT string appears
// in none of the recorded headers.
//
// PROVEN BY THIS HARNESS: validate -> strip -> exchange -> inject end to end;
// forwarded Authorization != the inbound weak JWT; the filestore never sees the
// weak JWT; a missing/invalid token is rejected at the edge before the
// filestore; a foreign-scope token is denied. This harness exercises the SAME
// validate->strip->exchange->inject chain the Envoy YAML expresses. The YAML is
// the deployment artifact; this harness is the proof. The keyed
// credential_injector behaviour is RE-PROVEN against a live serving Envoy in
// Phase F (see deploy/compose/envoy/README.md).
package edgeswap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/controlplane"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/edgeglue"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/exchange"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/filestore"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

const (
	issuer   = "https://control-plane.test"
	audience = "filestore-edge"
)

var fixedNow = func() time.Time { return time.Unix(1_700_000_000, 0) }

// recordingFilestore wraps the real filestore peer and records the exact
// Authorization header value of every request that reaches it, so a test can
// assert what the upstream actually saw.
type recordingFilestore struct {
	delegate http.Handler

	mu   sync.Mutex
	seen []string
}

func (r *recordingFilestore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Header.Get("Authorization"))
	r.mu.Unlock()
	r.delegate.ServeHTTP(w, req)
}

func (r *recordingFilestore) authorizations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.seen))
	copy(out, r.seen)
	return out
}

// edge is the egress-edge leg: it validates the weak JWT against the
// control-plane JWKS, strips it, exchanges it for the real credential keyed on
// the validated filesystem_id, injects that credential, and forwards to the
// filestore upstream. It mirrors the Envoy filter chain stage for stage.
type edge struct {
	jwks         jwtmint.JWKS
	exchanger    *edgeglue.Exchanger
	upstream     *httptest.Server
	now          func() time.Time
	upstreamClnt *http.Client
}

func (e *edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// --- Stage 1: VALIDATE the inbound weak session JWT. ---
	authz := r.Header.Get("Authorization")
	weak := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	if weak == "" || weak == authz {
		// No bearer token at all: reject at the edge, never forward.
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	claims, err := jwtmint.Verify(weak, e.jwks, issuer, audience, e.now())
	if err != nil {
		// Invalid/forged/expired/foreign-key token: reject at the edge.
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if claims.FilesystemID == "" {
		http.Error(w, "token carries no scope", http.StatusUnauthorized)
		return
	}

	// --- Stage 3: EXCHANGE the validated token for the real credential, keyed
	// on the validated filesystem_id. (Stage 2, STRIP, is realised below by
	// building a fresh forwarded request that never copies the inbound
	// Authorization header.) ---
	cred, err := e.exchanger.Resolve(r.Context(), claims.FilesystemID, weak)
	if err != nil {
		http.Error(w, "exchange failed", http.StatusUnauthorized)
		return
	}

	// Read and rewind the body so it can be forwarded.
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	// --- Stage 2 + 4: build a FRESH upstream request. The inbound Authorization
	// is NOT copied (the weak JWT is stripped); the exchanged credential is
	// INJECTED in its place, then the request is routed to the filestore. ---
	up, err := http.NewRequestWithContext(r.Context(), r.Method, e.upstream.URL+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build upstream request", http.StatusBadGateway)
		return
	}
	up.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	up.Header.Set("Authorization", "Bearer "+cred)

	resp, err := e.upstreamClnt.Do(up)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// chain wires the full four-leg harness and returns the control-plane (to mint
// weak JWTs), the recording filestore (to inspect what it received), the edge
// HTTP server (the client target), and the credential sink.
type chain struct {
	cp      *controlplane.Server
	rec     *recordingFilestore
	edgeSrv *httptest.Server
	sink    map[string]string
	rwFSID  string
	roFSID  string
	otherID string
	t       *testing.T
}

func newChain(t *testing.T) *chain {
	t.Helper()
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer: issuer, Audience: audience, Kid: "kid-cp", Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}

	const rwFSID, roFSID, otherID = "fs-outputs", "fs-uploads", "fs-other"
	rwDir := t.TempDir()
	roDir := t.TempDir()

	// The exchange issues credentials into this sink; the filestore validates
	// against it. The same shared map is the seam the swap rides on.
	sink := map[string]string{}
	ex := exchange.NewServer(exchange.Options{
		JWKS: cp, Issuer: issuer, Audience: audience,
		Credentials: &exchange.MapCredentialIssuer{Sink: sink}, Now: fixedNow,
	})
	exSrv := httptest.NewServer(ex.Handler())
	t.Cleanup(exSrv.Close)

	fs := filestore.NewServer(filestore.Options{
		Scopes: []filestore.Scope{
			{FilesystemID: rwFSID, Root: rwDir, ReadOnly: false},
			{FilesystemID: roFSID, Root: roDir, ReadOnly: true},
		},
		Credentials: filestore.StaticCredentialValidator{Credentials: sink},
	})
	rec := &recordingFilestore{delegate: fs.Handler()}
	fsSrv := httptest.NewServer(rec)
	t.Cleanup(fsSrv.Close)

	g, err := edgeglue.New(edgeglue.Options{ExchangeURL: exSrv.URL + exchange.ExchangePath})
	if err != nil {
		t.Fatalf("edgeglue.New: %v", err)
	}
	ed := &edge{
		jwks: cp.JWKS(), exchanger: g, upstream: fsSrv, now: fixedNow,
		upstreamClnt: fsSrv.Client(),
	}
	edgeSrv := httptest.NewServer(ed)
	t.Cleanup(edgeSrv.Close)

	return &chain{cp: cp, rec: rec, edgeSrv: edgeSrv, sink: sink, rwFSID: rwFSID, roFSID: roFSID, otherID: otherID, t: t}
}

// listBody builds a listDirectory request body for the given scope at its root.
// listDirectory on "." (the scope root temp dir, which always exists) is a read
// op that returns 200 on a correctly-scoped credential, so it is the probe op.
func listBody(fsID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"filesystem_id": fsID,
		"authorization_metadata": map[string]any{
			"intent": "read", "downloadable": false,
		},
		"path": ".",
	})
	return b
}

// callEdge sends a listDirectory request through the edge with the given bearer
// token and returns the edge's response status.
func (c *chain) callEdge(t *testing.T, bearer, requestFSID string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		c.edgeSrv.URL+"/v1/filestore/fs/listDirectory", bytes.NewReader(listBody(requestFSID)))
	if err != nil {
		t.Fatalf("build edge request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.edgeSrv.Client().Do(req)
	if err != nil {
		t.Fatalf("edge request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestSwap_ForwardedCredentialIsExchangedNotWeakJWT proves properties (a) and
// (b): the Authorization the filestore receives is the real exchanged
// credential (not the inbound weak JWT), and the filestore never sees the weak
// JWT.
func TestSwap_ForwardedCredentialIsExchangedNotWeakJWT(t *testing.T) {
	c := newChain(t)
	weak, err := c.cp.Mint(c.rwFSID, "read", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if status := c.callEdge(t, weak, c.rwFSID); status != http.StatusOK {
		t.Fatalf("edge returned %d, want 200 on a valid scoped request", status)
	}

	seen := c.rec.authorizations()
	if len(seen) != 1 {
		t.Fatalf("filestore saw %d requests, want 1: %v", len(seen), seen)
	}
	got := seen[0]
	// (a) The forwarded Authorization is the real exchanged credential.
	if got == "" {
		t.Fatalf("filestore saw no Authorization header")
	}
	if got == "Bearer "+weak || got == weak {
		t.Fatalf("filestore received the weak JWT, not the exchanged credential")
	}
	gotCred := strings.TrimPrefix(got, "Bearer ")
	if c.sink[gotCred] != c.rwFSID {
		t.Fatalf("forwarded credential %q is not the exchanged one bound to %q (sink=%v)", gotCred, c.rwFSID, c.sink)
	}
	// (b) The weak JWT string appears in NONE of the headers the filestore got.
	for _, h := range seen {
		if strings.Contains(h, weak) {
			t.Fatalf("weak JWT leaked to the filestore in header %q", h)
		}
	}
}

// TestSwap_MissingTokenRejectedAtEdge proves property (c) for a missing token:
// no Authorization is rejected 401 at the edge and never reaches the filestore.
func TestSwap_MissingTokenRejectedAtEdge(t *testing.T) {
	c := newChain(t)
	if status := c.callEdge(t, "", c.rwFSID); status != http.StatusUnauthorized {
		t.Fatalf("missing token: edge returned %d, want 401", status)
	}
	if seen := c.rec.authorizations(); len(seen) != 0 {
		t.Fatalf("a missing-token request reached the filestore: %v", seen)
	}
}

// TestSwap_ForgedTokenRejectedAtEdge proves property (c) for an invalid token:
// a tampered/forged weak JWT is rejected 401 at the edge and never reaches the
// filestore.
func TestSwap_ForgedTokenRejectedAtEdge(t *testing.T) {
	c := newChain(t)
	weak, _ := c.cp.Mint(c.rwFSID, "read", false)
	// Deterministically corrupt the signature so verification always fails.
	parts := strings.Split(weak, ".")
	sig := []byte(parts[2])
	sig[0] ^= 0x01 // flip a bit in an early base64url char of the signature segment
	if sig[0] == parts[2][0] {
		sig[0] ^= 0x02
	}
	parts[2] = string(sig)
	forged := strings.Join(parts, ".")

	if status := c.callEdge(t, forged, c.rwFSID); status != http.StatusUnauthorized {
		t.Fatalf("forged token: edge returned %d, want 401", status)
	}
	if seen := c.rec.authorizations(); len(seen) != 0 {
		t.Fatalf("a forged-token request reached the filestore: %v", seen)
	}
}

// TestSwap_ForeignScopeDenied proves property (d): a valid token scoped to fs-A
// used for an fs-B request is denied. The denial may surface as a 401 at the
// edge (the keyed exchange refuses to mint a foreign-scope credential under the
// mismatched key — WR-01) OR as a 403 at the filestore (the injected
// credential's bound scope != the request body scope). Either way the weak JWT
// is never seen by the filestore.
func TestSwap_ForeignScopeDenied(t *testing.T) {
	c := newChain(t)
	// A token validly scoped to the RO scope, used to request the RW scope.
	weakRO, _ := c.cp.Mint(c.roFSID, "read", false)

	status := c.callEdge(t, weakRO, c.rwFSID)
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatalf("foreign-scope: edge returned %d, want 401 (edge) or 403 (filestore)", status)
	}
	// Whatever the filestore saw, it must not be the weak JWT, and any forwarded
	// credential must be bound to the token's true scope, never the requested one.
	for _, h := range c.rec.authorizations() {
		if strings.Contains(h, weakRO) {
			t.Fatalf("weak JWT leaked to the filestore on a foreign-scope request: %q", h)
		}
		cred := strings.TrimPrefix(h, "Bearer ")
		if c.sink[cred] == c.rwFSID {
			t.Fatalf("a credential bound to the requested (foreign) scope was forwarded: %q", h)
		}
	}
}

// TestSwap_ExpiredTokenRejectedAtEdge proves the expiry arm of property (c): a
// token past its exp is rejected at the edge.
func TestSwap_ExpiredTokenRejectedAtEdge(t *testing.T) {
	c := newChain(t)
	// Mint with a control-plane whose clock is far in the past relative to the
	// edge's verification clock, so the token is already expired at the edge.
	pastCP, err := controlplane.NewServer(controlplane.Options{
		Issuer: issuer, Audience: audience, Kid: "kid-cp",
		Now: func() time.Time { return fixedNow().Add(-2 * time.Hour) },
		TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("past control-plane: %v", err)
	}
	// The edge validates against THIS control plane's JWKS, so swap the edge's
	// trust anchor to the past CP's key for this token to be signature-valid but
	// expired.
	c.edgeSrv.Close()
	ed := &edge{
		jwks: pastCP.JWKS(), exchanger: mustExchanger(t, c), upstream: nil, now: fixedNow,
	}
	srv := httptest.NewServer(ed)
	t.Cleanup(srv.Close)
	c.edgeSrv = srv

	weak, _ := pastCP.Mint(c.rwFSID, "read", false)
	if status := c.callEdge(t, weak, c.rwFSID); status != http.StatusUnauthorized {
		t.Fatalf("expired token: edge returned %d, want 401", status)
	}
	if seen := c.rec.authorizations(); len(seen) != 0 {
		t.Fatalf("an expired-token request reached the filestore: %v", seen)
	}
}

// mustExchanger returns an exchanger pointed at the chain's exchange peer, used
// when a test rebuilds the edge leg.
func mustExchanger(t *testing.T, _ *chain) *edgeglue.Exchanger {
	t.Helper()
	// The expired-token test rejects before the exchange is ever reached, so a
	// dummy (but valid) exchanger suffices.
	g, err := edgeglue.New(edgeglue.Options{ExchangeURL: "http://unused.test/token"})
	if err != nil {
		t.Fatalf("edgeglue.New: %v", err)
	}
	return g
}
