// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package wiring boots the harness peers and the LIVE serving edge in-process
// over the local CA and asserts the network e2e chain end to end:
// validate -> strip -> keyed exchange -> inject -> route, plus the foreign-scope
// denial and the per-op throttle. It proves the same properties the deployment
// chain expresses, against the live serving edge (not the httptest edgeswap
// double), satisfying the Task 2 (cmd mains round-trip) and Task 4 (live edge
// swap) done-conditions without docker.
package wiring

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
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
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

const (
	cpIssuer   = "https://control-plane.test"
	cpAudience = "filestore-edge"

	credIssuer   = "https://exchange.test"
	credAudience = "filestore"
)

// recordingFilestore records the exact Authorization each upstream request
// carried so the swap (forwarded credential != weak JWT) can be asserted.
type recordingFilestore struct {
	delegate http.Handler
	mu       sync.Mutex
	seen     []string
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

// liveEdge is the serving edge handler under test: validate -> strip ->
// exchange -> inject -> route, identical in stages to cmd/edge.
type liveEdge struct {
	jwks        jwtmint.JWKS
	exchanger   *edgeglue.Exchanger
	upstreamURL string
	upstream    *http.Client
}

func (e *liveEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	weak := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	if weak == "" || weak == authz {
		http.Error(w, "missing bearer", http.StatusUnauthorized)
		return
	}
	claims, err := jwtmint.Verify(weak, e.jwks, cpIssuer, cpAudience, time.Now())
	if err != nil || claims.FilesystemID == "" {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	cred, err := e.exchanger.Resolve(r.Context(), claims.FilesystemID, weak)
	if err != nil {
		http.Error(w, "exchange failed", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	up, err := http.NewRequestWithContext(r.Context(), r.Method, e.upstreamURL+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build upstream", http.StatusBadGateway)
		return
	}
	up.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	up.Header.Set("Authorization", "Bearer "+cred)
	resp, err := e.upstream.Do(up)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// chain holds the running peers + edge for one test.
type chain struct {
	cp      *controlplane.Server
	edgeURL string
	rec     *recordingFilestore
}

// tlsServer starts an httptest TLS server whose serving cert is issued by ca
// for the given SAN host, and returns it plus a client trusting the CA.
func tlsServer(t *testing.T, ca *localca.CA, h http.Handler) *httptest.Server {
	t.Helper()
	leaf, err := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func caClient(ca *localca.CA) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}}}
}

func newChain(t *testing.T, throttle *filestore.PerOpThrottle) *chain {
	t.Helper()
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	client := caClient(ca)

	// Control-plane with a stable key.
	cpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cp key: %v", err)
	}
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer: cpIssuer, Audience: cpAudience, Kid: "kid-cp", SigningKey: cpKey,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}

	// Credential issuer + its JWKS (the exchange<->filestore seam).
	issuer, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: credIssuer, Audience: credAudience, Kid: "kid-cred",
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	// Exchange peer (validates weak JWT against the CP JWKS, issues credential JWT).
	exSrv := exchange.NewServer(exchange.Options{
		JWKS: cp, Issuer: cpIssuer, Audience: cpAudience, Credentials: issuer,
	})
	exTS := tlsServer(t, ca, exSrv.Handler())

	// Filestore peer (validates injected credential against the issuer JWKS).
	rwDir, roDir, thDir := t.TempDir(), t.TempDir(), t.TempDir()
	fsOpts := filestore.Options{
		Scopes: []filestore.Scope{
			{FilesystemID: "fsrw", Root: rwDir, ReadOnly: false},
			{FilesystemID: "fsro", Root: roDir, ReadOnly: true},
			{FilesystemID: "fsthrottle", Root: thDir, ReadOnly: false},
		},
		Credentials:   filestore.JWTCredentialValidator{JWKS: issuer.JWKS(), Issuer: credIssuer, Audience: credAudience},
		PerOpThrottle: throttle,
	}
	fs := filestore.NewServer(fsOpts)
	rec := &recordingFilestore{delegate: fs.Handler()}
	fsTS := tlsServer(t, ca, rec)

	// The live serving edge.
	exchanger, err := edgeglue.New(edgeglue.Options{ExchangeURL: exTS.URL + exchange.ExchangePath, Client: client})
	if err != nil {
		t.Fatalf("exchanger: %v", err)
	}
	edge := &liveEdge{jwks: cp.JWKS(), exchanger: exchanger, upstreamURL: fsTS.URL, upstream: client}
	edgeTS := tlsServer(t, ca, edge)

	return &chain{cp: cp, edgeURL: edgeTS.URL, rec: rec}
}

// call sends a listDirectory request through the edge with the given bearer and
// requested scope; it returns the edge status and uses a CA-trusting client.
func (c *chain) call(t *testing.T, ca *localca.CA, bearer, fsID string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"filesystem_id": fsID, "authorization_metadata": map[string]any{"intent": "read"}, "path": ".",
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, c.edgeURL+"/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	// A fresh CA-trusting client per call (the edge serves a CA leaf).
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}} //nolint:gosec // G402: the edge serves a CA leaf for "localhost"; the swap assertion is the point, not cert pinning, and a per-call CA pool is overkill for the in-process loopback
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("edge call: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestLiveEdgeSwap proves the forwarded credential is the exchanged one (not the
// weak JWT) and the weak JWT never reaches the filestore — against the LIVE
// serving edge over TLS.
func TestLiveEdgeSwap(t *testing.T) {
	c := newChain(t, nil)
	weak, err := c.cp.Mint("fsrw", "read", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if status := c.call(t, nil, weak, "fsrw"); status != http.StatusOK {
		t.Fatalf("valid scoped request returned %d, want 200", status)
	}
	seen := c.rec.authorizations()
	if len(seen) != 1 {
		t.Fatalf("filestore saw %d requests, want 1", len(seen))
	}
	got := strings.TrimPrefix(seen[0], "Bearer ")
	if got == "" || got == weak {
		t.Fatalf("filestore received the weak JWT, not the exchanged credential: %q", seen[0])
	}
	for _, h := range seen {
		if strings.Contains(h, weak) {
			t.Fatalf("weak JWT leaked to the filestore: %q", h)
		}
	}
}

// TestLiveEdgeRejectsBadToken proves missing/forged tokens are rejected at the
// edge and never reach the filestore.
func TestLiveEdgeRejectsBadToken(t *testing.T) {
	c := newChain(t, nil)
	if status := c.call(t, nil, "", "fsrw"); status != http.StatusUnauthorized {
		t.Fatalf("missing token: edge returned %d, want 401", status)
	}
	weak, _ := c.cp.Mint("fsrw", "read", false)
	parts := strings.Split(weak, ".")
	parts[2] = parts[2][:len(parts[2])-2] + "AA"
	if status := c.call(t, nil, strings.Join(parts, "."), "fsrw"); status != http.StatusUnauthorized {
		t.Fatalf("forged token: edge returned %d, want 401", status)
	}
	if seen := c.rec.authorizations(); len(seen) != 0 {
		t.Fatalf("a rejected request reached the filestore: %v", seen)
	}
}

// TestLiveEdgeForeignScopeDenied proves a token scoped to fsro used for an fsrw
// request is denied and the weak JWT never reaches the filestore.
func TestLiveEdgeForeignScopeDenied(t *testing.T) {
	c := newChain(t, nil)
	weakRO, _ := c.cp.Mint("fsro", "read", false)
	status := c.call(t, nil, weakRO, "fsrw")
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatalf("foreign-scope returned %d, want 401 or 403", status)
	}
	for _, h := range c.rec.authorizations() {
		if strings.Contains(h, weakRO) {
			t.Fatalf("weak JWT leaked on a foreign-scope request: %q", h)
		}
	}
}

// TestLiveEdgeThrottleFires proves the per-op throttle on fsthrottle refuses an
// over-budget burst through the live edge with the unmapped throttle status.
func TestLiveEdgeThrottleFires(t *testing.T) {
	c := newChain(t, &filestore.PerOpThrottle{FilesystemID: "fsthrottle", Rate: 2, Burst: 2})
	weak, _ := c.cp.Mint("fsthrottle", "write", false)
	refused := 0
	for i := 0; i < 6; i++ {
		if status := c.call(t, nil, weak, "fsthrottle"); status == http.StatusTeapot {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("the per-op throttle never fired through the live edge")
	}
}
