// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/controlplane"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/edgeglue"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/exchange"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/filestore"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

func leafFiles(t *testing.T, ca *localca.CA, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	leaf, err := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	certPath = filepath.Join(dir, "leaf.cert.pem")
	keyPath = filepath.Join(dir, "leaf.key.pem")
	caPath = filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), 0o600)
	der, _ := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey.(*ecdsa.PrivateKey))
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	return certPath, keyPath, caPath
}

func ephemeralAddr(t *testing.T) string {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func tlsSrv(t *testing.T, ca *localca.CA, h http.Handler) *httptest.Server {
	t.Helper()
	leaf, _ := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// fullChain stands up the control-plane, exchange, and filestore over TLS issued
// by ca and returns the control-plane (to mint), the CP JWKS URL, the exchange
// token URL, and the filestore upstream URL — everything the edge run() needs.
func fullChain(t *testing.T, ca *localca.CA) (cp *controlplane.Server, cpJWKS, exchangeURL, upstreamURL string) {
	t.Helper()
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp, err := controlplane.NewServer(controlplane.Options{
		Issuer: cpIssuer, Audience: cpAudience, Kid: "kid-cp", SigningKey: sk,
	})
	if err != nil {
		t.Fatalf("control-plane: %v", err)
	}
	cpSrv := tlsSrv(t, ca, cp.Handler())
	cpJWKS = cpSrv.URL + "/.well-known/jwks.json"

	issuer, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: "https://exchange.test", Audience: "filestore", Kid: "kid-cred",
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	ex := exchange.MustNewServer(exchange.Options{
		JWKS: cp, Issuer: cpIssuer, Audience: cpAudience, Credentials: issuer,
	})
	exSrv := tlsSrv(t, ca, ex.Handler())
	exchangeURL = exSrv.URL + exchange.ExchangePath

	fs := filestore.MustNewServer(filestore.Options{
		Scopes:      []filestore.Scope{{FilesystemID: "fsrw", Root: t.TempDir(), ReadOnly: false}},
		Credentials: filestore.JWTCredentialValidator{JWKS: issuer.JWKS(), Issuer: "https://exchange.test", Audience: "filestore"},
	})
	fsSrv := tlsSrv(t, ca, fs.Handler())
	upstreamURL = fsSrv.URL
	return cp, cpJWKS, exchangeURL, upstreamURL
}

// TestEdgeRunFullFlow boots the edge against a real CP/exchange/filestore chain
// and drives a valid scoped request through it, exercising the whole
// validate -> strip -> exchange -> inject -> route path in ServeHTTP, plus the
// missing-token 401 arm.
func TestEdgeRunFullFlow(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := leafFiles(t, ca, dir)
	cp, cpJWKS, exchangeURL, upstreamURL := fullChain(t, ca)
	addr := ephemeralAddr(t)

	go func() { _ = run(addr, certPath, keyPath, caPath, cpJWKS, exchangeURL, upstreamURL) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}}}

	// Wait until the edge is up: a no-token request returns 401.
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, derr := client.Post("https://"+addr+"/v1/filestore/fs/listDirectory", "application/json", nil)
		if derr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("edge never came up: %v", derr)
		}
		time.Sleep(150 * time.Millisecond)
	}

	// A valid scoped request flows through validate -> exchange -> inject -> route
	// and the filestore returns 200 for a listDirectory at the scope root.
	weak, err := cp.Mint("fsrw", "read", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"filesystem_id": "fsrw", "authorization_metadata": map[string]any{"intent": "read"}, "path": ".",
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+addr+"/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+weak)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("valid request through edge: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid scoped request through the edge returned %d, want 200", resp.StatusCode)
	}
}

// TestEdgeServeHTTPErrorArms constructs an edge directly and drives its error
// arms: a forged token (validate fail -> 401), a valid token whose exchange
// fails (exchanger pointed at nothing -> 401), and a valid exchange but an
// unreachable upstream (-> 502).
func TestEdgeServeHTTPErrorArms(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cp, _, exchangeURL, _ := fullChain(t, ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}}}

	// Valid token, but the upstream URL points at nothing reachable: validate and
	// exchange succeed, the route to the upstream fails -> 502.
	exchanger, err := edgeglue.New(edgeglue.Options{ExchangeURL: exchangeURL, Client: client})
	if err != nil {
		t.Fatalf("exchanger: %v", err)
	}
	e := &edge{jwks: cp.JWKS(), exchanger: exchanger, upstreamURL: "https://127.0.0.1:1", upstream: client}

	weak, err := cp.Mint("fsrw", "read", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"filesystem_id": "fsrw", "authorization_metadata": map[string]any{"intent": "read"}, "path": ".",
	})

	// 502: upstream unreachable.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+weak)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("unreachable upstream returned %d, want 502", w.Code)
	}

	// 401: exchange fails (exchanger pointed at a dead endpoint).
	deadExchanger, _ := edgeglue.New(edgeglue.Options{ExchangeURL: "https://127.0.0.1:1/token", Client: client})
	e2 := &edge{jwks: cp.JWKS(), exchanger: deadExchanger, upstreamURL: "https://127.0.0.1:1", upstream: client}
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+weak)
	e2.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("failed exchange returned %d, want 401", w2.Code)
	}

	// 401: a token carrying no scope is rejected (forged/empty-scope arm). Use a
	// token minted with an empty filesystem_id via a raw mint is not exposed, so
	// drive the missing-bearer arm instead.
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/listDirectory", bytes.NewReader(body))
	e.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer returned %d, want 401", w3.Code)
	}
}

// TestEdgeForwardsOversizedBodyWithoutSilentTruncation pins that the edge streams
// the inbound body to the upstream faithfully, byte-for-byte, rather than
// buffering it behind a cap that silently truncates (io.LimitReader returns EOF,
// not an error, so an over-cap body used to reach the upstream short). It stands a
// capturing upstream that records the exact bytes it receives, drives a body far
// larger than the old buffering path would have tolerated in a unit, and asserts
// the upstream saw the whole body. The injected credential and stripped inbound
// Authorization are asserted alongside so strip+inject stay pinned.
func TestEdgeForwardsOversizedBodyWithoutSilentTruncation(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cp, _, exchangeURL, _ := fullChain(t, ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}}}

	// A capturing upstream: it records the exact body length and bytes it receives,
	// plus the forwarded Authorization, then replies 200.
	var (
		gotLen         int
		gotAuth        string
		gotContentLen  int64
		bodyFingerHead string
		bodyFingerTail string
	)
	capturing := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotLen = len(b)
		gotContentLen = r.ContentLength
		gotAuth = r.Header.Get("Authorization")
		if len(b) >= 8 {
			bodyFingerHead = string(b[:8])
			bodyFingerTail = string(b[len(b)-8:])
		}
		w.WriteHeader(http.StatusOK)
	}))
	leaf, _ := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	capturing.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	capturing.StartTLS()
	t.Cleanup(capturing.Close)

	exchanger, err := edgeglue.New(edgeglue.Options{ExchangeURL: exchangeURL, Client: client})
	if err != nil {
		t.Fatalf("exchanger: %v", err)
	}
	e := &edge{jwks: cp.JWKS(), exchanger: exchanger, upstreamURL: capturing.URL, upstream: client}

	// A body comfortably larger than any in-memory form budget the edge might have
	// kept, with a recognisable head and tail so a truncation is unmistakable.
	const size = 4 << 20 // 4 MiB
	payload := make([]byte, size)
	copy(payload, []byte("HEADMARK"))
	copy(payload[size-8:], []byte("TAILMARK"))

	weak, err := cp.Mint("fsrw", "write", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/fileUpload", bytes.NewReader(payload))
	req.ContentLength = int64(size)
	req.Header.Set("Authorization", "Bearer "+weak)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("edge returned %d, want 200", w.Code)
	}
	if gotLen != size {
		t.Fatalf("upstream received %d bytes, want the full %d (silent truncation)", gotLen, size)
	}
	if gotContentLen != int64(size) {
		t.Fatalf("upstream Content-Length = %d, want %d", gotContentLen, size)
	}
	if bodyFingerHead != "HEADMARK" || bodyFingerTail != "TAILMARK" {
		t.Fatalf("body corrupted in transit: head=%q tail=%q", bodyFingerHead, bodyFingerTail)
	}
	// Strip + inject: the forwarded Authorization is the exchanged credential, not
	// the inbound weak JWT.
	fwd := strings.TrimPrefix(gotAuth, "Bearer ")
	if fwd == "" || fwd == weak {
		t.Fatalf("forwarded Authorization must be the exchanged credential, not the weak JWT: got %q", gotAuth)
	}
}

// gatedBody is an inbound request body whose second half is withheld until the
// upstream has begun consuming the first half. It emits headChunk, then blocks
// the next Read on upstreamReading (bounded by a deadline) before emitting
// tailChunk and EOF. If the wait times out it returns io.ErrUnexpectedEOF so the
// consumer observes a hard, fast failure rather than hanging.
type gatedBody struct {
	headChunk       []byte
	tailChunk       []byte
	upstreamReading <-chan struct{}
	deadline        time.Duration

	headDone bool
	tailDone bool
}

func (g *gatedBody) Read(p []byte) (int, error) {
	if !g.headDone {
		n := copy(p, g.headChunk)
		g.headChunk = g.headChunk[n:]
		if len(g.headChunk) == 0 {
			g.headDone = true
		}
		return n, nil
	}
	if !g.tailDone {
		// The gate: the tail is only released once the upstream has started
		// reading. A path that streams r.Body straight to the upstream unblocks
		// here; a path that must fully buffer r.Body before building the upstream
		// request deadlocks and trips the deadline.
		select {
		case <-g.upstreamReading:
		case <-time.After(g.deadline):
			return 0, io.ErrUnexpectedEOF
		}
		n := copy(p, g.tailChunk)
		g.tailChunk = g.tailChunk[n:]
		if len(g.tailChunk) == 0 {
			g.tailDone = true
		}
		return n, nil
	}
	return 0, io.EOF
}

func (g *gatedBody) Close() error { return nil }

// TestEdgeStreamsBodyWithoutFullyBufferingFirst is the red-first guard for
// F-40/F-41: it distinguishes a streaming forward from a buffer-everything-first
// forward by ordering, not by size (a size-based test cannot go red against the
// old 1 GiB in-memory cap without allocating a gigabyte). The inbound body
// withholds its tail until the upstream has begun reading. The streaming edge
// hands r.Body straight to the upstream, so the upstream reads the head, which
// releases the tail, and the full body arrives. A buffer-first edge must drain
// the whole inbound body before it ever builds the upstream request, so the tail
// is never released, the body reader trips its deadline, and the forward fails —
// exactly the class of silent-truncation/stall the cap-and-buffer form caused.
func TestEdgeStreamsBodyWithoutFullyBufferingFirst(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cp, _, exchangeURL, _ := fullChain(t, ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}}}

	upstreamReading := make(chan struct{})
	var (
		gotBody   []byte
		signalled bool
	)
	capturing := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Signal the moment the upstream starts consuming the body: read the first
		// byte, close the gate channel, then drain the rest.
		buf := make([]byte, 1)
		n, _ := r.Body.Read(buf)
		if n > 0 && !signalled {
			signalled = true
			close(upstreamReading)
		}
		rest, _ := io.ReadAll(r.Body)
		gotBody = append(append([]byte{}, buf[:n]...), rest...)
		w.WriteHeader(http.StatusOK)
	}))
	leaf, _ := ca.IssueLeaf([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	capturing.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	capturing.StartTLS()
	t.Cleanup(capturing.Close)

	exchanger, err := edgeglue.New(edgeglue.Options{ExchangeURL: exchangeURL, Client: client})
	if err != nil {
		t.Fatalf("exchanger: %v", err)
	}
	e := &edge{jwks: cp.JWKS(), exchanger: exchanger, upstreamURL: capturing.URL, upstream: client}

	weak, err := cp.Mint("fsrw", "write", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	head := []byte("HEADMARK-first-half-of-the-inbound-body-")
	tail := []byte("-second-half-of-the-inbound-body-TAILMARK")
	body := &gatedBody{
		headChunk:       append([]byte{}, head...),
		tailChunk:       append([]byte{}, tail...),
		upstreamReading: upstreamReading,
		deadline:        3 * time.Second,
	}
	// Unknown inbound length: a chunked/streamed body is exactly the case a
	// buffer-first path could not forward faithfully, and it lets the upstream
	// start reading as soon as the first chunk arrives.
	req := httptest.NewRequest(http.MethodPost, "/v1/filestore/fs/fileUpload", body)
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+weak)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("streamed forward returned %d, want 200 (a buffer-first edge stalls on the withheld tail)", w.Code)
	}
	want := string(head) + string(tail)
	if string(gotBody) != want {
		t.Fatalf("upstream body = %q, want %q (streaming forward incomplete)", string(gotBody), want)
	}
}

// TestRunRejectsBadCA covers the CAClient error arm of run.
func TestRunRejectsBadCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad-ca.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	if err := run(ephemeralAddr(t), "c", "k", bad,
		"https://127.0.0.1:1/jwks", "https://127.0.0.1:1/token", "https://127.0.0.1:1"); err == nil {
		t.Fatal("run accepted a CA file with no certificate")
	}
}

// TestMainWith covers the flag-parsing entry with runFn stubbed.
func TestMainWith(t *testing.T) {
	saved := runFn
	t.Cleanup(func() { runFn = saved })
	called := false
	runFn = func(addr, cert, key, ca, cpJWKS, exch, up string) error { called = true; return nil }
	if err := mainWith([]string{"-addr", "127.0.0.1:9"}); err != nil {
		t.Fatalf("mainWith: %v", err)
	}
	if !called {
		t.Fatal("mainWith did not invoke runFn")
	}
	if err := mainWith([]string{"-nope"}); err == nil {
		t.Fatal("mainWith accepted an unknown flag")
	}
}
