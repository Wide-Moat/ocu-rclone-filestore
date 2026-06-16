// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package edgeglue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/controlplane"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/exchange"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/filestore"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

const (
	issuer   = "https://control-plane.test"
	audience = "filestore-edge"
)

var fixedNow = func() time.Time { return time.Unix(1_700_000_000, 0) }

// countingTransport wraps an http.Handler and counts how many requests reach it,
// so a test can prove the exchange peer is hit exactly once across cached calls.
type countingTransport struct {
	delegate http.Handler
	calls    int64
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(&c.calls, 1)
	rec := httptest.NewRecorder()
	c.delegate.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// newWired stands up the real control-plane + exchange peers over a shared
// credential sink that doubles as the filestore peer's validator map, exactly as
// exchange_test.go:newPaired does. It returns the control-plane (to mint weak
// JWTs), the sink (to assert issued credentials), the exchange test server, and
// a counting transport over the exchange handler.
func newWired(t *testing.T) (*controlplane.Server, map[string]string, *httptest.Server, *countingTransport) {
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
	ex := exchange.NewServer(exchange.Options{
		JWKS:        cp,
		Issuer:      issuer,
		Audience:    audience,
		Credentials: exchange.MapCredentialIssuer{Sink: sink},
		Now:         fixedNow,
	})
	ts := httptest.NewServer(ex.Handler())
	t.Cleanup(ts.Close)
	ct := &countingTransport{delegate: ex.Handler()}
	return cp, sink, ts, ct
}

func TestResolveIssuesAcceptedCredential(t *testing.T) {
	cp, sink, ts, _ := newWired(t)
	g, err := New(Options{ExchangeURL: ts.URL + exchange.ExchangePath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	weak, err := cp.Mint("fs-outputs", "write", false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred, err := g.Resolve(context.Background(), "fs-outputs", weak)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cred == "" {
		t.Fatalf("empty credential")
	}
	if cred == weak {
		t.Fatalf("resolved credential equals the weak JWT")
	}
	// The resolved credential is the one the exchange issued into the sink, and
	// the filestore peer accepts it for the validated scope.
	if sink[cred] != "fs-outputs" {
		t.Fatalf("credential not bound to fs-outputs in sink: %v", sink)
	}
	fsID, verr := filestore.StaticCredentialValidator{Credentials: sink}.Validate("Bearer " + cred)
	if verr != nil {
		t.Fatalf("filestore rejected resolved credential: %v", verr)
	}
	if fsID != "fs-outputs" {
		t.Fatalf("filestore resolved wrong scope: %q", fsID)
	}
}

func TestResolveCachesPerFilesystemID(t *testing.T) {
	cp, _, _, ct := newWired(t)
	g, err := New(Options{
		ExchangeURL: "http://exchange.test" + exchange.ExchangePath,
		Client:      &http.Client{Transport: ct},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	weak, _ := cp.Mint("fs-outputs", "write", false)

	first, err := g.Resolve(context.Background(), "fs-outputs", weak)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	second, err := g.Resolve(context.Background(), "fs-outputs", weak)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if first != second {
		t.Fatalf("cache returned a different credential: %q vs %q", first, second)
	}
	if got := atomic.LoadInt64(&ct.calls); got != 1 {
		t.Fatalf("exchange peer hit %d times, want exactly 1", got)
	}
	if cached, ok := g.Cached("fs-outputs"); !ok || cached != first {
		t.Fatalf("Cached did not reflect the resolved credential: %q %v", cached, ok)
	}
}

func TestResolveConcurrentSingleFlightStable(t *testing.T) {
	cp, _, ts, _ := newWired(t)
	g, err := New(Options{ExchangeURL: ts.URL + exchange.ExchangePath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	weak, _ := cp.Mint("fs-outputs", "write", false)

	const n = 16
	results := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			cred, rerr := g.Resolve(context.Background(), "fs-outputs", weak)
			if rerr != nil {
				t.Errorf("concurrent Resolve: %v", rerr)
				return
			}
			results[idx] = cred
		}(i)
	}
	wg.Wait()
	// Every concurrent resolver must observe the single, stable cached value.
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("concurrent resolves disagreed: %q vs %q", results[0], results[i])
		}
	}
}

func TestResolveErrorsAndCachesNothing(t *testing.T) {
	cp, _, ts, _ := newWired(t)
	g, err := New(Options{ExchangeURL: ts.URL + exchange.ExchangePath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Tampered signature: the exchange peer re-validates and refuses to issue.
	weak, _ := cp.Mint("fs-outputs", "write", false)
	parts := strings.Split(weak, ".")
	sig := []byte(parts[2])
	// Flip a character early in the signature segment (not the final char, whose
	// low bits do not all survive a base64url round trip) to corrupt R||S.
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")

	if _, rerr := g.Resolve(context.Background(), "fs-outputs", tampered); rerr == nil {
		t.Fatalf("expected error on tampered subject token")
	}
	if _, ok := g.Cached("fs-outputs"); ok {
		t.Fatalf("a failed exchange must cache nothing")
	}

	// Foreign-key token (signed by a control plane the JWKS does not publish).
	foreign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ftok, _ := jwtmint.Sign(foreign, "kid-cp", jwtmint.Claims{
		Issuer: issuer, Audience: audience, FilesystemID: "fs-outputs",
		Expiry: fixedNow().Add(time.Minute).Unix(),
	})
	if _, rerr := g.Resolve(context.Background(), "fs-outputs", ftok); rerr == nil {
		t.Fatalf("expected error on foreign-key subject token")
	}
	if _, ok := g.Cached("fs-outputs"); ok {
		t.Fatalf("a foreign-key exchange must cache nothing")
	}
}

func TestResolveRejectsEmptyFilesystemID(t *testing.T) {
	_, _, ts, _ := newWired(t)
	g, err := New(Options{ExchangeURL: ts.URL + exchange.ExchangePath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, rerr := g.Resolve(context.Background(), "", "anything"); rerr == nil {
		t.Fatalf("expected error on empty filesystem_id")
	}
}

func TestNewRejectsEmptyURL(t *testing.T) {
	if _, err := New(Options{ExchangeURL: "   "}); err == nil {
		t.Fatalf("expected error on empty exchange URL")
	}
}

func TestNewDefaultsClient(t *testing.T) {
	g, err := New(Options{ExchangeURL: "http://exchange.test/token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.client != http.DefaultClient {
		t.Fatalf("expected http.DefaultClient default")
	}
}

func TestExchangeErrorsOnTransportFailure(t *testing.T) {
	// A URL that fails to dial surfaces a round-trip error and caches nothing.
	g, err := New(Options{
		ExchangeURL: "http://127.0.0.1:0/token",
		Client:      &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, rerr := g.Resolve(context.Background(), "fs-outputs", "weak"); rerr == nil {
		t.Fatalf("expected transport error")
	}
}

func TestExchangeErrorsOnNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()
	g, _ := New(Options{ExchangeURL: ts.URL})
	if _, err := g.Resolve(context.Background(), "fs-outputs", "weak"); err == nil {
		t.Fatalf("expected error on non-200")
	}
}

func TestExchangeErrorsOnEmptyAccessToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":""}`))
	}))
	defer ts.Close()
	g, _ := New(Options{ExchangeURL: ts.URL})
	if _, err := g.Resolve(context.Background(), "fs-outputs", "weak"); err == nil {
		t.Fatalf("expected error on empty access_token")
	}
}

func TestExchangeErrorsOnGarbledBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer ts.Close()
	g, _ := New(Options{ExchangeURL: ts.URL})
	if _, err := g.Resolve(context.Background(), "fs-outputs", "weak"); err == nil {
		t.Fatalf("expected error on garbled body")
	}
}

func TestExchangeErrorsOnBadRequestBuild(t *testing.T) {
	// A control character in the URL makes http.NewRequestWithContext fail.
	g, err := New(Options{ExchangeURL: "http://exchange.test/\x7f"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := g.Resolve(context.Background(), "fs-outputs", "weak"); err == nil {
		t.Fatalf("expected request-build error")
	}
}
