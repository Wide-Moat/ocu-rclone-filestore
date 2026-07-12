// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cmdtest

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

// exitingMain models a peer main's error path: it prints the "<name>:" prefixed
// error and exits non-zero. AssertMainExitsNonZero drives it in the re-exec'd
// child.
func exitingMain() {
	fmt.Fprintln(os.Stderr, "cmdtestbin: boom")
	os.Exit(1)
}

// TestAssertMainExitsNonZero exercises the shared re-exec dance end to end: the
// parent branch re-execs this test filtered to itself with the guard set, and
// the child branch runs exitingMain, which prints the prefix and exits 1. This
// drives both branches of AssertMainExitsNonZero and every parent-side
// assertion on the success path.
func TestAssertMainExitsNonZero(t *testing.T) {
	AssertMainExitsNonZero(t, "cmdtestbin", "^TestAssertMainExitsNonZero$", exitingMain)
}

// TestNewTLSServerAndHTTPClientRoundTrip stands up a CA-served TLS endpoint and
// proves a client from HTTPClient — trusting only that CA — completes the
// handshake and reads the body back, covering NewTLSServer and HTTPClient.
func TestNewTLSServerAndHTTPClientRoundTrip(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := NewTLSServer(t, ca, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	resp, err := HTTPClient(ca).Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q; want %q", body, "ok")
	}
}

// TestEphemeralAddr checks EphemeralAddr returns a parsable loopback host:port
// the kernel handed out and then released.
func TestEphemeralAddr(t *testing.T) {
	addr := EphemeralAddr(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("host = %q; want 127.0.0.1", host)
	}
	if port == "" || port == "0" {
		t.Fatalf("port = %q; want a concrete port", port)
	}
}
