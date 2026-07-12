// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package cmdtest is shared scaffolding for the harness peer command tests. It
// is imported ONLY from _test.go files, never from a file that compiles into a
// shipped binary, so it may safely pull in testing-only packages
// (net/http/httptest, testing) that must not enter any peer binary's graph.
//
// It holds two families of helper: the main-exit re-exec dance the peer mains
// share to prove their os.Exit(1) failure path, and the CA-backed TLS server
// and client builders the peer tests share to stand up leaf-served endpoints
// over a harness CA.
package cmdtest

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

// mainExitGuard is the environment variable that switches a re-exec of the
// calling test binary into the child that runs the peer main with failing args.
// A peer main calls os.Exit on its error path, which cannot run in-process
// without killing the test binary, so the child re-exec turns that exit into an
// observable process result the parent inspects.
const mainExitGuard = "OCU_TEST_RUN_MAIN_FAILURE"

// AssertMainExitsNonZero proves a peer main's failure path. When the guard env
// var is set — i.e. this call is running inside the re-exec'd child — it points
// os.Args at binaryName with an unknown flag and calls mainFn, which is expected
// to print the "<binaryName>:" error prefix and call os.Exit(1); the trailing
// return is never reached. Otherwise it re-execs the calling test binary
// filtered to runFilter (the calling test's own name) with the guard set, and
// asserts the child exited with code 1 carrying the "<binaryName>:" prefix on
// its combined output.
//
// runFilter must anchor the calling test's name (for example
// "^TestMainExitsNonZeroOnError$") so the child re-enters the same test and thus
// the guard branch of this helper.
func AssertMainExitsNonZero(t *testing.T, binaryName, runFilter string, mainFn func()) {
	t.Helper()
	if os.Getenv(mainExitGuard) == "1" {
		os.Args = []string{binaryName, "-nope"}
		mainFn()
		return // unreachable: mainFn exits on the error path
	}
	cmd := exec.Command(os.Args[0], "-test.run="+runFilter, "-test.v")
	cmd.Env = append(os.Environ(), mainExitGuard+"=1")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("child error = %v; want a non-zero exit\noutput:\n%s", err, out)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("child exit code = %d; want 1\noutput:\n%s", exitErr.ExitCode(), out)
	}
	if !strings.Contains(string(out), binaryName+":") {
		t.Fatalf("child stderr missing the error prefix; got:\n%s", out)
	}
}

// NewTLSServer starts an httptest server whose serving certificate is a
// localhost leaf issued by ca, so a client trusting only ca's CA PEM completes
// the handshake to it. It registers t.Cleanup(srv.Close) and returns the
// started server. The serving config pins TLS 1.2 as its floor.
func NewTLSServer(t *testing.T, ca *localca.CA, h http.Handler) *httptest.Server {
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

// HTTPClient returns an http.Client that trusts only ca's CA, so it verifies a
// leaf ca issued and rejects anything else. The client config pins TLS 1.2 as
// its floor.
func HTTPClient(ca *localca.CA) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12},
		},
	}
}

// EphemeralAddr reserves a loopback TCP address the kernel is free to hand back
// and returns it as host:port. The listener is closed before return so a caller
// may bind the address itself.
func EphemeralAddr(t *testing.T) string {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
