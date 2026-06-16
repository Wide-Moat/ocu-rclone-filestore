// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// testAuthToken is the static credential every TLS test client carries; tests
// assert it surfaces verbatim as the Authorization: Bearer value.
const testAuthToken = "test-jwt"

// tlsTestServer starts an httptest TLS server invoking h for each request and
// returns the server (auto-closed via t.Cleanup) plus its leaf certificate PEM.
func tlsTestServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, []byte) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv, certPEMOf(t, srv)
}

// newTLSTestClient builds a production *Client wired to a TLS test server. The
// client trusts the server's own certificate (via ca_cert_pem) and carries
// testAuthToken. It returns the client and the server URL.
func newTLSTestClient(t *testing.T, fsID string, h http.HandlerFunc) (*Client, string) {
	t.Helper()
	srv, certPEM := tlsTestServer(t, h)
	c, err := New(srv.URL, fsID, testAuthToken, certPEM)
	if err != nil {
		t.Fatalf("brokerrpc.New(%q): %v", srv.URL, err)
	}
	return c, srv.URL
}

// newTLSTestClientOpts is newTLSTestClient with explicit ClientOptions (e.g. a
// small message ceiling for chunking tests).
func newTLSTestClientOpts(t *testing.T, fsID string, opts ClientOptions, h http.HandlerFunc) *Client {
	t.Helper()
	srv, certPEM := tlsTestServer(t, h)
	c, err := NewWithOptions(srv.URL, fsID, testAuthToken, certPEM, opts)
	if err != nil {
		t.Fatalf("brokerrpc.NewWithOptions(%q): %v", srv.URL, err)
	}
	return c
}
