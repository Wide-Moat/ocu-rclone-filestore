// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
)

// capturedRequest holds details of a single captured HTTP request for
// assertion in tests.
type capturedRequest struct {
	mu       sync.Mutex
	Method   string
	Path     string
	CT       string
	AuthHdr  string
	ProtoHdr string
	Body     []byte
}

func (c *capturedRequest) set(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Method = r.Method
	c.Path = r.URL.Path
	c.CT = r.Header.Get("Content-Type")
	c.AuthHdr = r.Header.Get("Authorization")
	c.ProtoHdr = r.Header.Get("Connect-Protocol-Version")
	c.Body = body
}

// ackHandler captures the request then replies with a bare JSON ack.
func ackHandler(captured *capturedRequest) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		captured.set(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}
}

// TestClientPostsToRESTRoute verifies a unary op POSTs to the REST route
// <service_url>/v1/filestore/fs/<op>.
func TestClientPostsToRESTRoute(t *testing.T) {
	var captured capturedRequest
	c, _ := newTLSTestClient(t, "fs-test", ackHandler(&captured))

	_, _ = c.ListDirectory(context.Background(), "/")

	if captured.Method != http.MethodPost {
		t.Errorf("method = %q; want POST", captured.Method)
	}
	const wantPath = "/v1/filestore/fs/listDirectory"
	if captured.Path != wantPath {
		t.Errorf("path = %q; want %q", captured.Path, wantPath)
	}
}

// TestClientSetsContentTypeAndBearer verifies every unary op carries
// Content-Type: application/json and Authorization: Bearer <token>, and does
// NOT carry the Connect-Protocol-Version header.
func TestClientSetsContentTypeAndBearer(t *testing.T) {
	var captured capturedRequest
	c, _ := newTLSTestClient(t, "fs-test", ackHandler(&captured))

	_, _ = c.MakeDirectory(context.Background(), "/newdir")

	if captured.CT != "application/json" {
		t.Errorf("Content-Type = %q; want application/json", captured.CT)
	}
	if want := "Bearer " + testAuthToken; captured.AuthHdr != want {
		t.Errorf("Authorization = %q; want %q", captured.AuthHdr, want)
	}
	if captured.ProtoHdr != "" {
		t.Errorf("Connect-Protocol-Version = %q; want absent", captured.ProtoHdr)
	}
}

// TestClientRequestBodyCarriesAuthMetadata verifies that both a write op and a
// read op include authorization_metadata with the correct op-derived intent and
// downloadable=false, plus top-level filesystem_id.
func TestClientRequestBodyCarriesAuthMetadata(t *testing.T) {
	cases := []struct {
		name       string
		call       func(c *Client) error
		wantIntent string
	}{
		{
			name:       "read op listDirectory",
			call:       func(c *Client) error { _, err := c.ListDirectory(context.Background(), "/"); return err },
			wantIntent: "read",
		},
		{
			name:       "write op createFile",
			call:       func(c *Client) error { _, err := c.CreateFile(context.Background(), "/new.txt"); return err },
			wantIntent: "write",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured capturedRequest
			c, _ := newTLSTestClient(t, "fs-meta-test", ackHandler(&captured))

			_ = tc.call(c)

			if len(captured.Body) == 0 {
				t.Fatal("no request body captured")
			}
			var top map[string]json.RawMessage
			if err := json.Unmarshal(captured.Body, &top); err != nil {
				t.Fatalf("unmarshal body: %v", err)
			}
			if _, ok := top["filesystem_id"]; !ok {
				t.Error("filesystem_id missing from top-level request body")
			}
			rawAM, ok := top["authorization_metadata"]
			if !ok {
				t.Fatal("authorization_metadata missing from request body")
			}
			var am struct {
				Intent       string `json:"intent"`
				Downloadable bool   `json:"downloadable"`
			}
			if err := json.Unmarshal(rawAM, &am); err != nil {
				t.Fatalf("unmarshal authorization_metadata: %v", err)
			}
			if am.Intent != tc.wantIntent {
				t.Errorf("intent = %q; want %q", am.Intent, tc.wantIntent)
			}
			if am.Downloadable {
				t.Error("downloadable = true; must always be false")
			}
		})
	}
}

// TestClientUnaryMethodsExist verifies that all 16 exported unary op methods are
// present on Client and route over the TLS server with the Bearer header.
func TestClientUnaryMethodsExist(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-smoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testAuthToken {
			t.Errorf("missing Bearer header on %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	ctx := context.Background()
	_, _ = c.ListDirectory(ctx, "/")
	_, _ = c.ReadFile(ctx, "/f.txt", Range{})
	_, _ = c.ReadMetadata(ctx, "/f.txt")
	_, _ = c.GetFileMetadata(ctx, "u-abc")
	_, _ = c.ListFiles(ctx, "u-abc")
	_, _ = c.MakeDirectory(ctx, "/d")
	_, _ = c.MoveDirectory(ctx, "/src", "/dst")
	_, _ = c.RemoveDirectory(ctx, "/d")
	_, _ = c.CreateFile(ctx, "/f.txt")
	_, _ = c.CopyFile(ctx, "/src", "/dst")
	_, _ = c.MoveFile(ctx, "/src", "/dst")
	_, _ = c.RemoveFile(ctx, "/f.txt")
	_, _ = c.ImportFiles(ctx, "/dir")
	_, _ = c.ImportZip(ctx, "/archive.zip")
	_, _ = c.MigrateFilesystem(ctx)
	_, _ = c.RemoveFilesystem(ctx)
}

// TestClientNewRejectsBadInputs verifies the construction guards: a non-https
// service_url, an empty auth_token, and an empty ca_cert_pem each error.
func TestClientNewRejectsBadInputs(t *testing.T) {
	goodCert := unrelatedCAPEM(t) // any valid cert PEM satisfies the trust-anchor check

	if _, err := New("http://broker.example", "fs", testAuthToken, goodCert); err == nil {
		t.Error("non-https service_url: expected error, got nil")
	}
	if _, err := New("ftp://broker", "fs", testAuthToken, goodCert); err == nil {
		t.Error("non-https scheme: expected error, got nil")
	}
	if _, err := New("", "fs", testAuthToken, goodCert); err == nil {
		t.Error("empty service_url: expected error, got nil")
	}
	if _, err := New("https://broker", "", testAuthToken, goodCert); err == nil {
		t.Error("empty fsID: expected error, got nil")
	}
	if _, err := New("https://broker", "fs", "", goodCert); err == nil {
		t.Error("empty authToken: expected error, got nil")
	}
	if _, err := New("https://broker", "fs", testAuthToken, nil); err == nil {
		t.Error("empty caCertPEM: expected error, got nil")
	}
	if _, err := New("https://broker", "fs", testAuthToken, []byte("not a cert")); err == nil {
		t.Error("garbage caCertPEM: expected error, got nil")
	}
	// All valid: construction succeeds.
	if _, err := New("https://broker:8443", "fs", testAuthToken, goodCert); err != nil {
		t.Errorf("valid construction: %v", err)
	}
}
