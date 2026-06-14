// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
)

// unixTestServer creates a temporary AF_UNIX socket, starts an httptest server
// on it, and returns the socket path plus a cleanup function. The handler h
// is called for every request received.
//
// macOS limits AF_UNIX socket paths to 104 bytes (including the null
// terminator), so we use os.MkdirTemp with a short prefix instead of
// t.TempDir() to keep the path well under the limit.
func unixTestServer(t *testing.T, h http.Handler) (socketPath string, cleanup func()) {
	t.Helper()

	// Use a short directory to stay well under the 104-byte macOS AF_UNIX
	// path limit. os.TempDir() on macOS is /var/folders/... which is already
	// long; we need the filename to be short too.
	dir, err := os.MkdirTemp("", "brpc")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	socketPath = filepath.Join(dir, "b.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}

	srv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: h},
	}
	srv.Start()

	return socketPath, func() {
		srv.Close()
		_ = os.RemoveAll(dir)
	}
}

// capturedRequest holds details of a single captured HTTP request for
// assertion in tests.
type capturedRequest struct {
	Method      string
	Path        string
	ContentType string
	VersionHdr  string
	Body        []byte
}

// capturingHandler captures the first incoming request into *captured and
// replies with an empty JSON object (bare ack).
func capturingHandler(t *testing.T, captured *capturedRequest) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		*captured = capturedRequest{
			Method:      r.Method,
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
			VersionHdr:  r.Header.Get("Connect-Protocol-Version"),
			Body:        body,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
}

// TestClientPostsToCorrectRoute verifies that a unary op POSTs to the correct
// Connect-RPC route path under ocu.filestore.v1alpha.FilesystemService.
func TestClientPostsToCorrectRoute(t *testing.T) {
	var captured capturedRequest
	sockPath, cleanup := unixTestServer(t, capturingHandler(t, &captured))
	defer cleanup()

	c, err := brokerrpc.New(sockPath, "fs-test")
	if err != nil {
		t.Fatalf("brokerrpc.New: %v", err)
	}

	_, _ = c.ListDirectory(context.Background(), "/")

	if captured.Method != http.MethodPost {
		t.Errorf("method = %q; want POST", captured.Method)
	}
	const wantPath = "/ocu.filestore.v1alpha.FilesystemService/listDirectory"
	if captured.Path != wantPath {
		t.Errorf("path = %q; want %q", captured.Path, wantPath)
	}
}

// TestClientSetsContentTypeAndVersionHeader verifies that every unary op
// carries Content-Type: application/json and Connect-Protocol-Version: 1.
func TestClientSetsContentTypeAndVersionHeader(t *testing.T) {
	var captured capturedRequest
	sockPath, cleanup := unixTestServer(t, capturingHandler(t, &captured))
	defer cleanup()

	c, err := brokerrpc.New(sockPath, "fs-test")
	if err != nil {
		t.Fatalf("brokerrpc.New: %v", err)
	}

	_, _ = c.MakeDirectory(context.Background(), "/newdir")

	if captured.ContentType != "application/json" {
		t.Errorf("Content-Type = %q; want application/json", captured.ContentType)
	}
	if captured.VersionHdr != "1" {
		t.Errorf("Connect-Protocol-Version = %q; want 1", captured.VersionHdr)
	}
}

// TestClientDialsPerSessionSocket verifies that two clients built from
// different socket paths dial different sockets. If both dialled the same
// socket, one would get connection refused.
func TestClientDialsPerSessionSocket(t *testing.T) {
	var cap1, cap2 capturedRequest

	sock1, clean1 := unixTestServer(t, capturingHandler(t, &cap1))
	defer clean1()
	sock2, clean2 := unixTestServer(t, capturingHandler(t, &cap2))
	defer clean2()

	c1, err := brokerrpc.New(sock1, "fs-1")
	if err != nil {
		t.Fatalf("brokerrpc.New sock1: %v", err)
	}
	c2, err := brokerrpc.New(sock2, "fs-2")
	if err != nil {
		t.Fatalf("brokerrpc.New sock2: %v", err)
	}

	_, _ = c1.RemoveFile(context.Background(), "/a.txt")
	_, _ = c2.RemoveFile(context.Background(), "/b.txt")

	// Each server must have received exactly one request to confirm
	// the two clients reached different sockets.
	if len(cap1.Body) == 0 {
		t.Error("c1 did not reach sock1")
	}
	if len(cap2.Body) == 0 {
		t.Error("c2 did not reach sock2")
	}
}

// TestClientRequestBodyCarriesAuthMetadata verifies that both a write op and
// a read op include authorization_metadata in the request body with the
// correct op-derived intent and downloadable=false, plus top-level
// filesystem_id.
func TestClientRequestBodyCarriesAuthMetadata(t *testing.T) {
	cases := []struct {
		name          string
		call          func(c *brokerrpc.Client) error
		wantIntent    string
		wantFSIDInTop bool
	}{
		{
			name: "read op listDirectory",
			call: func(c *brokerrpc.Client) error {
				_, err := c.ListDirectory(context.Background(), "/")
				return err
			},
			wantIntent:    "read",
			wantFSIDInTop: true,
		},
		{
			name: "write op createFile",
			call: func(c *brokerrpc.Client) error {
				_, err := c.CreateFile(context.Background(), "/new.txt")
				return err
			},
			wantIntent:    "write",
			wantFSIDInTop: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured capturedRequest
			sockPath, cleanup := unixTestServer(t, capturingHandler(t, &captured))
			defer cleanup()

			c, err := brokerrpc.New(sockPath, "fs-meta-test")
			if err != nil {
				t.Fatalf("brokerrpc.New: %v", err)
			}

			_ = tc.call(c)

			if len(captured.Body) == 0 {
				t.Fatal("no request body captured")
			}

			var top map[string]json.RawMessage
			if err := json.Unmarshal(captured.Body, &top); err != nil {
				t.Fatalf("unmarshal body: %v", err)
			}

			if tc.wantFSIDInTop {
				if _, ok := top["filesystem_id"]; !ok {
					t.Error("filesystem_id missing from top-level request body")
				}
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

// TestClientUnaryMethodsExist verifies that all 16 exported unary op methods
// are present on Client and can be called without panicking (the ops that
// need only a path or a uuid). This is a compile-time + basic-smoke test.
func TestClientUnaryMethodsExist(t *testing.T) {
	sockPath, cleanup := unixTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer cleanup()

	c, err := brokerrpc.New(sockPath, "fs-smoke")
	if err != nil {
		t.Fatalf("brokerrpc.New: %v", err)
	}

	ctx := context.Background()
	// Read ops
	_, _ = c.ListDirectory(ctx, "/")
	_, _ = c.ReadFile(ctx, "/f.txt", brokerrpc.Range{})
	_, _ = c.ReadMetadata(ctx, "/f.txt")
	_, _ = c.GetFileMetadata(ctx, "u-abc")
	_, _ = c.ListFiles(ctx, "u-abc")
	// Write ops
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

// TestDialerTargetsSuppliedSocketPath verifies that the dialer targets the
// socket path passed to New, not any shared constant.
func TestDialerTargetsSuppliedSocketPath(t *testing.T) {
	// Start one server, deliberately do NOT start the second path.
	var captured capturedRequest
	realSock, cleanup := unixTestServer(t, capturingHandler(t, &captured))
	defer cleanup()

	fakeDir, err := os.MkdirTemp("", "brpc")
	if err != nil {
		t.Fatalf("mkdirtemp for fake socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fakeDir) })
	fakeSock := filepath.Join(fakeDir, "n.sock")

	// Client pointed at real socket should succeed.
	real, err := brokerrpc.New(realSock, "fs-real")
	if err != nil {
		t.Fatalf("brokerrpc.New real: %v", err)
	}
	_, _ = real.ListDirectory(context.Background(), "/")
	if len(captured.Body) == 0 {
		t.Error("real socket: no request received")
	}

	// Client pointed at a non-existent socket should fail.
	fake, err := brokerrpc.New(fakeSock, "fs-fake")
	if err != nil {
		t.Fatalf("brokerrpc.New fake (unexpected error at construction): %v", err)
	}
	_, err = fake.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Error("expected error dialling non-existent socket; got nil")
	}
}
