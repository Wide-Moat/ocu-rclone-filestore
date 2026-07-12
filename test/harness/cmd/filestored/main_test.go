// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/exchange"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/cmdtest"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

func leafFiles(t *testing.T, ca *localca.CA, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	certPath, keyPath, caPath, err := ca.WriteLeafFiles(dir)
	if err != nil {
		t.Fatalf("write leaf files: %v", err)
	}
	return certPath, keyPath, caPath
}

// startCredentialJWKS serves the exchange's credential JWKS over TLS so the
// filestore can fetch it at startup.
func startCredentialJWKS(t *testing.T, ca *localca.CA) string {
	t.Helper()
	issuer, err := exchange.NewJWTCredentialIssuer(exchange.CredentialIssuerOptions{
		Issuer: credIssuer, Audience: credAudience, Kid: "kid-cred",
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/credential-jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(issuer.JWKS())
	})
	srv := cmdtest.NewTLSServer(t, ca, mux)
	return srv.URL + "/credential-jwks"
}

func TestFilestoredRunServes(t *testing.T) {
	ca, err := localca.New()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := leafFiles(t, ca, dir)
	credJWKS := startCredentialJWKS(t, ca)
	root := filepath.Join(dir, "workspace")
	addr := cmdtest.EphemeralAddr(t)

	go func() { _ = run(addr, certPath, keyPath, caPath, credJWKS, root) }()

	// Poll until the filestore answers. A POST with no credential draws 401,
	// which proves it is up and validating.
	client := cmdtest.HTTPClient(ca)
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Post("https://"+addr+"/v1/filestore/fs/listDirectory", "application/json", nil)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				break
			}
			t.Fatalf("filestore returned %d for an uncredentialled request, want 401", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("filestore never came up: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// The per-scope roots were created under the engine root.
	for _, sc := range []string{fsRW, fsRO, fsThrottle, fsConf} {
		if _, statErr := os.Stat(filepath.Join(root, sc)); statErr != nil {
			t.Fatalf("scope root %q not created: %v", sc, statErr)
		}
	}
}

// TestRunRejectsBadCA covers the CAClient error arm of run.
func TestRunRejectsBadCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad-ca.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	if err := run(cmdtest.EphemeralAddr(t), "c", "k", bad, "https://127.0.0.1:1/jwks", filepath.Join(dir, "ws")); err == nil {
		t.Fatal("run accepted a CA file with no certificate")
	}
}

// TestMainWith covers the flag-parsing entry with runFn stubbed.
func TestMainWith(t *testing.T) {
	saved := runFn
	t.Cleanup(func() { runFn = saved })
	called := false
	runFn = func(addr, cert, key, ca, credJWKS, root string) error { called = true; return nil }
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
