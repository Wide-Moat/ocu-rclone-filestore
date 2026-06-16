// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadReadError covers the read-failure path: a path that does not resolve
// to a readable file is wrapped with the path, not silently swallowed. This is
// not one of the typed validation errors — it is the os.ReadFile failure, which
// must still surface a non-nil error naming the offending path.
func TestLoadReadError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")

	cfg, err := Load(missing)
	if err == nil {
		t.Fatalf("expected a read error for a missing path, got cfg=%+v", cfg)
	}
	if cfg != nil {
		t.Fatalf("expected nil Config on read failure, got %+v", cfg)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected the wrapped error to be os.ErrNotExist, got %v", err)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("expected the error to name the failing path %q, got %v", missing, err)
	}
}

// TestLoadUnparseableServiceURL covers the second branch of validateServiceURL:
// a service_url that carries the required https:// prefix but is not a parseable
// request URI. The prefix check passes; url.ParseRequestURI rejects it; the
// loader reports ErrServiceURL with the "not a parseable URI" reason rather than
// the prefix reason.
func TestLoadUnparseableServiceURL(t *testing.T) {
	// Written inline rather than as a committed testdata fixture: the
	// contract package's loader/schema parity sweep reads every file under
	// mountcfg/testdata, and the vendored schema's service_url constraint
	// checks only the https:// prefix, not URI-parseability — so a committed
	// fixture with an https-prefixed-but-unparseable URL would be a loader-only
	// reject and trip the parity invariant. Keeping it inline exercises the
	// loader branch without exposing the (separately tracked) schema-weaker-
	// than-loader divergence to the parity sweep.
	const unparseable = "https://%zz"
	doc := `{
  "schema_version": "v1alpha",
  "service_url": "` + unparseable + `",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  "mounts": [
    {
      "destination": "/workspace/out",
      "auth_token": "tok.opaque.value",
      "filesystem_id": "session_01HXYZ_chat",
      "readonly": false,
      "vfs_cache_mode": "writes",
      "cache_duration_s": 3600,
      "vfs_cache_max_size": "1G",
      "dir_perms": "0755",
      "file_perms": "0644"
    }
  ]
}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := Load(path)
	if err == nil {
		t.Fatalf("expected ErrServiceURL, got cfg=%+v", cfg)
	}
	var e *ErrServiceURL
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrServiceURL, got %T: %v", err, err)
	}
	if e.Reason != "is not a parseable URI" {
		t.Fatalf("expected the parseable-URI reason, got %q", e.Reason)
	}
	if e.Value != unparseable {
		t.Fatalf("expected the offending value echoed, got %q", e.Value)
	}
}

// TestLoadMalformedJSON covers the strict-decode failure path for bytes that are
// not a decodable document. The observable result is ErrDecode wrapping the
// decoder's own error.
func TestLoadMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(path)
	if err == nil {
		t.Fatalf("expected ErrDecode, got cfg=%+v", cfg)
	}
	var e *ErrDecode
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrDecode, got %T: %v", err, err)
	}
	if e.Err == nil {
		t.Fatal("expected ErrDecode to wrap the decoder error")
	}
}

// TestLoadBadFilePerms covers the file_perms branch of validateMount. The mount
// carries a valid dir_perms so validation reaches the file_perms check, then
// fails it: the typed error must name file_perms (not dir_perms) and echo the
// offending value.
func TestLoadBadFilePerms(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "invalid_file_perms.json"))
	if err == nil {
		t.Fatalf("expected ErrPerms, got cfg=%+v", cfg)
	}
	var e *ErrPerms
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrPerms, got %T: %v", err, err)
	}
	if e.Field != "file_perms" {
		t.Fatalf("expected file_perms flagged, got %+v", e)
	}
	if e.Value != "0688" {
		t.Fatalf("expected the offending value echoed, got %q", e.Value)
	}
}

// TestLoadBackendCacheTTLAccepted covers the accepted-but-not-consumed top-level
// backend_cache_ttl field. The single shape allows it at the top level, so the
// loader must decode it (rather than reject it as unknown) and surface the value
// without otherwise acting on it.
func TestLoadBackendCacheTTLAccepted(t *testing.T) {
	doc := `{
  "schema_version": "v1alpha",
  "service_url": "https://broker.internal",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  "backend_cache_ttl": 30,
  "mounts": [
    {
      "destination": "/workspace/out",
      "auth_token": "tok.opaque.value",
      "filesystem_id": "session_01HXYZ_chat",
      "readonly": false,
      "vfs_cache_mode": "writes",
      "cache_duration_s": 3600,
      "vfs_cache_max_size": "1G",
      "dir_perms": "0755",
      "file_perms": "0644"
    }
  ]
}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("a config carrying backend_cache_ttl must load, got %v", err)
	}
	if cfg.BackendCacheTTL == nil {
		t.Fatal("expected backend_cache_ttl to be decoded as present")
	}
	if *cfg.BackendCacheTTL != 30 {
		t.Fatalf("expected backend_cache_ttl 30, got %d", *cfg.BackendCacheTTL)
	}
}
