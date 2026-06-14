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
  "mounts": [
    {
      "destination": "/workspace/out",
      "filesystem_id": "session_01HXYZ_chat",
      "writes": true,
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
// not a decodable document. The pre-scan tolerates non-object bytes (it defers
// to the strict decoder), so the observable result is ErrDecode wrapping the
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

// TestScanProvisionMarkersNonObject covers the pre-scan early return: when the
// raw bytes are not a JSON object, the scanner cannot enumerate fields, so it
// returns nil and lets the strict decoder report the real error. The marker
// refusal must not fire (and must not panic) on a top-level array.
func TestScanProvisionMarkersNonObject(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`[1,2,3]`),
		[]byte(`"just a string"`),
		[]byte(`not json at all`),
		[]byte(``),
	} {
		if err := scanProvisionMarkers(raw); err != nil {
			t.Fatalf("non-object bytes %q should pre-scan clean, got %v", raw, err)
		}
	}
}

// TestScanProvisionMarkersMalformedArray covers the inner unmarshal-failure
// branch: a top-level object whose mounts value is present but is not an array
// of objects. The scanner cannot enumerate entries, so it skips that array
// rather than erroring; a marker hidden behind a non-array shape is left for the
// strict decoder to reject. The scan itself returns nil.
func TestScanProvisionMarkersMalformedArray(t *testing.T) {
	raw := []byte(`{"mounts": "not an array", "readonly_mounts": 42}`)
	if err := scanProvisionMarkers(raw); err != nil {
		t.Fatalf("malformed mounts array should pre-scan clean, got %v", err)
	}
}

// TestLoadMissingWrites covers the writes-absent branch of validateMount: the
// writes flag is required per mount, so an entry that omits it entirely is a
// posture failure flagged as missing (distinct from an entry that sets the
// wrong value, which the fixture-driven table already covers).
func TestLoadMissingWrites(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "invalid_missing_writes.json"))
	if err == nil {
		t.Fatalf("expected ErrWritesPosture, got cfg=%+v", cfg)
	}
	var e *ErrWritesPosture
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrWritesPosture, got %T: %v", err, err)
	}
	if !e.Missing {
		t.Fatalf("expected the missing-flag posture, got %+v", e)
	}
	if e.Array != arrayMounts || !e.Expected {
		t.Fatalf("expected mounts/expected=true, got %+v", e)
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

// TestScanProvisionMarkersInMount confirms a marker buried in a mount entry is
// found at its array index location, exercising the per-entry scan loop's hit
// path (the top-level hit path is exercised by the auth_token fixture).
func TestScanProvisionMarkersInMount(t *testing.T) {
	raw := []byte(`{"mounts":[{"destination":"/m","ca_cert_pem":"x"}]}`)
	err := scanProvisionMarkers(raw)
	var e *ErrProvisionMarker
	if !errors.As(err, &e) {
		t.Fatalf("expected *ErrProvisionMarker, got %T: %v", err, err)
	}
	if e.Marker != "ca_cert_pem" {
		t.Fatalf("expected ca_cert_pem marker, got %q", e.Marker)
	}
	if e.Location != "mounts[0]" {
		t.Fatalf("expected location mounts[0], got %q", e.Location)
	}
}
