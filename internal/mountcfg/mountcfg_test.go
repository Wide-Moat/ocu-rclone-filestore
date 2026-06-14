// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mountcfg

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		// wantErr, when non-nil, is checked with errors.As against the returned
		// error; nil means the load must succeed.
		wantErr any
		// assert runs extra checks on the typed error after errors.As matches.
		assert func(t *testing.T, err error)
	}{
		{
			name:    "valid minimal loads",
			fixture: "valid_minimal.json",
			wantErr: nil,
		},
		{
			name:    "both ids is a hard error (CFG-02)",
			fixture: "invalid_both_ids.json",
			wantErr: new(*ErrMountScope),
			assert: func(t *testing.T, err error) {
				var e *ErrMountScope
				errors.As(err, &e)
				if !e.HasFilesystem || !e.HasMemory {
					t.Fatalf("expected both-ids flagged, got %+v", e)
				}
			},
		},
		{
			name:    "neither id is a hard error (CFG-02)",
			fixture: "invalid_neither_id.json",
			wantErr: new(*ErrMountScope),
			assert: func(t *testing.T, err error) {
				var e *ErrMountScope
				errors.As(err, &e)
				if e.HasFilesystem || e.HasMemory {
					t.Fatalf("expected neither-id flagged, got %+v", e)
				}
			},
		},
		{
			name:    "http service_url rejected (CFG-02)",
			fixture: "invalid_http_url.json",
			wantErr: new(*ErrServiceURL),
		},
		{
			name:    "relative destination rejected (CFG-02)",
			fixture: "invalid_relative_dest.json",
			wantErr: new(*ErrDestination),
		},
		{
			name:    "non-octal perms rejected (CFG-02)",
			fixture: "invalid_perms.json",
			wantErr: new(*ErrPerms),
		},
		{
			name:    "bad byte-size rejected (CFG-02)",
			fixture: "invalid_bytesize.json",
			wantErr: new(*ErrByteSize),
		},
		{
			name:    "bad cache mode rejected (CFG-02)",
			fixture: "invalid_cache_mode.json",
			wantErr: new(*ErrCacheMode),
		},
		{
			name:    "readonly mount with writes=true rejected (CFG-03)",
			fixture: "invalid_ro_writes_true.json",
			wantErr: new(*ErrWritesPosture),
			assert: func(t *testing.T, err error) {
				var e *ErrWritesPosture
				errors.As(err, &e)
				if e.Array != arrayReadonlyMounts || e.Expected != false {
					t.Fatalf("expected readonly writes=false posture, got %+v", e)
				}
			},
		},
		{
			name:    "rw mount with writes=false rejected (CFG-03)",
			fixture: "invalid_rw_writes_false.json",
			wantErr: new(*ErrWritesPosture),
			assert: func(t *testing.T, err error) {
				var e *ErrWritesPosture
				errors.As(err, &e)
				if e.Array != arrayMounts || e.Expected != true {
					t.Fatalf("expected mounts writes=true posture, got %+v", e)
				}
			},
		},
		{
			name:    "auth_token rejected as provision marker (CFG-04)",
			fixture: "reject_auth_token.json",
			wantErr: new(*ErrProvisionMarker),
			assert: func(t *testing.T, err error) {
				var e *ErrProvisionMarker
				errors.As(err, &e)
				if e.Marker != "auth_token" {
					t.Fatalf("expected auth_token marker, got %q", e.Marker)
				}
			},
		},
		{
			name:    "ca_cert_pem rejected as provision marker (CFG-04)",
			fixture: "reject_ca_cert_pem.json",
			wantErr: new(*ErrProvisionMarker),
			assert: func(t *testing.T, err error) {
				var e *ErrProvisionMarker
				errors.As(err, &e)
				if e.Marker != "ca_cert_pem" {
					t.Fatalf("expected ca_cert_pem marker, got %q", e.Marker)
				}
			},
		},
		{
			name:    "unknown field rejected by strict decode (CFG-01)",
			fixture: "reject_unknown_field.json",
			wantErr: new(*ErrDecode),
		},
		{
			name:    "empty filesystem_id beside memory_store_id trips the both-set error (CFG-02)",
			fixture: "invalid_empty_fs_with_mem.json",
			wantErr: new(*ErrMountScope),
			assert: func(t *testing.T, err error) {
				var e *ErrMountScope
				errors.As(err, &e)
				if !e.HasFilesystem || !e.HasMemory {
					t.Fatalf("expected both keys flagged present, got %+v", e)
				}
			},
		},
		{
			name:    "present-but-empty filesystem_id rejected (CFG-02)",
			fixture: "invalid_empty_fs_id.json",
			wantErr: new(*ErrScopeID),
			assert: func(t *testing.T, err error) {
				var e *ErrScopeID
				errors.As(err, &e)
				if e.Field != "filesystem_id" {
					t.Fatalf("expected filesystem_id flagged, got %+v", e)
				}
			},
		},
		{
			name:    "present-but-empty memory_store_id rejected (CFG-02)",
			fixture: "invalid_empty_mem_id.json",
			wantErr: new(*ErrScopeID),
			assert: func(t *testing.T, err error) {
				var e *ErrScopeID
				errors.As(err, &e)
				if e.Field != "memory_store_id" {
					t.Fatalf("expected memory_store_id flagged, got %+v", e)
				}
			},
		},
		{
			name:    "negative cache_duration_s rejected (CFG-02)",
			fixture: "invalid_negative_cache_duration.json",
			wantErr: new(*ErrCacheDuration),
			assert: func(t *testing.T, err error) {
				var e *ErrCacheDuration
				errors.As(err, &e)
				if e.Missing || e.Value != -5 {
					t.Fatalf("expected negative value flagged, got %+v", e)
				}
			},
		},
		{
			name:    "explicit zero cache_duration_s loads (CFG-02: 0 is legal)",
			fixture: "valid_cache_duration_zero.json",
			wantErr: nil,
		},
		{
			name:    "missing cache_duration_s rejected (CFG-02)",
			fixture: "invalid_missing_cache_duration.json",
			wantErr: new(*ErrCacheDuration),
			assert: func(t *testing.T, err error) {
				var e *ErrCacheDuration
				errors.As(err, &e)
				if !e.Missing {
					t.Fatalf("expected missing field flagged, got %+v", e)
				}
			},
		},
		{
			name:    "missing mounts key rejected (CFG-02)",
			fixture: "invalid_missing_mounts.json",
			wantErr: new(*ErrMissingField),
			assert: func(t *testing.T, err error) {
				var e *ErrMissingField
				errors.As(err, &e)
				if e.Field != "mounts" {
					t.Fatalf("expected mounts flagged as missing, got %+v", e)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(filepath.Join("testdata", tc.fixture))

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if cfg == nil {
					t.Fatal("expected a *Config, got nil")
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %T, got nil (cfg=%+v)", tc.wantErr, cfg)
			}
			if !errors.As(err, tc.wantErr) {
				t.Fatalf("expected error of type %T, got %T: %v", tc.wantErr, err, err)
			}
			if tc.assert != nil {
				tc.assert(t, err)
			}
		})
	}
}

// TestLoadAcceptsZeroCacheDuration pins the lower bound of the cache_duration_s
// range: an explicit 0 is legal (the schema's minimum is 0) and must load. The
// validation guard is `*m.CacheDurationS < 0`, so 0 is accepted; were the guard
// `<= 0` this config would be wrongly rejected. The standalone test asserts both
// that Load succeeds AND that 0 round-trips as a present (non-nil) zero on every
// mount, so a wrong-direction off-by-one in either the presence check or the
// range check is caught.
func TestLoadAcceptsZeroCacheDuration(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "valid_cache_duration_zero.json"))
	if err != nil {
		t.Fatalf("explicit cache_duration_s 0 must load, got %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a *Config, got nil")
	}

	groups := map[string][]Mount{
		"mounts":          cfg.Mounts,
		"readonly_mounts": cfg.ReadonlyMounts,
	}
	for label, group := range groups {
		if len(group) == 0 {
			t.Fatalf("%s: expected at least one mount in the zero-duration fixture", label)
		}
		for i, m := range group {
			if m.CacheDurationS == nil {
				t.Fatalf("%s[%d]: cache_duration_s parsed as absent, want present 0", label, i)
			}
			if *m.CacheDurationS != 0 {
				t.Fatalf("%s[%d]: cache_duration_s parsed as %d, want 0", label, i, *m.CacheDurationS)
			}
		}
	}
}
