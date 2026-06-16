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
			name:    "single array mixing readonly true and false loads",
			fixture: "valid_readonly_mount.json",
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
			name:    "mount missing readonly rejected (CFG-03)",
			fixture: "invalid_missing_readonly.json",
			wantErr: new(*ErrReadonlyMissing),
			assert: func(t *testing.T, err error) {
				var e *ErrReadonlyMissing
				errors.As(err, &e)
				if e.Index != 0 {
					t.Fatalf("expected index 0 flagged, got %+v", e)
				}
			},
		},
		{
			name:    "mount with empty auth_token rejected (CFG-04)",
			fixture: "invalid_empty_auth_token.json",
			wantErr: new(*ErrAuthToken),
			assert: func(t *testing.T, err error) {
				var e *ErrAuthToken
				errors.As(err, &e)
				if e.Index != 0 {
					t.Fatalf("expected index 0 flagged, got %+v", e)
				}
			},
		},
		{
			name:    "missing top-level ca_cert_pem rejected (CFG-04)",
			fixture: "invalid_missing_ca_cert.json",
			wantErr: new(*ErrMissingField),
			assert: func(t *testing.T, err error) {
				var e *ErrMissingField
				errors.As(err, &e)
				if e.Field != "ca_cert_pem" {
					t.Fatalf("expected ca_cert_pem flagged as missing, got %+v", e)
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
// range check is caught. It also asserts the held-credential path is populated:
// the top-level ca_cert_pem and each mount's auth_token survive the load
// non-empty, proving the loader holds the credential rather than dropping it.
func TestLoadAcceptsZeroCacheDuration(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "valid_cache_duration_zero.json"))
	if err != nil {
		t.Fatalf("explicit cache_duration_s 0 must load, got %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a *Config, got nil")
	}

	if cfg.CACertPEM == "" {
		t.Fatal("expected the held ca_cert_pem to survive the load, got empty")
	}

	if len(cfg.Mounts) == 0 {
		t.Fatal("expected at least one mount in the zero-duration fixture")
	}
	for i, m := range cfg.Mounts {
		if m.CacheDurationS == nil {
			t.Fatalf("mounts[%d]: cache_duration_s parsed as absent, want present 0", i)
		}
		if *m.CacheDurationS != 0 {
			t.Fatalf("mounts[%d]: cache_duration_s parsed as %d, want 0", i, *m.CacheDurationS)
		}
		if m.AuthToken == "" {
			t.Fatalf("mounts[%d]: auth_token parsed as empty, want the held token", i)
		}
		if m.Readonly == nil {
			t.Fatalf("mounts[%d]: readonly parsed as absent, want present", i)
		}
	}
}
