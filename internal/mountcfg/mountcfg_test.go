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
