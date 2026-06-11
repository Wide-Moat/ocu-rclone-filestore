// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mounter"
)

// validConfig is a minimal config that passes mountcfg.Load: a single write
// mount and a single read-only mount, each with a filesystem scope, valid octal
// perms, a byte-size cap, and an allowed cache mode.
const validConfig = `{
  "schema_version": "v1alpha",
  "service_url": "https://broker.internal",
  "mounts": [
    {
      "destination": "/workspace/out",
      "filesystem_id": "session_test_chat",
      "writes": true,
      "vfs_cache_mode": "writes",
      "cache_duration_s": 3600,
      "vfs_cache_max_size": "1G",
      "dir_perms": "0755",
      "file_perms": "0644"
    }
  ],
  "readonly_mounts": [
    {
      "destination": "/workspace/in",
      "filesystem_id": "session_test_inputs",
      "writes": false,
      "vfs_cache_mode": "minimal",
      "cache_duration_s": 3,
      "vfs_cache_max_size": "512M",
      "dir_perms": "0755",
      "file_perms": "0644"
    }
  ]
}`

// writeTemp writes content to a temp file under t.TempDir and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config %q: %v", name, err)
	}
	return path
}

func TestRun(t *testing.T) {
	validPath := writeTemp(t, "valid.json", validConfig)
	badJSONPath := writeTemp(t, "bad.json", `{ this is not json `)
	missingPath := filepath.Join(t.TempDir(), "does-not-exist.json")

	tests := []struct {
		name string
		args []string
		// wantNotImplemented asserts the returned error wraps
		// mounter.ErrNotImplemented (the valid-config success path that then
		// hits the not-implemented seam).
		wantNotImplemented bool
	}{
		{
			name: "no --config flag returns a non-nil error",
			args: []string{},
		},
		{
			name: "empty --config value returns a non-nil error",
			args: []string{"--config", ""},
		},
		{
			name: "non-existent config path returns the load error",
			args: []string{"--config", missingPath},
		},
		{
			name: "malformed config returns the load error",
			args: []string{"--config", badJSONPath},
		},
		{
			name:               "valid config reaches the not-implemented mounter seam",
			args:               []string{"--config", validPath},
			wantNotImplemented: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args, io.Discard)
			if err == nil {
				t.Fatalf("run(%v) = nil; want non-nil error (every path here is an error path)", tc.args)
			}
			if tc.wantNotImplemented && !errors.Is(err, mounter.ErrNotImplemented) {
				t.Fatalf("run(%v) error = %v; want errors.Is ErrNotImplemented", tc.args, err)
			}
			if !tc.wantNotImplemented && errors.Is(err, mounter.ErrNotImplemented) {
				t.Fatalf("run(%v) reached the mounter seam; want a flag/load error before the seam", tc.args)
			}
		})
	}
}
