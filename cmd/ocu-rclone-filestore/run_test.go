// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mounter"
)

// validConfig is a minimal config that passes mountcfg.Load: a single
// read-write mount and a single read-only mount in one mounts array, each with
// a filesystem scope and a per-mount session token, valid octal perms, a
// byte-size cap, and an allowed cache mode, plus the top-level service_url and
// trust anchor that carry the transport.
const validConfig = `{
  "schema_version": "v1alpha",
  "service_url": "https://broker.internal",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  "mounts": [
    {
      "destination": "/workspace/out",
      "auth_token": "tok.rw.session",
      "filesystem_id": "session_test_chat",
      "readonly": false,
      "vfs_cache_mode": "writes",
      "cache_duration_s": 3600,
      "vfs_cache_max_size": "1G",
      "dir_perms": "0755",
      "file_perms": "0644"
    },
    {
      "destination": "/workspace/in",
      "auth_token": "tok.ro.session",
      "filesystem_id": "session_test_inputs",
      "readonly": true,
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

// TestRun covers the error paths through run: the flag layer rejects bad args
// before any config load, and the --config requirement and loader surface their
// own errors. The valid-config success path is asserted separately through the
// newMounter recorder (TestRunDrivesProductionMountAdapter) so this table never
// drives a real kernel mount.
func TestRun(t *testing.T) {
	validPath := writeTemp(t, "valid.json", validConfig)
	badJSONPath := writeTemp(t, "bad.json", `{ this is not json `)
	missingPath := filepath.Join(t.TempDir(), "does-not-exist.json")

	tests := []struct {
		name string
		args []string
		// wantParseError asserts the flag layer rejected the args BEFORE any
		// config load: the returned error wraps the parse failure ("parse
		// flags:") and the run never touches the --config requirement, the
		// loader, or the mount seam.
		wantParseError bool
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
			name:           "unknown flag is rejected by the parse layer",
			args:           []string{"--config", validPath, "--no-such-flag"},
			wantParseError: true,
		},
		{
			name:           "flag missing its required argument is rejected by the parse layer",
			args:           []string{"--config"},
			wantParseError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args, io.Discard)
			if err == nil {
				t.Fatalf("run(%v) = nil; want non-nil error (every path here is an error path)", tc.args)
			}
			gotParseErr := strings.Contains(err.Error(), "parse flags:")
			if tc.wantParseError && !gotParseErr {
				t.Fatalf("run(%v) error = %v; want the wrapped parse-flags error", tc.args, err)
			}
			if !tc.wantParseError && gotParseErr {
				t.Fatalf("run(%v) returned a parse-flags error; want a later flag/load error", tc.args)
			}
		})
	}
}

// recordingMounter captures the config handed to newMounter's returned Mounter
// and the functional options applied, so the adapter wiring is assertable
// without constructing a live mount.
type recordingMounter struct {
	gotCfg *mountcfg.Config
}

func (m *recordingMounter) Mount(cfg *mountcfg.Config) error {
	m.gotCfg = cfg
	return nil
}

// TestRunDrivesProductionMountAdapter proves run/runWith reach the REAL
// productionMount (not a recorder): with the newMounter seam swapped for a
// recorder, a valid config threads all the way through runWith ->
// productionMount, the transport flows in cfg (service_url + ca_cert_pem), and
// productionMount applies only WithReadiness + WithSignals. This closes the gap
// where every runWith test injected a recorder in place of productionMount and
// so never exercised the adapter.
func TestRunDrivesProductionMountAdapter(t *testing.T) {
	validPath := writeTemp(t, "valid.json", validConfig)

	rec := &recordingMounter{}
	orig := newMounter
	t.Cleanup(func() { newMounter = orig })
	newMounter = func(_ ...mounter.Option) mounter.Mounter {
		return rec
	}

	err := runWith(
		[]string{"--config", validPath},
		io.Discard,
		productionMount,
	)
	if err != nil {
		t.Fatalf("runWith with the real productionMount = %v; want nil", err)
	}
	if rec.gotCfg == nil {
		t.Fatal("productionMount did not reach the mounter's Mount; the adapter under test never ran")
	}
	if rec.gotCfg.ServiceURL != "https://broker.internal" {
		t.Errorf("Mount received ServiceURL = %q; want https://broker.internal (transport must flow in cfg)", rec.gotCfg.ServiceURL)
	}
	if rec.gotCfg.CACertPEM == "" {
		t.Error("Mount received an empty CACertPEM; want the config's trust anchor threaded through")
	}
}

// TestRunVersionFlag asserts that --version prints the build-stamped version
// and exits cleanly WITHOUT requiring --config and WITHOUT reaching the mount
// seam: a version query must not need a config.
func TestRunVersionFlag(t *testing.T) {
	var out strings.Builder
	reached := false
	recorder := func(*mountcfg.Config, mounter.ReadinessConfig, <-chan os.Signal) error {
		reached = true
		return nil
	}

	if err := runWith([]string{"--version"}, &out, recorder); err != nil {
		t.Fatalf("runWith(--version) = %v; want nil (clean exit)", err)
	}
	if reached {
		t.Fatal("--version reached the mount seam; it must short-circuit before mounting")
	}
	got := out.String()
	if !strings.Contains(got, "ocu-rclone-filestore") {
		t.Errorf("--version output %q missing the program name", got)
	}
	if !strings.Contains(got, version) {
		t.Errorf("--version output %q missing the version %q", got, version)
	}
}

// TestRunResolvesReadyFile asserts that --ready-file parses, that the
// OCU_READY_FILE env fallback resolves when the flag is unset, and that the flag
// wins over the env. It drives runWith with a recording double so the resolved
// value is asserted WITHOUT mounting (no /dev/fuse). The transport now flows in
// the config, so the only runtime input resolved here is the ready-file.
func TestRunResolvesReadyFile(t *testing.T) {
	validPath := writeTemp(t, "valid.json", validConfig)

	type captured struct {
		rc      mounter.ReadinessConfig
		signals bool
	}

	tests := []struct {
		name          string
		args          []string
		env           map[string]string
		wantReadyFile string
	}{
		{
			name:          "flag supplies the ready-file",
			args:          []string{"--config", validPath, "--ready-file", "/run/ready"},
			wantReadyFile: "/run/ready",
		},
		{
			name:          "env fallback resolves when the flag is unset",
			args:          []string{"--config", validPath},
			env:           map[string]string{"OCU_READY_FILE": "/env/ready"},
			wantReadyFile: "/env/ready",
		},
		{
			name:          "flag wins over env",
			args:          []string{"--config", validPath, "--ready-file", "/flag/ready"},
			env:           map[string]string{"OCU_READY_FILE": "/env/ready"},
			wantReadyFile: "/flag/ready",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			var got captured
			recorder := func(_ *mountcfg.Config, rc mounter.ReadinessConfig, signals <-chan os.Signal) error {
				got = captured{rc: rc, signals: signals != nil}
				return nil
			}

			if err := runWith(tc.args, io.Discard, recorder); err != nil {
				t.Fatalf("runWith(%v) = %v; want nil (recorder returns nil)", tc.args, err)
			}
			if got.rc.ReadyFilePath != tc.wantReadyFile {
				t.Errorf("ReadyFilePath = %q; want %q", got.rc.ReadyFilePath, tc.wantReadyFile)
			}
			if !got.signals {
				t.Error("signals channel was nil; want a real signal.Notify channel threaded into the mounter")
			}
		})
	}
}
