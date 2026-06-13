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
		// wantBrokerSocketError asserts the valid-config path threads through to
		// the orchestrator and returns the empty-broker-socket hard error (no
		// --broker-socket / OCU_BROKER_SOCKET set). This proves the wiring
		// reaches the seam without /dev/fuse — it replaces the wave-1
		// ErrNotImplemented case.
		wantBrokerSocketError bool
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
			name:                  "valid config with no broker socket hits the orchestrator hard error",
			args:                  []string{"--config", validPath},
			wantBrokerSocketError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args, io.Discard)
			if err == nil {
				t.Fatalf("run(%v) = nil; want non-nil error (every path here is an error path)", tc.args)
			}
			gotSocketErr := strings.Contains(err.Error(), "broker socket path not provided")
			if tc.wantBrokerSocketError && !gotSocketErr {
				t.Fatalf("run(%v) error = %v; want the empty-broker-socket hard error", tc.args, err)
			}
			if !tc.wantBrokerSocketError && gotSocketErr {
				t.Fatalf("run(%v) reached the orchestrator socket check; want a flag/load error before the seam", tc.args)
			}
		})
	}
}

// TestRunVersionFlag asserts that --version prints the build-stamped version
// and exits cleanly WITHOUT requiring --config and WITHOUT reaching the mount
// seam: a version query must not need a config or a broker socket.
func TestRunVersionFlag(t *testing.T) {
	var out strings.Builder
	reached := false
	recorder := func(*mountcfg.Config, mounter.ReadinessConfig, string, string, <-chan os.Signal) error {
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

// TestRunResolvesReadyFileAndBrokerSocket asserts that --ready-file,
// --broker-socket and --broker-socket-dir parse, that the OCU_READY_FILE /
// OCU_BROKER_SOCKET / OCU_BROKER_SOCKET_DIR env fallbacks resolve when the flag
// is unset, and that the flag wins over the env. It drives runWith with a
// recording double so the resolved values are asserted WITHOUT mounting (no
// /dev/fuse).
func TestRunResolvesReadyFileAndBrokerSocket(t *testing.T) {
	validPath := writeTemp(t, "valid.json", validConfig)

	type captured struct {
		rc              mounter.ReadinessConfig
		brokerSocket    string
		brokerSocketDir string
		signals         bool
	}

	tests := []struct {
		name              string
		args              []string
		env               map[string]string
		wantReadyFile     string
		wantBrokerSock    string
		wantBrokerSockDir string
	}{
		{
			name:           "flags supply both runtime inputs",
			args:           []string{"--config", validPath, "--ready-file", "/run/ready", "--broker-socket", "/run/broker.sock"},
			wantReadyFile:  "/run/ready",
			wantBrokerSock: "/run/broker.sock",
		},
		{
			name:           "env fallbacks resolve when flags unset",
			args:           []string{"--config", validPath},
			env:            map[string]string{"OCU_READY_FILE": "/env/ready", "OCU_BROKER_SOCKET": "/env/broker.sock"},
			wantReadyFile:  "/env/ready",
			wantBrokerSock: "/env/broker.sock",
		},
		{
			name:           "flag wins over env",
			args:           []string{"--config", validPath, "--ready-file", "/flag/ready", "--broker-socket", "/flag/broker.sock"},
			env:            map[string]string{"OCU_READY_FILE": "/env/ready", "OCU_BROKER_SOCKET": "/env/broker.sock"},
			wantReadyFile:  "/flag/ready",
			wantBrokerSock: "/flag/broker.sock",
		},
		{
			name:              "socket-dir flag resolves",
			args:              []string{"--config", validPath, "--broker-socket-dir", "/run/sockets"},
			wantBrokerSockDir: "/run/sockets",
		},
		{
			name:              "socket-dir env fallback resolves when the flag is unset",
			args:              []string{"--config", validPath},
			env:               map[string]string{"OCU_BROKER_SOCKET_DIR": "/env/sockets"},
			wantBrokerSockDir: "/env/sockets",
		},
		{
			name:              "socket-dir flag wins over env",
			args:              []string{"--config", validPath, "--broker-socket-dir", "/flag/sockets"},
			env:               map[string]string{"OCU_BROKER_SOCKET_DIR": "/env/sockets"},
			wantBrokerSockDir: "/flag/sockets",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			var got captured
			recorder := func(_ *mountcfg.Config, rc mounter.ReadinessConfig, brokerSocket, brokerSocketDir string, signals <-chan os.Signal) error {
				got = captured{rc: rc, brokerSocket: brokerSocket, brokerSocketDir: brokerSocketDir, signals: signals != nil}
				return nil
			}

			if err := runWith(tc.args, io.Discard, recorder); err != nil {
				t.Fatalf("runWith(%v) = %v; want nil (recorder returns nil)", tc.args, err)
			}
			if got.rc.ReadyFilePath != tc.wantReadyFile {
				t.Errorf("ReadyFilePath = %q; want %q", got.rc.ReadyFilePath, tc.wantReadyFile)
			}
			if got.brokerSocket != tc.wantBrokerSock {
				t.Errorf("brokerSocket = %q; want %q", got.brokerSocket, tc.wantBrokerSock)
			}
			if got.brokerSocketDir != tc.wantBrokerSockDir {
				t.Errorf("brokerSocketDir = %q; want %q", got.brokerSocketDir, tc.wantBrokerSockDir)
			}
			if !got.signals {
				t.Error("signals channel was nil; want a real signal.Notify channel threaded into the mounter")
			}
		})
	}
}
