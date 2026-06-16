// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mainExitGuard switches a re-exec of this test binary into the child that calls
// main() with failing args, so main's os.Exit(1) branch is exercised as real
// process behaviour rather than skipped (os.Exit cannot run in-process without
// killing the test binary).
const mainExitGuard = "OCU_TEST_RUN_MAIN_FAILURE"

// TestMainExitsNonZeroOnError asserts main's failure path: an unknown flag makes
// mainWith return a parse error, so main prints the prefixed error to stderr and
// calls os.Exit(1). The parent re-execs this binary as the guarded child and
// asserts a non-zero exit with the prefix on stderr.
func TestMainExitsNonZeroOnError(t *testing.T) {
	if os.Getenv(mainExitGuard) == "1" {
		os.Args = []string{"conformance-bootstrap", "-nope"}
		main()
		return // unreachable: main exits on the error path
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainExitsNonZeroOnError$", "-test.v")
	cmd.Env = append(os.Environ(), mainExitGuard+"=1")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("child error = %v; want a non-zero exit\noutput:\n%s", err, out)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("child exit code = %d; want 1\noutput:\n%s", exitErr.ExitCode(), out)
	}
	if !strings.Contains(string(out), "conformance-bootstrap:") {
		t.Fatalf("child stderr missing the error prefix; got:\n%s", out)
	}
}

func TestRunWritesEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	caPEM := "-----BEGIN CERTIFICATE-----\nLINE1\nLINE2\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(ca, []byte(caPEM), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	tokens := filepath.Join(dir, "weak-tokens.json")
	if err := os.WriteFile(tokens, []byte(`{"fsconf":"weak.jwt.token"}`), 0o600); err != nil {
		t.Fatalf("write tokens: %v", err)
	}
	out := filepath.Join(dir, "env.sh")

	if err := run("fsconf", out, "https://edge:8450", "fsconf", ca, tokens); err != nil {
		t.Fatalf("run: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		"export RCLONE_CONFIG_FSCONF_TYPE='ocufs'",
		"export RCLONE_CONFIG_FSCONF_SERVICE_URL='https://edge:8450'",
		"export RCLONE_CONFIG_FSCONF_FILESYSTEM_ID='fsconf'",
		"export RCLONE_CONFIG_FSCONF_AUTH_TOKEN='weak.jwt.token'",
		"export RCLONE_CONFIG_FSCONF_READ_ONLY='false'",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("env file missing %q; got:\n%s", want, s)
		}
	}
	// The multi-line CA PEM must be present intact inside a single-quoted value.
	if !strings.Contains(s, caPEM) {
		t.Fatalf("env file did not carry the CA PEM intact:\n%s", s)
	}
}

func TestRunRejectsMissingInputs(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "env.sh")

	// Missing CA.
	if err := run("fsconf", out, "u", "fsconf", filepath.Join(dir, "no-ca"), filepath.Join(dir, "no-tok")); err == nil {
		t.Fatal("run accepted a missing CA path")
	}

	// CA present, tokens missing.
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, []byte("ca"), 0o600)
	if err := run("fsconf", out, "u", "fsconf", ca, filepath.Join(dir, "no-tok")); err == nil {
		t.Fatal("run accepted a missing tokens path")
	}

	// Tokens present but no entry for the scope.
	tok := filepath.Join(dir, "tok.json")
	_ = os.WriteFile(tok, []byte(`{"other":"x"}`), 0o600)
	if err := run("fsconf", out, "u", "fsconf", ca, tok); err == nil {
		t.Fatal("run accepted tokens with no entry for the scope")
	}

	// Tokens not JSON.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("not json"), 0o600)
	if err := run("fsconf", out, "u", "fsconf", ca, bad); err == nil {
		t.Fatal("run accepted non-JSON tokens")
	}
}

func TestShellSingleQuote(t *testing.T) {
	got := shellSingleQuote("a'b")
	want := `'a'\''b'`
	if got != want {
		t.Fatalf("shellSingleQuote(%q) = %q, want %q", "a'b", got, want)
	}
}

// TestMainWith drives the flag-parsing entry with valid flags so the success
// path is covered, and rejects an unknown flag.
func TestMainWith(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"), 0o600)
	tok := filepath.Join(dir, "tok.json")
	_ = os.WriteFile(tok, []byte(`{"fsconf":"weak.jwt"}`), 0o600)

	if err := mainWith([]string{"-out", filepath.Join(dir, "env.sh"), "-ca", ca, "-tokens", tok}); err != nil {
		t.Fatalf("mainWith: %v", err)
	}
	if err := mainWith([]string{"-nope"}); err == nil {
		t.Fatal("mainWith accepted an unknown flag")
	}
}
