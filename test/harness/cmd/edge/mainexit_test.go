// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// mainExitGuard switches a re-exec of this test binary into the child that calls
// main() with failing args, so main's os.Exit(1) branch runs as real process
// behaviour (os.Exit cannot run in-process without killing the test binary).
const mainExitGuard = "OCU_TEST_RUN_MAIN_FAILURE"

// TestMainExitsNonZeroOnError asserts main's failure path: an unknown flag makes
// mainWith return a parse error, so main prints the prefixed error to stderr and
// calls os.Exit(1). The parent re-execs this binary as the guarded child and
// asserts a non-zero exit carrying the prefix.
func TestMainExitsNonZeroOnError(t *testing.T) {
	if os.Getenv(mainExitGuard) == "1" {
		os.Args = []string{"edge", "-nope"}
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
	if !strings.Contains(string(out), "edge:") {
		t.Fatalf("child stderr missing the error prefix; got:\n%s", out)
	}
}
