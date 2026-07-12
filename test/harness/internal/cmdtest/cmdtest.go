// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package cmdtest is shared scaffolding for the harness peer command tests. It
// is imported ONLY from _test.go files, never from a file that compiles into a
// shipped binary, so it may safely pull in testing-only packages that must not
// enter any peer binary's graph.
//
// It holds the main-exit re-exec dance the peer mains share to prove their
// os.Exit(1) failure path.
package cmdtest

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// mainExitGuard is the environment variable that switches a re-exec of the
// calling test binary into the child that runs the peer main with failing args.
// A peer main calls os.Exit on its error path, which cannot run in-process
// without killing the test binary, so the child re-exec turns that exit into an
// observable process result the parent inspects.
const mainExitGuard = "OCU_TEST_RUN_MAIN_FAILURE"

// AssertMainExitsNonZero proves a peer main's failure path. When the guard env
// var is set — i.e. this call is running inside the re-exec'd child — it points
// os.Args at binaryName with an unknown flag and calls mainFn, which is expected
// to print the "<binaryName>:" error prefix and call os.Exit(1); the trailing
// return is never reached. Otherwise it re-execs the calling test binary
// filtered to runFilter (the calling test's own name) with the guard set, and
// asserts the child exited with code 1 carrying the "<binaryName>:" prefix on
// its combined output.
//
// runFilter must anchor the calling test's name (for example
// "^TestMainExitsNonZeroOnError$") so the child re-enters the same test and thus
// the guard branch of this helper.
func AssertMainExitsNonZero(t *testing.T, binaryName, runFilter string, mainFn func()) {
	t.Helper()
	if os.Getenv(mainExitGuard) == "1" {
		os.Args = []string{binaryName, "-nope"}
		mainFn()
		return // unreachable: mainFn exits on the error path
	}
	cmd := exec.Command(os.Args[0], "-test.run="+runFilter, "-test.v")
	cmd.Env = append(os.Environ(), mainExitGuard+"=1")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("child error = %v; want a non-zero exit\noutput:\n%s", err, out)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("child exit code = %d; want 1\noutput:\n%s", exitErr.ExitCode(), out)
	}
	if !strings.Contains(string(out), binaryName+":") {
		t.Fatalf("child stderr missing the error prefix; got:\n%s", out)
	}
}
