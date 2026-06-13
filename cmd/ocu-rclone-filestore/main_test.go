// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMainCleanExit drives main() on its clean-exit path: --version makes run
// return nil, so main evaluates the error guard, takes neither the stderr write
// nor os.Exit(1), and returns. It is invoked in-process (not a subprocess) so
// the run wiring stays covered; the args are swapped via os.Args and restored.
//
// The os.Exit(1) failure branch of main cannot be exercised in-process without
// terminating the test binary; it is the unavoidable main seam. Every other
// statement in the package is covered.
func TestMainCleanExit(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })

	// --version short-circuits before --config / the loader / the mount seam and
	// returns nil, so main's error guard is false and main returns cleanly. If
	// run returned an error here main would call os.Exit(1) and kill the test —
	// the test passing is itself the assertion that this path stays clean.
	os.Args = []string{"ocu-rclone-filestore", "--version"}
	main()
}

// mainExitGuard names the env var that switches a re-exec of the test binary
// into the "call main() with a failing run" child. The parent leaves it unset
// and runs the child; the child sets it and invokes main directly.
const mainExitGuard = "OCU_TEST_RUN_MAIN_FAILURE"

// TestMainFailureExits asserts main's failure path as real process behaviour:
// run returns a non-nil error (here: the missing --config error), main prints
// "ocu-rclone-filestore: <err>" to stderr and calls os.Exit(1). os.Exit cannot
// be exercised in-process without killing the test binary, so the parent
// re-execs this same test binary as a child that calls main(), then asserts the
// child exited non-zero with the wrapped error on stderr.
func TestMainFailureExits(t *testing.T) {
	if os.Getenv(mainExitGuard) == "1" {
		// Child: no --config, so run returns the missing-config error and main
		// must os.Exit(1). Nothing past main() should run.
		os.Args = []string{"ocu-rclone-filestore"}
		main()
		// Unreachable: main exits the process on the error path.
		return
	}

	// Parent: re-exec this test binary, running only the child case, with the
	// guard set so it takes the main() branch above.
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainFailureExits$", "-test.v")
	cmd.Env = append(os.Environ(), mainExitGuard+"=1")
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !asExitError(err, &exitErr) {
		t.Fatalf("child process error = %v; want a non-zero exit (os.Exit(1) on the failure path)\noutput:\n%s", err, out)
	}
	if code := exitErr.ExitCode(); code != 1 {
		t.Fatalf("child exit code = %d; want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(string(out), "ocu-rclone-filestore:") {
		t.Fatalf("child stderr missing the wrapped error prefix; got:\n%s", out)
	}
	if !strings.Contains(string(out), "missing required --config") {
		t.Fatalf("child stderr missing the underlying run error; got:\n%s", out)
	}
}

// asExitError reports whether err is (or wraps) an *exec.ExitError and, if so,
// stores it through target. It keeps the failure-path assertion readable
// without importing errors solely for one As call.
func asExitError(err error, target **exec.ExitError) bool {
	if err == nil {
		return false
	}
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}
