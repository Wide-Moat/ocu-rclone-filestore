// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cmdtest

import (
	"fmt"
	"os"
	"testing"
)

// exitingMain models a peer main's error path: it prints the "<name>:" prefixed
// error and exits non-zero. AssertMainExitsNonZero drives it in the re-exec'd
// child.
func exitingMain() {
	fmt.Fprintln(os.Stderr, "cmdtestbin: boom")
	os.Exit(1)
}

// TestAssertMainExitsNonZero exercises the shared re-exec dance end to end: the
// parent branch re-execs this test filtered to itself with the guard set, and
// the child branch runs exitingMain, which prints the prefix and exits 1. This
// drives both branches of AssertMainExitsNonZero and every parent-side
// assertion on the success path.
func TestAssertMainExitsNonZero(t *testing.T) {
	AssertMainExitsNonZero(t, "cmdtestbin", "^TestAssertMainExitsNonZero$", exitingMain)
}
