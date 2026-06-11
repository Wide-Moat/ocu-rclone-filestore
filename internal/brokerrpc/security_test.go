// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc_test — security source-scan assertions.
//
// This file contains source-level assertions that enforce SEC-25 and SEC-73:
// no Authorization/bearer/token header construction exists anywhere in the
// non-test package source, and no code path sets downloadable to true. The
// scan explicitly skips test files (files ending in _test.go) to avoid
// self-tripping on the fixture strings used in these very assertions.
package brokerrpc_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAuthorizationHeaderInSource asserts that no non-test Go source file
// in the brokerrpc package constructs an Authorization header (SEC-25). The
// guest holds no credential and must never set an Authorization, bearer, or
// token header.
func TestNoAuthorizationHeaderInSource(t *testing.T) {
	sources := nonTestSources(t)

	// Patterns that would indicate an Authorization code path. The strings
	// themselves appear here only as test fixtures; they must not appear in
	// production source.
	forbidden := []string{
		`"Authorization"`,
		`"authorization"`,
		`bearer`,
		`Bearer`,
		// The doc promises the scan also catches token-bearing headers and the
		// adjacent credential-header spellings; these patterns make the
		// enforcement match the documentation (LO-02).
		`auth_token`,
		`authToken`,
		`AuthToken`,
		`"X-Api-Key"`,
		`"X-API-Key"`,
		`"Proxy-Authorization"`,
	}

	for _, path := range sources {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(content)
		for _, pat := range forbidden {
			if strings.Contains(text, pat) {
				t.Errorf("forbidden pattern %q found in non-test source %s (SEC-25: no Authorization code path)", pat, filepath.Base(path))
			}
		}
	}
}

// TestDownloadableNeverTrueInSource asserts that no non-test Go source file
// in the brokerrpc package sets downloadable to true (SEC-73 / T-02-02).
// The only legitimate occurrence of the downloadable field is in the stamp
// helper, where it is hardcoded to false.
func TestDownloadableNeverTrueInSource(t *testing.T) {
	sources := nonTestSources(t)

	// The literal that would indicate a code path setting downloadable=true.
	const forbidden = "Downloadable: true"

	for _, path := range sources {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(content), forbidden) {
			t.Errorf("forbidden pattern %q found in non-test source %s (SEC-73: downloadable must always be false)", forbidden, filepath.Base(path))
		}
	}
}

// nonTestSources returns the absolute paths of all non-test .go files in the
// brokerrpc package directory. Test files (_test.go) are excluded so that
// the fixture strings in this file do not cause the scan to self-trip.
func nonTestSources(t *testing.T) []string {
	t.Helper()

	// Locate the package directory relative to the module root.
	pkgDir := filepath.Join(moduleRoot(t), "internal", "brokerrpc")

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("readdir %s: %v", pkgDir, err)
	}

	var paths []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue // exclude test files from the scan
		}
		paths = append(paths, filepath.Join(pkgDir, name))
	}
	return paths
}

// moduleRoot returns the module root directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test binary's working directory until go.mod is found.
	// Using os.Getwd is reliable in test context when no chdir happens.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod from test working directory")
		}
		dir = parent
	}
}
