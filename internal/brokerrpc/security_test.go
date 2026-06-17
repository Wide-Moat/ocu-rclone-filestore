// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc_test — security source-scan assertions.
//
// This file contains source-level assertions that enforce the credential and
// confidentiality invariants: the ONLY credential header the guest constructs
// is the static Authorization: Bearer header (no alternate credential-header
// spellings), and no code path sets downloadable to true. The scan explicitly
// skips test files (files ending in _test.go) to avoid self-tripping on the
// fixture strings used in these very assertions.
package brokerrpc_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnlyBearerCredentialHeaderInSource asserts that the only credential
// header the non-test package source constructs is the standard Authorization
// header — no alternate credential-header spellings (api-key, proxy-auth) and
// no second credential transport. The guest's single credential is the static
// session JWT carried as Authorization: Bearer; any OTHER credential-header
// construction would indicate a divergent or duplicated credential path.
func TestOnlyBearerCredentialHeaderInSource(t *testing.T) {
	sources := nonTestSources(t)

	// Alternate credential-header spellings that must NOT appear: the guest
	// carries exactly one credential, and only via the standard Authorization
	// header set in client.go.
	forbidden := []string{
		`"X-Api-Key"`,
		`"X-API-Key"`,
		`"Proxy-Authorization"`,
		`"X-Auth-Token"`,
		`"Cookie"`,
	}

	for _, path := range sources {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(content)
		for _, pat := range forbidden {
			if strings.Contains(text, pat) {
				t.Errorf("forbidden alternate credential header %q found in non-test source %s (the only credential header is Authorization: Bearer)", pat, filepath.Base(path))
			}
		}
	}
}

// TestBearerHeaderConstructedInClient asserts that the Authorization: Bearer
// header construction is present — and ONLY — in client.go. This pins the
// single credential code path: exactly one file sets the header, so a stray
// second credential path elsewhere is caught.
func TestBearerHeaderConstructedInClient(t *testing.T) {
	sources := nonTestSources(t)
	var withBearer []string
	for _, path := range sources {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(content), `"Bearer "`) {
			withBearer = append(withBearer, filepath.Base(path))
		}
	}
	if len(withBearer) != 1 || withBearer[0] != "client.go" {
		t.Errorf("Bearer header must be constructed in exactly client.go; found in %v", withBearer)
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
