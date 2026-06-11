// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package coverage holds the coverage-ratchet gate. A floor is recorded in
// .coverage-floor at the repository root; the gate fails if measured total
// coverage drops below that floor, so coverage can only ratchet upward.
package coverage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCoverageRatchet reads the recorded floor and the measured total
// coverage and fails when measured < floor.
//
// The measured total comes from a coverage profile whose path is passed in
// the COVERAGE_PROFILE env var (CI produces it with `go test -coverprofile`).
// When the env var is unset — the local default — the test skips with a
// notice rather than recomputing, keeping local runs fast and deterministic.
func TestCoverageRatchet(t *testing.T) {
	floor := readFloor(t)

	profile := os.Getenv("COVERAGE_PROFILE")
	if profile == "" {
		t.Skipf("COVERAGE_PROFILE unset; skipping coverage ratchet (floor is %.2f%%). "+
			"CI sets COVERAGE_PROFILE to the profile from `go test ./... -coverprofile`.", floor)
	}

	measured := measuredTotal(t, profile)
	if measured < floor {
		t.Fatalf("coverage regression: measured total %.2f%% is below the recorded floor %.2f%%; "+
			"raise coverage or, only with justification, lower .coverage-floor", measured, floor)
	}
	t.Logf("coverage ratchet ok: measured %.2f%% >= floor %.2f%%", measured, floor)
}

// readFloor reads .coverage-floor (a single decimal percentage, e.g. 71.00)
// from the repository root.
func readFloor(t *testing.T) float64 {
	t.Helper()
	path := filepath.Join(repoRoot(t), ".coverage-floor")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading coverage floor at %s: %v", path, err)
	}
	floor, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
	if err != nil {
		t.Fatalf("parsing coverage floor %q: %v", strings.TrimSpace(string(raw)), err)
	}
	return floor
}

// measuredTotal parses the total statement coverage from a coverage profile
// via `go tool cover -func`.
func measuredTotal(t *testing.T, profile string) float64 {
	t.Helper()
	if !filepath.IsAbs(profile) {
		profile = filepath.Join(repoRoot(t), profile)
	}
	cmd := exec.Command("go", "tool", "cover", "-func="+profile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go tool cover -func failed for %s: %v\n%s", profile, err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	fields := strings.Fields(last)
	if len(fields) == 0 {
		t.Fatalf("could not parse coverage total from:\n%s", out)
	}
	pct := strings.TrimSuffix(fields[len(fields)-1], "%")
	measured, err := strconv.ParseFloat(pct, 64)
	if err != nil {
		t.Fatalf("parsing measured coverage %q: %v", pct, err)
	}
	return measured
}

// repoRoot returns the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolving module root failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}
