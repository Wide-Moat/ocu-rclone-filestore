// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

// writeSet mints a CA + one filestore leaf with the given TTL into out and
// renders a marker guest-config, i.e. the minimum set needsReissue inspects: the
// guest-config.json marker and the representative filestore.cert.pem leaf.
func writeSet(t *testing.T, out string, ttl time.Duration) {
	t.Helper()
	if err := os.MkdirAll(out, 0o750); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	ca, err := localca.NewWithTTL(ttl)
	if err != nil {
		t.Fatalf("mint CA: %v", err)
	}
	certPEM, keyPEM, err := issueLeafPEM(ca, serviceNames[0])
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, serviceNames[0]+".cert.pem"), certPEM, 0o600); err != nil {
		t.Fatalf("write leaf cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, serviceNames[0]+".key.pem"), keyPEM, 0o600); err != nil {
		t.Fatalf("write leaf key: %v", err)
	}
	// The marker the guard stats. Content is irrelevant to needsReissue.
	if err := os.WriteFile(filepath.Join(out, "guest-config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

// TestNeedsReissueOnExpiringLeaf is the keystone RED-baseline: a rendered set
// whose leaf is already past its NotAfter must trigger a re-issue, not the
// leave-in-place path. Breaking the guard (e.g. reverting to a stat-only check)
// makes this fail.
func TestNeedsReissueOnExpiringLeaf(t *testing.T) {
	out := t.TempDir()
	// A leaf with a tiny TTL: NotAfter is now+1ms, already inside any real renew
	// window a moment later.
	writeSet(t, out, time.Millisecond)

	// Evaluate as-of a time well past that NotAfter.
	future := time.Now().Add(time.Hour)
	reissue, why, err := needsReissue(out, 2*time.Hour, future)
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if !reissue {
		t.Fatalf("expired leaf must trigger re-issue; got reissue=false (why=%q)", why)
	}
}

// TestNeedsReissueLeavesFreshLeaf pins the idempotent half: a set whose leaf is
// comfortably valid (full default TTL) must be left in place.
func TestNeedsReissueLeavesFreshLeaf(t *testing.T) {
	out := t.TempDir()
	writeSet(t, out, localca.DefaultCertTTL)

	reissue, why, err := needsReissue(out, 2*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if reissue {
		t.Fatalf("a fresh full-TTL leaf must be left in place; got reissue=true (why=%q)", why)
	}
}

// TestNeedsReissueOnAbsentSet covers the first-run path: no marker means produce
// the set.
func TestNeedsReissueOnAbsentSet(t *testing.T) {
	out := t.TempDir() // empty: no guest-config.json
	reissue, _, err := needsReissue(out, 2*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if !reissue {
		t.Fatal("an absent set must trigger production")
	}
}

// TestNeedsReissueOnTornLeaf covers a present marker with a missing/unparseable
// leaf: a partial set must be re-issued, not served broken.
func TestNeedsReissueOnTornLeaf(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "guest-config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	// No leaf file at all.
	reissue, why, err := needsReissue(out, 2*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if !reissue {
		t.Fatalf("a marker with no leaf must re-issue; got reissue=false (why=%q)", why)
	}
}

// TestNeedsReissueDisabledByZeroWindow pins the opt-out: renewBefore<=0 restores
// pure stat-idempotency even for an expired leaf.
func TestNeedsReissueDisabledByZeroWindow(t *testing.T) {
	out := t.TempDir()
	writeSet(t, out, time.Millisecond)
	future := time.Now().Add(time.Hour)

	reissue, _, err := needsReissue(out, 0, future)
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if reissue {
		t.Fatal("renewBefore<=0 must disable the expiry check and leave the set in place")
	}
}

// TestRunReissuesExpiredSet is the integration keystone: a first run that stamps
// an already-expired leaf, then a normal-TTL run, must ROTATE the set to a leaf
// whose NotAfter is in the future — proving the guard both detects expiry and
// heals it end-to-end through run().
func TestRunReissuesExpiredSet(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.json")
	if err := os.WriteFile(tmpl, []byte(fixtureTemplate), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	out := filepath.Join(dir, "shared")

	// First run stamps a leaf that is already expired (1ns TTL).
	if err := run(out, "edge", 8450, tmpl, time.Nanosecond, testRenewBefore); err != nil {
		t.Fatalf("first run: %v", err)
	}
	firstNotAfter := readLeafNotAfter(t, filepath.Join(out, serviceNames[0]+".cert.pem"))
	if firstNotAfter.After(time.Now()) {
		t.Fatalf("precondition: the seeded leaf should already be expired, NotAfter=%s", firstNotAfter)
	}

	// Second run with a real TTL must re-issue, not leave the dead set in place.
	if err := run(out, "edge", 8450, tmpl, testCertTTL, testRenewBefore); err != nil {
		t.Fatalf("second run: %v", err)
	}
	secondNotAfter := readLeafNotAfter(t, filepath.Join(out, serviceNames[0]+".cert.pem"))
	if !secondNotAfter.After(time.Now()) {
		t.Fatalf("re-issued leaf must be valid into the future; NotAfter=%s", secondNotAfter)
	}
	if !secondNotAfter.After(firstNotAfter) {
		t.Fatalf("second run did not rotate the leaf: NotAfter unchanged at %s", secondNotAfter)
	}
}

// TestRunLeavesFreshSet is the integration idempotency half: a first normal run,
// then a second, must NOT rotate the leaf (same NotAfter).
func TestRunLeavesFreshSet(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.json")
	if err := os.WriteFile(tmpl, []byte(fixtureTemplate), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	out := filepath.Join(dir, "shared")

	if err := run(out, "edge", 8450, tmpl, testCertTTL, testRenewBefore); err != nil {
		t.Fatalf("first run: %v", err)
	}
	first := readLeafNotAfter(t, filepath.Join(out, serviceNames[0]+".cert.pem"))
	if err := run(out, "edge", 8450, tmpl, testCertTTL, testRenewBefore); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second := readLeafNotAfter(t, filepath.Join(out, serviceNames[0]+".cert.pem"))
	if !first.Equal(second) {
		t.Fatalf("a fresh set was rotated: NotAfter %s -> %s", first, second)
	}
}

// TestLeafNotAfterRejectsBadInput pins leafNotAfter's error paths: a missing
// file, a file with no CERTIFICATE block, and a CERTIFICATE block with garbage
// DER each return an error so needsReissue treats the set as torn.
func TestLeafNotAfterRejectsBadInput(t *testing.T) {
	dir := t.TempDir()

	if _, err := leafNotAfter(filepath.Join(dir, "absent.pem")); err == nil {
		t.Fatal("a missing leaf file must error")
	}

	noBlock := filepath.Join(dir, "noblock.pem")
	if err := os.WriteFile(noBlock, []byte("not pem at all"), 0o600); err != nil {
		t.Fatalf("write noblock: %v", err)
	}
	if _, err := leafNotAfter(noBlock); err == nil {
		t.Fatal("a file with no CERTIFICATE PEM block must error")
	}

	badDER := filepath.Join(dir, "badder.pem")
	garbage := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	if err := os.WriteFile(badDER, garbage, 0o600); err != nil {
		t.Fatalf("write badder: %v", err)
	}
	if _, err := leafNotAfter(badDER); err == nil {
		t.Fatal("a CERTIFICATE block with unparseable DER must error")
	}
}

// readLeafNotAfter parses a PEM leaf file and returns its NotAfter.
func readLeafNotAfter(t *testing.T, path string) time.Time {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read leaf %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no CERTIFICATE block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf %s: %v", path, err)
	}
	return cert.NotAfter
}
