// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

// writeSet mints a CA + one filestore leaf with the given TTL into out, mints a
// fresh weak-tokens.json whose token exp is stamped with the SAME ttl (so the
// token axis and the cert axis stay coupled exactly as run couples them), and
// renders a marker guest-config. This is the minimum COHERENT set needsReissue
// inspects across both axes: the guest-config.json marker, the representative
// filestore.cert.pem leaf, and the weak-tokens.json token set.
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
	// A fresh weak-tokens.json whose token exp tracks the leaf's TTL, so the token
	// axis is coherent with the cert axis for every writeSet caller.
	writeTokensExpiringAt(t, out, time.Now().Add(ttl))
	// The marker the guard stats. Content is irrelevant to needsReissue.
	if err := os.WriteFile(filepath.Join(out, "guest-config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

// writeTokensExpiringAt mints a single weak session JWT under a throwaway ES256
// key with the given exp and writes it as weak-tokens.json in run's artifact
// shape (map[string]string of fsid -> compact JWT). It lets a test seed a token
// axis whose lifetime is decoupled from the cert axis, to exercise the
// token-expiry arm of needsReissue independently.
func writeTokensExpiringAt(t *testing.T, out string, exp time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("throwaway key: %v", err)
	}
	tok, err := jwtmint.Sign(key, "kid-test", jwtmint.Claims{
		Issuer:       cpIssuer,
		Audience:     cpAudience,
		Subject:      weakJWTScopes[0].fsid,
		IssuedAt:     time.Now().Unix(),
		Expiry:       exp.Unix(),
		FilesystemID: weakJWTScopes[0].fsid,
		Intent:       weakJWTScopes[0].intent,
	})
	if err != nil {
		t.Fatalf("sign weak token: %v", err)
	}
	raw, err := json.Marshal(map[string]string{weakJWTScopes[0].fsid: tok})
	if err != nil {
		t.Fatalf("marshal tokens: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, "weak-tokens.json"), raw, 0o600); err != nil {
		t.Fatalf("write weak tokens: %v", err)
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

// TestNeedsReissueOnExpiredWeakJWT is the M1 keystone RED-baseline: a set whose
// LEAF is fresh (full default TTL) but whose weak-tokens.json token is already
// expired must trigger a re-issue on the TOKEN axis. On the pre-M1 guard (leaf
// axis only) this is reissue=false — a fresh cert masks the dead tokens, the edge
// 401s every request, and the stand self-heals nothing.
func TestNeedsReissueOnExpiredWeakJWT(t *testing.T) {
	out := t.TempDir()
	// Fresh full-TTL leaf + coherent fresh tokens...
	writeSet(t, out, localca.DefaultCertTTL)
	// ...then OVERWRITE the token set with an already-expired token.
	writeTokensExpiringAt(t, out, time.Now().Add(-time.Hour))

	reissue, why, err := needsReissue(out, 2*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if !reissue {
		t.Fatalf("an expired weak JWT (fresh leaf) must trigger re-issue; got reissue=false")
	}
	if !strings.Contains(why, "weak JWT") {
		t.Fatalf("expected a token-axis reason, got %q", why)
	}
}

// TestNeedsReissueLeavesFreshWeakJWT pins the idempotent half of the token axis:
// a fresh leaf and a comfortably-valid token must be left in place.
func TestNeedsReissueLeavesFreshWeakJWT(t *testing.T) {
	out := t.TempDir()
	writeSet(t, out, localca.DefaultCertTTL)
	// An explicit far-future token exp exercises the "token comfortably valid"
	// branch beyond what the coupled writeSet TTL already covers.
	writeTokensExpiringAt(t, out, time.Now().Add(48*time.Hour))

	reissue, why, err := needsReissue(out, 2*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if reissue {
		t.Fatalf("a fresh leaf and a far-future token must be left in place; got reissue=true (why=%q)", why)
	}
}

// TestNeedsReissueOnTornWeakTokens covers a present marker + fresh leaf but a
// missing/garbage weak-tokens.json: a partial set must be re-issued, mirroring
// TestNeedsReissueOnTornLeaf on the token axis.
func TestNeedsReissueOnTornWeakTokens(t *testing.T) {
	out := t.TempDir()
	writeSet(t, out, localca.DefaultCertTTL)

	// Delete the token set: an older set (or a torn write) that predates the token
	// axis must re-issue, not serve dead tokens.
	if err := os.Remove(filepath.Join(out, "weak-tokens.json")); err != nil {
		t.Fatalf("remove weak tokens: %v", err)
	}
	reissue, why, err := needsReissue(out, 2*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("needsReissue: %v", err)
	}
	if !reissue {
		t.Fatalf("a marker with no weak-tokens.json must re-issue; got reissue=false")
	}
	if !strings.Contains(why, "weak-tokens.json") {
		t.Fatalf("expected a torn-token reason, got %q", why)
	}

	// Garbage token file: unparseable JSON is likewise a torn set.
	if err := os.WriteFile(filepath.Join(out, "weak-tokens.json"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write garbage tokens: %v", err)
	}
	if reissue, _, err := needsReissue(out, 2*time.Hour, time.Now()); err != nil || !reissue {
		t.Fatalf("garbage weak-tokens.json must re-issue; got reissue=%v err=%v", reissue, err)
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
