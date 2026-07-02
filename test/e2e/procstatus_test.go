// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Untagged (no e2e build tag): this runs under a plain `go test ./test/e2e/` on
// every PR. It is the host-runnable two-sided proof that the posture predicates
// the live runtime-posture arms assert on are NON-VACUOUS — each predicate must
// accept the hardened value and REJECT a weakened one. The live arms in
// mount_runtime_posture_test.go bind these same predicates to the real
// /proc/<pid>/status of the running mount on the amd64 live-e2e job; here we
// prove the extraction-and-decision logic itself distinguishes a hardened
// process from a regressed one, so a future edit that silently voids a predicate
// goes RED without needing the live kernel.
package e2e

import (
	"strings"
	"testing"
)

// hardenedStatus is a /proc/<pid>/status excerpt for the fully hardened mount
// process, byte-shaped like the real file: cap masks reduced to CAP_SYS_ADMIN,
// NoNewPrivs enabled, seccomp in filter mode. These are the values observed on
// the live hardened mount.
const hardenedStatus = `Name:	ocu-rclone-file
Umask:	0022
State:	S (sleeping)
CapInh:	0000000000000000
CapPrm:	0000000000200000
CapEff:	0000000000200000
CapBnd:	0000000000200000
CapAmb:	0000000000000000
NoNewPrivs:	1
Seccomp:	2
Seccomp_filters:	1
`

// weakenedStatus is the same file shape for a REGRESSED process: the capability
// masks carry extra bits (a leaked drop), NoNewPrivs is off, and seccomp is
// disabled. Every predicate must reject these — that rejection is what makes the
// live arms real regression guards.
const weakenedStatus = `Name:	ocu-rclone-file
Umask:	0022
State:	S (sleeping)
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Seccomp_filters:	0
`

// TestParseStatusFieldsHardened proves the parsers extract each field from a
// real-shaped status excerpt.
func TestParseStatusFieldsHardened(t *testing.T) {
	capEff, ok := parseStatusHex(strings.NewReader(hardenedStatus), "CapEff")
	if !ok || capEff != capSysAdmin {
		t.Fatalf("parseStatusHex CapEff = 0x%x ok=%v; want 0x%x ok=true", capEff, ok, capSysAdmin)
	}
	capBnd, ok := parseStatusHex(strings.NewReader(hardenedStatus), "CapBnd")
	if !ok || capBnd != capSysAdmin {
		t.Fatalf("parseStatusHex CapBnd = 0x%x ok=%v; want 0x%x ok=true", capBnd, ok, capSysAdmin)
	}
	nnp, ok := parseStatusInt(strings.NewReader(hardenedStatus), "NoNewPrivs")
	if !ok || nnp != noNewPrivsEnabled {
		t.Fatalf("parseStatusInt NoNewPrivs = %d ok=%v; want %d ok=true", nnp, ok, noNewPrivsEnabled)
	}
	sec, ok := parseStatusInt(strings.NewReader(hardenedStatus), "Seccomp")
	if !ok || sec != seccompModeFilter {
		t.Fatalf("parseStatusInt Seccomp = %d ok=%v; want %d ok=true", sec, ok, seccompModeFilter)
	}
}

// TestParseStatusFieldAbsent proves a missing field reports ok=false rather than
// a misleading zero that a predicate could mistake for a value.
func TestParseStatusFieldAbsent(t *testing.T) {
	if _, ok := parseStatusHex(strings.NewReader(hardenedStatus), "CapNope"); ok {
		t.Fatal("parseStatusHex on an absent key = ok; want ok=false")
	}
	if _, ok := parseStatusInt(strings.NewReader(hardenedStatus), "NoSuchField"); ok {
		t.Fatal("parseStatusInt on an absent key = ok; want ok=false")
	}
}

// TestParseStatusMalformed proves the numeric parsers reject a present-but-junk
// field: a value that is not valid hex (or not an integer, or empty) reports
// ok=false rather than a silent zero a predicate could misread as a value. The
// zero-value + ok=false contract is what keeps a corrupted status line from
// passing an arm.
func TestParseStatusMalformed(t *testing.T) {
	const junkHex = "CapEff:\tnot-a-hex-value\n"
	if v, ok := parseStatusHex(strings.NewReader(junkHex), "CapEff"); ok || v != 0 {
		t.Fatalf("parseStatusHex on junk hex = (0x%x, ok=%v); want (0, false)", v, ok)
	}

	const junkInt = "NoNewPrivs:\tnot-an-int\n"
	if v, ok := parseStatusInt(strings.NewReader(junkInt), "NoNewPrivs"); ok || v != 0 {
		t.Fatalf("parseStatusInt on junk int = (%d, ok=%v); want (0, false)", v, ok)
	}

	const emptyVal = "Seccomp:\t\n"
	if v, ok := parseStatusInt(strings.NewReader(emptyVal), "Seccomp"); ok || v != 0 {
		t.Fatalf("parseStatusInt on an empty value = (%d, ok=%v); want (0, false)", v, ok)
	}
}

// TestPosturePredicatesTwoSided is the core non-vacuity proof: each predicate
// must ACCEPT the hardened value and REJECT the weakened one. If a predicate
// accepted both (or rejected both), the live arm using it could not tell a
// hardened process from a regressed one — the guard would be vacuous.
func TestPosturePredicatesTwoSided(t *testing.T) {
	// capBnd/capEff: exactly CAP_SYS_ADMIN accepted; a leaked wider mask rejected.
	hardEff, _ := parseStatusHex(strings.NewReader(hardenedStatus), "CapEff")
	weakEff, _ := parseStatusHex(strings.NewReader(weakenedStatus), "CapEff")
	if !capIsExactlySysAdmin(hardEff) {
		t.Errorf("capIsExactlySysAdmin(hardened CapEff 0x%x) = false; want true", hardEff)
	}
	if capIsExactlySysAdmin(weakEff) {
		t.Errorf("capIsExactlySysAdmin(weakened CapEff 0x%x) = true; want false (a wider mask must be rejected)", weakEff)
	}

	hardBnd, _ := parseStatusHex(strings.NewReader(hardenedStatus), "CapBnd")
	weakBnd, _ := parseStatusHex(strings.NewReader(weakenedStatus), "CapBnd")
	if !capIsExactlySysAdmin(hardBnd) {
		t.Errorf("capIsExactlySysAdmin(hardened CapBnd 0x%x) = false; want true", hardBnd)
	}
	if capIsExactlySysAdmin(weakBnd) {
		t.Errorf("capIsExactlySysAdmin(weakened CapBnd 0x%x) = true; want false", weakBnd)
	}

	// NoNewPrivs: enabled accepted; disabled rejected.
	hardNNP, _ := parseStatusInt(strings.NewReader(hardenedStatus), "NoNewPrivs")
	weakNNP, _ := parseStatusInt(strings.NewReader(weakenedStatus), "NoNewPrivs")
	if !noNewPrivsSet(hardNNP) {
		t.Errorf("noNewPrivsSet(hardened %d) = false; want true", hardNNP)
	}
	if noNewPrivsSet(weakNNP) {
		t.Errorf("noNewPrivsSet(weakened %d) = true; want false (NoNewPrivs off must be rejected)", weakNNP)
	}

	// Seccomp: filter mode accepted; disabled rejected.
	hardSec, _ := parseStatusInt(strings.NewReader(hardenedStatus), "Seccomp")
	weakSec, _ := parseStatusInt(strings.NewReader(weakenedStatus), "Seccomp")
	if !seccompFilterLoaded(hardSec) {
		t.Errorf("seccompFilterLoaded(hardened %d) = false; want true", hardSec)
	}
	if seccompFilterLoaded(weakSec) {
		t.Errorf("seccompFilterLoaded(weakened %d) = true; want false (seccomp disabled must be rejected)", weakSec)
	}
}
