// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package e2e holds the real end-to-end exercise for the mount binary (the
// e2e-tagged files) plus the untagged /proc/<pid>/status parsers and posture
// predicates this file carries.
//
// This file is deliberately NOT behind the e2e build tag: keeping the parsers
// and predicates untagged means their two-sided proof (procstatus_test.go)
// compiles and runs under a plain `go test ./test/e2e/` on every PR — no Lima,
// no live gate — so a regression that makes a predicate vacuous (e.g. a parser
// that stops distinguishing NoNewPrivs=0 from =1) goes RED in ordinary CI, while
// the live arms in mount_runtime_posture_test.go bind the same predicates to the
// real kernel values on the amd64 live-e2e job. doc.go carries the fuller
// exercise narrative under the e2e tag.
package e2e

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// The hardened-posture constants the live mount container must exhibit at run
// time. Each is a single authoritative source shared by the live arm (which
// reads the value off the real process) and the predicate unit test (which
// drives both the hardened and a weakened value through the predicate).
const (
	// capSysAdmin is the lone capability bit the FUSE mount(2)/umount2(2) path
	// needs: bit 21 (CAP_SYS_ADMIN), 0x200000. cap_drop:[ALL]+cap_add:[SYS_ADMIN]
	// must reduce BOTH the effective set (CapEff) and the bounding set (CapBnd) to
	// exactly this — the bounding set is what caps anything a later execve could
	// regain, so pinning it catches a drop regression the effective set alone can
	// miss.
	capSysAdmin uint64 = 1 << 21

	// seccompModeFilter is the /proc/<pid>/status Seccomp value for
	// SECCOMP_MODE_FILTER (2): a seccomp BPF filter is loaded. 0 is disabled, 1 is
	// the strict single-syscall mode. The narrow mount-fuse.json profile must
	// leave the process in mode 2.
	seccompModeFilter = 2

	// noNewPrivsEnabled is the /proc/<pid>/status NoNewPrivs value once
	// no-new-privileges:true has taken effect (PR_SET_NO_NEW_PRIVS): 1.
	noNewPrivsEnabled = 1
)

// parseStatusField extracts the trimmed value of a "Key:" line from
// /proc/<pid>/status content. ok is false when no such line is present.
func parseStatusField(r io.Reader, key string) (value string, ok bool) {
	prefix := key + ":"
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, prefix)), true
	}
	return "", false
}

// parseStatusHex extracts a hex-encoded status field (CapEff, CapBnd) as a
// uint64. ok is false if the field is absent or not valid hex.
func parseStatusHex(r io.Reader, key string) (v uint64, ok bool) {
	raw, present := parseStatusField(r, key)
	if !present {
		return 0, false
	}
	parsed, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// parseStatusInt extracts a decimal status field (NoNewPrivs, Seccomp) as an int,
// tolerating trailing whitespace-separated tokens. ok is false if the field is
// absent or the first token is not an integer.
func parseStatusInt(r io.Reader, key string) (v int, ok bool) {
	raw, present := parseStatusField(r, key)
	if !present {
		return 0, false
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return 0, false
	}
	parsed, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// capIsExactlySysAdmin reports whether a capability mask (effective or bounding)
// is exactly CAP_SYS_ADMIN and nothing more. A missing CAP_SYS_ADMIN bit is an
// over-tightening that would break mount(2); any extra bit is a capability that
// leaked past cap_drop:[ALL].
func capIsExactlySysAdmin(mask uint64) bool {
	return mask == capSysAdmin
}

// noNewPrivsSet reports whether NoNewPrivs is enabled (execve can gain no new
// privileges). A regression that removes no-new-privileges:true drops this to 0.
func noNewPrivsSet(v int) bool {
	return v == noNewPrivsEnabled
}

// seccompFilterLoaded reports whether the process is in SECCOMP_MODE_FILTER — a
// BPF filter (the narrow mount-fuse.json profile) is loaded. A regression that
// strips the seccomp profile drops this to 0 (disabled).
func seccompFilterLoaded(mode int) bool {
	return mode == seccompModeFilter
}
