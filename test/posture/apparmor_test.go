// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package posture also pins the CONTENT of the narrow ocu-mount AppArmor profile
// as a static content check over the committed artifact. The compose-posture pins
// (compose_posture_test.go) assert the mount service REFERENCES apparmor=ocu-mount
// and is never unconfined; the seccomp pins (seccomp_test.go) assert the seccomp
// profile's content. Until now nothing asserted the AppArmor profile's OWN
// content, so a widening edit — a second capability, a bare unscoped mount rule, a
// dropped `deny ptrace`, a raw/packet network grant — would pass every static gate
// and would NOT redden the live e2e (widening does not break the happy path). This
// file closes that gap: it goes RED in ordinary `go test` the moment the profile is
// loosened past the deliberate narrow allowances, the AppArmor analog of the
// seccomp content pin.
package posture

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// apparmorProfilePath is the committed AppArmor profile the mount runs under,
// relative to this test file (repo deploy/compose/apparmor).
const apparmorProfilePath = "../../deploy/compose/apparmor/ocu-mount.profile"

// loadApparmorRules reads the profile and returns its rule lines with comments and
// blank lines stripped, each trimmed. The content pins below reason over rule
// lines, not comment prose, so a rule mentioned only inside a `#` comment never
// satisfies (or trips) a pin.
func loadApparmorRules(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(apparmorProfilePath)
	if err != nil {
		t.Fatalf("read apparmor profile: %v", err)
	}
	var rules []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rules = append(rules, trimmed)
	}
	return rules
}

// anyRuleMatches reports whether any rule line matches re.
func anyRuleMatches(rules []string, re *regexp.Regexp) bool {
	for _, r := range rules {
		if re.MatchString(r) {
			return true
		}
	}
	return false
}

// TestApparmorProfileName pins the profile declaration to the exact name the
// compose posture references (apparmor=ocu-mount). A renamed profile would fail to
// load under that reference at deploy, so the name is load-bearing.
func TestApparmorProfileName(t *testing.T) {
	rules := loadApparmorRules(t)
	nameRe := regexp.MustCompile(`^profile\s+ocu-mount\s`)
	if !anyRuleMatches(rules, nameRe) {
		t.Errorf("apparmor profile must declare `profile ocu-mount ...`; the compose posture " +
			"references it by that exact name (apparmor=ocu-mount)")
	}
}

// TestApparmorGrantsOnlySysAdminCapability pins the capability surface: the profile
// must grant `capability sys_admin` (the FUSE mount/umount path's only capability)
// and NO other capability. A second capability line (sys_ptrace, sys_module,
// dac_override, ...) is a widening — the whole point of the narrow profile is that
// it does not restore the default capability set. This is the profile-content twin
// of the compose cap_add:[SYS_ADMIN] pin.
func TestApparmorGrantsOnlySysAdminCapability(t *testing.T) {
	rules := loadApparmorRules(t)
	capRe := regexp.MustCompile(`^capability\b`)
	var caps []string
	for _, r := range rules {
		if capRe.MatchString(r) {
			caps = append(caps, r)
		}
	}
	if len(caps) != 1 {
		t.Fatalf("apparmor profile must carry exactly one capability rule, got %d: %v — the "+
			"narrow profile grants only CAP_SYS_ADMIN; a second capability line is a widening",
			len(caps), caps)
	}
	// The sole capability must be sys_admin (allow rule `capability sys_admin,`),
	// not a broader `capability,` (all) and not a different single capability.
	sysAdminRe := regexp.MustCompile(`^capability\s+sys_admin\s*,`)
	if !sysAdminRe.MatchString(caps[0]) {
		t.Errorf("the sole capability rule is %q, want `capability sys_admin,` — a bare "+
			"`capability,` grants ALL capabilities and any other single cap is the wrong one", caps[0])
	}
}

// TestApparmorMountRuleScopedToFuse pins the mount surface: the profile must permit
// a fuse.* mount and must NOT carry a bare unscoped `mount,` rule (which permits
// mounting ANY filesystem type onto ANY target). Only fuse.* superblocks may be
// mounted; a bare mount rule is the highest-value widening a FUSE profile can leak.
func TestApparmorMountRuleScopedToFuse(t *testing.T) {
	rules := loadApparmorRules(t)

	fuseMountRe := regexp.MustCompile(`^mount\s+fstype=fuse\.\*`)
	if !anyRuleMatches(rules, fuseMountRe) {
		t.Error("apparmor profile must permit `mount fstype=fuse.* -> ...` (the FUSE mount the " +
			"guest performs); without it the in-process mount(2) is refused")
	}

	// A bare `mount,` or `mount <target>` with no fstype constraint permits mounting
	// any filesystem type — forbidden. Every mount allow rule must constrain fstype.
	bareMountRe := regexp.MustCompile(`^mount\s*,`)
	unscopedMountRe := regexp.MustCompile(`^mount\s+(?:options|[/(-])`) // mount with options=/path but no fstype=
	for _, r := range rules {
		if bareMountRe.MatchString(r) {
			t.Errorf("apparmor profile carries a bare unscoped mount rule %q; only "+
				"`mount fstype=fuse.*` may be permitted — a bare mount rule allows mounting any "+
				"filesystem type", r)
		}
		// A mount allow rule that starts to specify a target/options without an
		// fstype= constraint is also a widening.
		if unscopedMountRe.MatchString(r) && !strings.Contains(r, "fstype=fuse.") {
			t.Errorf("apparmor profile carries a mount rule without an fstype=fuse.* "+
				"constraint %q; every permitted mount must be scoped to fuse.*", r)
		}
	}
}

// TestApparmorDeniesPtrace pins the explicit `deny ptrace` hardening. ptrace out of
// the profile is a cross-process attack primitive; the profile denies it explicitly
// (belt to the default-deny suspenders). Dropping the deny, or worse adding a
// ptrace ALLOW, is a widening this pin catches.
func TestApparmorDeniesPtrace(t *testing.T) {
	rules := loadApparmorRules(t)

	denyPtraceRe := regexp.MustCompile(`^deny\s+ptrace\b`)
	if !anyRuleMatches(rules, denyPtraceRe) {
		t.Error("apparmor profile must carry `deny ptrace` (explicit cross-process attack denial)")
	}

	// ptrace must NEVER appear in an ALLOW position (a rule that mentions ptrace and
	// is not a deny rule). Any such rule is a widening.
	for _, r := range rules {
		if !strings.Contains(r, "ptrace") {
			continue
		}
		if !strings.HasPrefix(r, "deny ") {
			t.Errorf("apparmor profile has a non-deny rule mentioning ptrace %q; ptrace must "+
				"only ever appear in a `deny` rule", r)
		}
	}
}

// TestApparmorNetworkIsNarrowInetOnly pins the network surface to the single
// outbound leg the guest needs: inet/inet6 stream+dgram sockets for the HTTPS dial
// to the edge and the DNS lookup that precedes it. A broader grant — a bare
// `network,` (all families), or raw/packet/netlink sockets — is a widening that
// hands the guest a transport it must never have (the guest has exactly one network
// path, and no second transport per SEC-25).
func TestApparmorNetworkIsNarrowInetOnly(t *testing.T) {
	rules := loadApparmorRules(t)

	// The four deliberate legs must be present.
	for _, want := range []string{
		`^network\s+inet\s+stream\b`,
		`^network\s+inet6\s+stream\b`,
		`^network\s+inet\s+dgram\b`,
		`^network\s+inet6\s+dgram\b`,
	} {
		if !anyRuleMatches(rules, regexp.MustCompile(want)) {
			t.Errorf("apparmor profile missing the deliberate network leg matching %q", want)
		}
	}

	// Forbidden broadenings: a bare `network,` (all families/types), or any
	// raw/packet/netlink/bluetooth/vsock socket grant.
	bareNetworkRe := regexp.MustCompile(`^network\s*,`)
	if anyRuleMatches(rules, bareNetworkRe) {
		t.Error("apparmor profile carries a bare `network,` rule (ALL address families); the " +
			"guest's socket surface must stay the narrow inet/inet6 stream+dgram set")
	}
	forbiddenFamilyRe := regexp.MustCompile(`^network\s+(raw|packet|netlink|bluetooth|vsock|can|rds)\b`)
	for _, r := range rules {
		if forbiddenFamilyRe.MatchString(r) {
			t.Errorf("apparmor profile grants a forbidden network family %q; only inet/inet6 "+
				"stream+dgram are permitted (the single outbound HTTPS+DNS leg)", r)
		}
	}
}
