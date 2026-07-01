// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package posture pins the deploy-time hardening posture of the guest mount as
// content checks over the committed compose and seccomp artifacts. These pins go
// RED when the posture is weakened in the tree, independent of any running host.
package posture

import (
	"encoding/json"
	"os"
	"testing"
)

// seccompProfilePath is the committed seccomp profile the mount runs under,
// relative to this test file (repo deploy/compose/seccomp).
const seccompProfilePath = "../../deploy/compose/seccomp/mount-fuse.json"

// seccompProfile is the minimal shape this pin needs: the top-level default
// action and the per-rule (names, action) tuples. Everything else in the
// profile (archMap, args, includes, excludes) is intentionally ignored.
type seccompProfile struct {
	DefaultAction string `json:"defaultAction"`
	Syscalls      []struct {
		Names  []string `json:"names"`
		Action string   `json:"action"`
	} `json:"syscalls"`
}

// loadSeccompProfile reads and unmarshals the committed profile.
func loadSeccompProfile(t *testing.T) seccompProfile {
	t.Helper()
	raw, err := os.ReadFile(seccompProfilePath)
	if err != nil {
		t.Fatalf("read seccomp profile: %v", err)
	}
	var p seccompProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal seccomp profile: %v", err)
	}
	return p
}

// TestSeccompDefaultActionDenies pins the profile to a default-deny stance: any
// syscall not explicitly allow-listed must return an errno, never run. If the
// default action is broadened to ALLOW (or LOG/TRACE), the narrow allow set
// stops meaning anything and this pin goes RED.
func TestSeccompDefaultActionDenies(t *testing.T) {
	p := loadSeccompProfile(t)
	const want = "SCMP_ACT_ERRNO"
	if p.DefaultAction != want {
		t.Fatalf("defaultAction = %q, want %q (profile must default-deny; a broader default voids the narrow allow set)", p.DefaultAction, want)
	}
}

// TestSeccompAllowsDeliberateSyscalls pins the syscalls this guest deliberately
// adds on top of the container-runtime default-minus-admin set: mount and
// umount2 (attach/detach the fuse superblock) and clone/clone3 (the language
// runtime's OS-thread creation under CAP_SYS_ADMIN). Each must appear in some
// rule whose action is SCMP_ACT_ALLOW. Dropping any of them (over-tightening)
// goes RED here and would break the mount or crash the runtime at deploy.
func TestSeccompAllowsDeliberateSyscalls(t *testing.T) {
	p := loadSeccompProfile(t)

	const allow = "SCMP_ACT_ALLOW"
	// allowed[name] is true once name is seen in an SCMP_ACT_ALLOW rule.
	allowed := map[string]bool{}
	for _, rule := range p.Syscalls {
		if rule.Action != allow {
			continue
		}
		for _, name := range rule.Names {
			allowed[name] = true
		}
	}

	for _, name := range []string{"mount", "umount2", "clone", "clone3"} {
		if !allowed[name] {
			t.Errorf("syscall %q is not in any %s rule; the deliberate allow set was over-tightened", name, allow)
		}
	}
}
