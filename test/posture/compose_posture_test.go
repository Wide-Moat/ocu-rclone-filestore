// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package posture pins the deployment posture of the guest mount service. It
// parses the compose harness YAML directly (no docker dependency, so the gate
// runs on every PR under plain `go test`) and asserts the four hardening levers
// the mount service carries: a narrow AppArmor profile (never unconfined), an
// all-dropped-but-SYS_ADMIN capability set, no-new-privileges, and a read-only
// root with the VFS cache tmpfs. These checks pin the file CONTENT of the
// compose posture; the kernel BINDING of inet-mediation, seccomp serve-path and
// private-pid is proven on the amd64 CI runner.
package posture

import (
	"os"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// composePath is the harness compose file relative to this test file.
const composePath = "../../deploy/compose/docker-compose.yml"

// service is the minimal shape of a compose service we navigate: only the four
// posture fields. Fields we do not assert on are left out so unrelated drift
// never fails this gate.
type service struct {
	CapDrop     []string `yaml:"cap_drop"`
	CapAdd      []string `yaml:"cap_add"`
	SecurityOpt []string `yaml:"security_opt"`
	ReadOnly    bool     `yaml:"read_only"`
	Tmpfs       []string `yaml:"tmpfs"`
	// Pid is the compose pid-namespace mode for the service. The empty string is
	// the compose default — a PRIVATE per-container PID namespace where the
	// process is PID 1 and exposes no foreign process table. "host" joins the
	// host PID namespace; "service:<name>"/"container:<name>" share another
	// container's. The hardened mount service must keep the private default.
	Pid string `yaml:"pid"`
}

// composeFile is the minimal shape of the compose document: the services map.
type composeFile struct {
	Services map[string]service `yaml:"services"`
}

func loadMountService(t *testing.T) service {
	t.Helper()
	raw, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read compose file: %v", err)
	}
	var doc composeFile
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse compose YAML: %v", err)
	}
	mount, ok := doc.Services["mount"]
	if !ok {
		t.Fatal("compose file has no services.mount entry")
	}
	return mount
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestMountAppArmorIsNarrowNotUnconfined pins lever 1: the mount service runs
// under the named ocu-mount AppArmor profile and is never unconfined.
func TestMountAppArmorIsNarrowNotUnconfined(t *testing.T) {
	mount := loadMountService(t)
	if !contains(mount.SecurityOpt, "apparmor=ocu-mount") {
		t.Errorf("security_opt %v: missing apparmor=ocu-mount (the narrow profile)", mount.SecurityOpt)
	}
	for _, opt := range mount.SecurityOpt {
		if opt == "apparmor=unconfined" || opt == "apparmor:unconfined" {
			t.Errorf("security_opt %v: mount must never run apparmor=unconfined", mount.SecurityOpt)
		}
	}
}

// TestMountCapabilitiesDropAllAddOnlySysAdmin pins lever 2: cap_drop is exactly
// [ALL] and cap_add grants back only the single CAP_SYS_ADMIN the FUSE
// mount/umount path needs — no second capability.
func TestMountCapabilitiesDropAllAddOnlySysAdmin(t *testing.T) {
	mount := loadMountService(t)
	if len(mount.CapDrop) != 1 || mount.CapDrop[0] != "ALL" {
		t.Errorf("cap_drop = %v, want exactly [ALL]", mount.CapDrop)
	}
	if len(mount.CapAdd) != 1 || mount.CapAdd[0] != "SYS_ADMIN" {
		t.Errorf("cap_add = %v, want exactly [SYS_ADMIN] (one capability)", mount.CapAdd)
	}
}

// TestMountNoNewPrivileges pins lever 3: privilege gain via execve is blocked.
func TestMountNoNewPrivileges(t *testing.T) {
	mount := loadMountService(t)
	if !contains(mount.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("security_opt %v: missing no-new-privileges:true", mount.SecurityOpt)
	}
}

// TestMountReadOnlyRootWithCacheTmpfs pins lever 4: the container root is
// read-only and the single writable surface is the rclone VFS cache tmpfs at
// /root/.cache.
func TestMountReadOnlyRootWithCacheTmpfs(t *testing.T) {
	mount := loadMountService(t)
	if !mount.ReadOnly {
		t.Error("read_only = false, want true (read-only container root)")
	}
	if !contains(mount.Tmpfs, "/root/.cache") {
		t.Errorf("tmpfs %v: missing /root/.cache (the VFS cache writable surface)", mount.Tmpfs)
	}
}

// TestMountKeepsPrivatePIDNamespace pins lever 5 (content): the mount service
// must run in its OWN private PID namespace, never the host's and never shared
// with another container. In compose that private namespace is the DEFAULT —
// expressed by the absence of any pid: key — so the pin asserts the mount
// carries no pid override. A "host" value would expose the host process table
// to the mount; a "service:"/"container:" value would couple its PID namespace
// to a peer. Either weakens the isolation, so any non-empty pid value goes RED.
//
// This pins the compose CONTENT. The kernel BINDING of the private PID
// namespace (the live mount process being PID 1 in a namespace of its own) is
// AMD64-bound and proven on the CI live-e2e runner, not on the arm64 dev host.
func TestMountKeepsPrivatePIDNamespace(t *testing.T) {
	mount := loadMountService(t)
	if mount.Pid != "" {
		t.Errorf("pid = %q, want \"\" (the compose default private PID namespace); the "+
			"mount must not join the host PID namespace or share a peer's", mount.Pid)
	}
}
