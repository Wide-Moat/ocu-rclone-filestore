// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package posture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPostureLayersBindToDeclaredConstants pins F-59: the posture facts this
// package declares once (Home, CacheTmpfs) are hand-synced into four deploy
// layers outside the binary — the Dockerfile's ENV HOME, both compose files'
// tmpfs declarations, and the AppArmor profile's write grants. Each leg below
// asserts one layer against the REAL constants, so a posture change (a
// non-root runtime user, a relocated tmpfs) that misses a layer goes red at
// test time instead of surfacing at live bringup as a silent cache degrade or
// an AppArmor denial. Each layer is a subtest so a mutation of the constants
// must red every leg individually — a leg that stays green under a constant
// change is vacuous.
func TestPostureLayersBindToDeclaredConstants(t *testing.T) {
	t.Run("dockerfile_env_home", func(t *testing.T) {
		raw := readRepoFile(t, "Dockerfile")
		want := "ENV HOME=" + Home
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == want {
				return
			}
		}
		t.Fatalf("Dockerfile carries no %q line: the image-level half of the cache-dir invariant no longer matches posture.Home — the global cache-dir default would resolve off the writable tmpfs", want)
	})

	// Both shipped compose services must mount the writable tmpfs at
	// CacheTmpfs. In docker-compose.yml the mount service takes the posture
	// wholesale from the x-mount-posture anchor via a merge key; yaml.v3
	// resolves the merge on decode, so the tmpfs list is visible on the
	// service map exactly like the fragment's directly-declared one.
	for _, tc := range []struct {
		file    string
		service string
	}{
		{"deploy/compose/docker-compose.yml", "mount"},
		{"deploy/compose/docker-compose.ocu-rclone-mount.fragment.yml", "ocu-rclone-mount"},
	} {
		t.Run("compose_tmpfs_"+tc.service, func(t *testing.T) {
			raw := readRepoFile(t, tc.file)
			var doc map[string]any
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("parse %s: %v", tc.file, err)
			}
			services, _ := doc["services"].(map[string]any)
			svc, _ := services[tc.service].(map[string]any)
			if svc == nil {
				t.Fatalf("%s: service %q not found", tc.file, tc.service)
			}
			tmpfsList, ok := svc["tmpfs"].([]any)
			if !ok {
				t.Fatalf("%s: service %q declares no tmpfs list — the hardened posture's single writable surface is gone (or the posture anchor no longer merges onto the service)", tc.file, tc.service)
			}
			for _, entry := range tmpfsList {
				if fmt.Sprintf("%v", entry) == CacheTmpfs {
					return
				}
			}
			t.Fatalf("%s: service %q tmpfs list %v does not mount posture.CacheTmpfs (%q) — the VFS cache would land on the read-only rootfs and silently disable (SEC-46)", tc.file, tc.service, tmpfsList, CacheTmpfs)
		})
	}

	t.Run("apparmor_write_grants", func(t *testing.T) {
		raw := readRepoFile(t, "deploy/compose/apparmor/ocu-mount.profile")
		// The profile must grant writes on the cache tmpfs dir and its subtree;
		// a relocated tmpfs the profile still denies would pass the compose leg
		// and then fail at runtime with an AppArmor denial. Plain-text scan on
		// the grant lines — no profile parser.
		wantDir := CacheTmpfs + "/ rw,"
		wantTree := CacheTmpfs + "/** rwk,"
		var haveDir, haveTree bool
		for _, line := range strings.Split(string(raw), "\n") {
			switch strings.TrimSpace(line) {
			case wantDir:
				haveDir = true
			case wantTree:
				haveTree = true
			}
		}
		if !haveDir || !haveTree {
			t.Fatalf("AppArmor profile is missing the cache-tmpfs write grants %q / %q for posture.CacheTmpfs — the mount process could not create its VFS cache under the declared tmpfs", wantDir, wantTree)
		}
	})
}

// readRepoFile reads a file by repo-root-relative path from this package's
// directory, matching how the compose-grace invariant test locates the deploy
// files.
func readRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", filepath.FromSlash(rel))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return raw
}
