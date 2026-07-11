// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Deliberately untagged, like teardown.go itself: the deploy-invariant tests
// below must run on every development platform, not only the mount-capable
// legs, so a compose-grace regression reds locally rather than first in CI.

package mounter

import (
	"fmt"
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestWritebackDrainCoversThrottleBackoffWindow pins F-34: the teardown drain
// bound must cover the broker-throttle write-back backoff window (SEC-46).
// rclone's write-back retry ladder under a 429 window runs 5/10/20/40s rungs,
// so a throttled dirty item routinely sits ~75s before its next upload
// attempt; the repo's own live-proven settle budget for a throttled burst is
// 120s (test/e2e exercise, SC2 step). A drain bound below that window makes a
// clean-looking SIGTERM (exit 0) silently discard the most recent writes —
// the VFS cache lives on a tmpfs that dies with the container.
func TestWritebackDrainCoversThrottleBackoffWindow(t *testing.T) {
	const throttleSettleWindow = 120 * time.Second
	if writebackDrainTimeout < throttleSettleWindow {
		t.Fatalf("writebackDrainTimeout = %v; want >= %v — the throttle write-back backoff ladder (5+10+20+40s rungs plus an in-flight upload) outlives a shorter drain, and SIGTERM then discards dirty cache on a clean-looking exit", writebackDrainTimeout, throttleSettleWindow)
	}
}

// TestComposeStopGraceCoversTeardownBudget is the two-sided deploy guard for
// F-34: the drain bound is decorative unless the container runtime lets the
// process live that long — without stop_grace_period the compose default
// (10s) SIGKILLs the mount mid-drain. Both shipped mount services must carry
// a stop_grace_period covering drain + detach grace, asserted against the
// REAL consts so raising the drain without the grace (or deleting the grace)
// reds this test.
func TestComposeStopGraceCoversTeardownBudget(t *testing.T) {
	needed := writebackDrainTimeout + unmountDetachGrace
	cases := []struct {
		file    string
		service string
	}{
		{"../../deploy/compose/docker-compose.ocu-rclone-mount.fragment.yml", "ocu-rclone-mount"},
		{"../../deploy/compose/docker-compose.yml", "mount"},
	}
	for _, tc := range cases {
		raw, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", tc.file, err)
		}
		services, _ := doc["services"].(map[string]any)
		svc, _ := services[tc.service].(map[string]any)
		if svc == nil {
			t.Fatalf("%s: service %q not found", tc.file, tc.service)
		}
		sgRaw, ok := svc["stop_grace_period"]
		if !ok {
			t.Fatalf("%s: service %q carries no stop_grace_period — the runtime default (10s) SIGKILLs the mount mid-drain; teardown needs >= %v", tc.file, tc.service, needed)
		}
		sg, err := time.ParseDuration(fmt.Sprintf("%v", sgRaw))
		if err != nil {
			t.Fatalf("%s: service %q stop_grace_period %v does not parse as a duration: %v", tc.file, tc.service, sgRaw, err)
		}
		if sg < needed {
			t.Fatalf("%s: service %q stop_grace_period = %v; want >= drain (%v) + detach grace (%v)", tc.file, tc.service, sg, writebackDrainTimeout, unmountDetachGrace)
		}
	}
}
