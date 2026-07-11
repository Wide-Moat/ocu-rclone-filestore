// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"os"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// TestBuildSpecsRejectsNestedDestinations pins the ancestry precondition of
// the shadow guard (F-31/F-32): a destination nested under another mount's
// destination would make the later mount's pre-mount walk traverse the
// earlier LIVE FUSE mount — reading broker content and refusing bringup on
// any real session file. Sibling destinations stay legal.
func TestBuildSpecsRejectsNestedDestinations(t *testing.T) {
	for _, order := range [][2]string{
		{"/mnt/user-data", "/mnt/user-data/outputs"},
		{"/mnt/user-data/outputs", "/mnt/user-data"},
	} {
		o := &orchestrator{
			seam:       newFake(),
			readiness:  ReadinessConfig{},
			signals:    make(chan os.Signal, 1),
			serviceURL: "https://broker.example",
			caCertPEM:  "pem",
		}
		cfg := &mountcfg.Config{
			Mounts: []mountcfg.Mount{writableEntry(order[0]), writableEntry(order[1])},
		}
		specs, err := o.buildSpecs(cfg)
		if err == nil {
			t.Fatalf("buildSpecs accepted nested destinations %q under %q (returned %d specs); want a hard error before any point starts", order[1], order[0], len(specs))
		}
		if !strings.Contains(err.Error(), order[0]) || !strings.Contains(err.Error(), order[1]) {
			t.Errorf("error %q does not name both nested destinations", err.Error())
		}
	}

	// Siblings sharing a parent must still pass buildSpecs (the run may then
	// proceed to mount them; only the spec-validation stage is under test).
	o := &orchestrator{
		seam:       newFake(),
		readiness:  ReadinessConfig{},
		signals:    make(chan os.Signal, 1),
		serviceURL: "https://broker.example",
		caCertPEM:  "pem",
	}
	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/user-data/outputs"), writableEntry("/mnt/user-data/uploads")},
	}
	specs, err := o.buildSpecs(cfg)
	if err != nil {
		t.Fatalf("buildSpecs rejected sibling destinations: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("buildSpecs = %d specs for two sibling destinations; want 2", len(specs))
	}
}
