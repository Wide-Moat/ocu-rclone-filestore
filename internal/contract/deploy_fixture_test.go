// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package contract

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeployFixtureValidatesAgainstCanon proves the shipped deploy fixture is
// provably the canon mount-config shape: it validates against the vendored
// schema root, not merely the binary's own loader. Together with the loader
// check in package mountcfg, this pins the fixture to both halves of config
// validation.
func TestDeployFixtureValidatesAgainstCanon(t *testing.T) {
	v := newValidator(t)
	path := filepath.Join("..", "..", "deploy", "compose", "fixtures", "guest-config.json")
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read deploy fixture: %v", err)
	}
	if err := v.Validate(doc); err != nil {
		t.Fatalf("deploy fixture must validate against the canon schema root, got %v", err)
	}
}
