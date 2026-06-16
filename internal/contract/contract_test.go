// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package contract

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// schemaID is the vendored schema's own $id; the validator registers and
// compiles the schema root under it.
const schemaID = "https://schemas.open-computer-use.dev/storage/mount-config.schema.json"

// vendoredSchemaPath is the byte-identical vendored copy of the canonical schema.
const vendoredSchemaPath = "testdata/mount-config.schema.json"

func newValidator(t *testing.T) *GuestValidator {
	t.Helper()
	schemaBytes, err := os.ReadFile(vendoredSchemaPath)
	if err != nil {
		t.Fatalf("read vendored schema: %v", err)
	}
	v, err := NewGuestValidator(schemaBytes, schemaID)
	if err != nil {
		t.Fatalf("compile guest validator: %v", err)
	}
	return v
}

// TestSchemaConformance compiles the schema root once and checks that accept
// fixtures validate and reject fixtures fail. The accept set holds auth_token
// and ca_cert_pem (the guest holds the credential, so a credential-carrying
// config is the valid shape); the reject set carries documents that violate a
// structural rule (http service_url, both scope ids, absent ca_cert_pem).
func TestSchemaConformance(t *testing.T) {
	v := newValidator(t)

	run := func(t *testing.T, dir string, wantValid bool) {
		t.Helper()
		entries, err := os.ReadDir(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatalf("read %s fixtures: %v", dir, err)
		}
		seen := 0
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			seen++
			name := e.Name()
			t.Run(filepath.Join(dir, name), func(t *testing.T) {
				doc, err := os.ReadFile(filepath.Join("testdata", dir, name))
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				err = v.Validate(doc)
				if wantValid && err != nil {
					t.Fatalf("expected %s to validate against the schema, got: %v", name, err)
				}
				if !wantValid && err == nil {
					t.Fatalf("expected %s to FAIL the schema, but it validated", name)
				}
			})
		}
		if seen == 0 {
			t.Fatalf("no fixtures found in %s", dir)
		}
	}

	run(t, "accept", true)
	run(t, "reject", false)
}

// TestVendoredSchemaParity asserts the vendored schema is byte-identical to the
// canonical source via the parity script. The canon location comes only from
// the OCU_ARCH_REPO environment variable (the same variable the script reads);
// when it is unset or the checkout is absent, the test skips cleanly so the
// hermetic CI run stays green.
func TestVendoredSchemaParity(t *testing.T) {
	repoRoot := os.Getenv("OCU_ARCH_REPO")
	if repoRoot == "" {
		t.Skip("OCU_ARCH_REPO unset; skipping vendored-schema parity (hermetic run). Set it to the architecture repo checkout to enable.")
	}
	canonPath := filepath.Join(repoRoot, "contracts", "storage", "mount-config.schema.json")
	if _, err := os.Stat(canonPath); err != nil {
		t.Skipf("canonical schema source absent at %s; skipping parity (hermetic run)", canonPath)
	}

	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "check-contract-parity.sh"))
	if err != nil {
		t.Fatalf("resolve parity script path: %v", err)
	}
	cmd := exec.Command("bash", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("parity script failed: %v\n%s", err, out)
	}
}
