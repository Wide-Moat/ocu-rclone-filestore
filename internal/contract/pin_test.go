// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// vendoredSchemaPinPath is the committed sha256 pin for the vendored schema,
// in standard checksum-file format: "<64-hex>  mount-config.schema.json".
const vendoredSchemaPinPath = vendoredSchemaPath + ".sha256"

// TestVendoredSchemaChecksumPin asserts the vendored mount-config schema's
// sha256 matches the committed pin file. It is hermetic — no environment, no
// network, and it never skips — so it enforces the pin under the ordinary
// required test gate from the moment it lands.
//
// Scope of the claim: this proves schema<->pin CONSISTENCY only. It is
// tamper-evidence that turns silent drift of the vendored contract into a
// conspicuous multi-file diff; it does not by itself prove the pinned bytes
// are canon. The canon-ref leg of scripts/check-contract-parity.sh binds the
// same bytes to the public canon commit recorded in testdata/CANON-REF.
func TestVendoredSchemaChecksumPin(t *testing.T) {
	pinBytes, err := os.ReadFile(vendoredSchemaPinPath)
	if err != nil {
		t.Fatalf("read checksum pin: %v", err)
	}
	fields := strings.Fields(string(pinBytes))
	if len(fields) != 2 || len(fields[0]) != 64 || fields[1] != "mount-config.schema.json" {
		t.Fatalf("checksum pin malformed: want %q, got %q",
			"<64-hex>  mount-config.schema.json", strings.TrimSpace(string(pinBytes)))
	}
	want := strings.ToLower(fields[0])

	schemaBytes, err := os.ReadFile(vendoredSchemaPath)
	if err != nil {
		t.Fatalf("read vendored schema: %v", err)
	}
	sum := sha256.Sum256(schemaBytes)
	got := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("vendored schema sha256 %s does not match the committed pin %s.\n"+
			"If the frozen contract was deliberately refreshed from canon, re-record "+
			"the pin file and testdata/CANON-REF in the same commit, stating the "+
			"canon commit the new copy is blessed against. Any other cause is drift.",
			got, want)
	}
}
