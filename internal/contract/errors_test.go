// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package contract

import (
	"os"
	"strings"
	"testing"
)

// readVendoredSchema returns the byte-identical vendored schema, the same input
// the production path compiles. Reusing it keeps the failure-path tests honest:
// the only thing that varies between cases is the deliberate fault injected.
func readVendoredSchema(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(vendoredSchemaPath)
	if err != nil {
		t.Fatalf("read vendored schema: %v", err)
	}
	return b
}

// TestNewGuestValidatorMalformedSchema drives unparseable schema bytes through
// the constructor and asserts it surfaces the parse failure rather than
// returning a usable validator. A validator built from garbage would silently
// accept anything, so the constructor must refuse.
func TestNewGuestValidatorMalformedSchema(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
	}{
		{name: "truncated_object", bytes: []byte("{ this is not json")},
		{name: "trailing_garbage", bytes: []byte(`{"type":"object"} trailing`)},
		{name: "empty", bytes: []byte("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewGuestValidator(tc.bytes, schemaID)
			if err == nil {
				t.Fatalf("expected a parse error for malformed schema, got a validator: %#v", v)
			}
			if v != nil {
				t.Fatalf("expected nil validator on failure, got %#v", v)
			}
			if !strings.Contains(err.Error(), "parse vendored schema") {
				t.Fatalf("error should name the parse stage, got: %v", err)
			}
		})
	}
}

// TestNewGuestValidatorBadResourceID drives a schema ID that the compiler
// refuses to register. A meta-schema URL is already reserved inside the
// compiler, so registering the vendored document under it collides. The
// constructor must report the registration failure, not swallow it.
func TestNewGuestValidatorBadResourceID(t *testing.T) {
	// The draft 2020-12 meta-schema URL is pre-registered in the compiler.
	const metaSchemaID = "https://json-schema.org/draft/2020-12/schema"

	v, err := NewGuestValidator(readVendoredSchema(t), metaSchemaID)
	if err == nil {
		t.Fatalf("expected a registration error for a reserved schema id, got a validator: %#v", v)
	}
	if v != nil {
		t.Fatalf("expected nil validator on failure, got %#v", v)
	}
	if !strings.Contains(err.Error(), "register vendored schema under") {
		t.Fatalf("error should name the registration stage, got: %v", err)
	}
	if !strings.Contains(err.Error(), metaSchemaID) {
		t.Fatalf("error should quote the offending id, got: %v", err)
	}
}

// TestNewGuestValidatorUncompilableRoot registers a well-formed schema document
// whose root references a $def that does not exist. Parsing and registration
// both succeed, but the unresolvable $ref makes the root uncompilable, so the
// constructor must surface a compile-stage error rather than returning an inert
// validator.
func TestNewGuestValidatorUncompilableRoot(t *testing.T) {
	// A schema whose root $ref points at a missing definition.
	danglingRef := []byte(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id": "https://schemas.open-computer-use.dev/storage/mount-config.schema.json",
		"$ref": "#/$defs/DoesNotExist"
	}`)

	v, err := NewGuestValidator(danglingRef, schemaID)
	if err == nil {
		t.Fatalf("expected a compile error for an unresolvable root $ref, got a validator: %#v", v)
	}
	if v != nil {
		t.Fatalf("expected nil validator on failure, got %#v", v)
	}
	if !strings.Contains(err.Error(), "compile vendored schema") {
		t.Fatalf("error should name the compile stage, got: %v", err)
	}
}

// TestNewGuestValidatorRoundTrips builds the validator from the real vendored
// schema and confirms the constructed validator actually enforces the contract:
// the minimal config (holding auth_token and ca_cert_pem) validates and a
// structurally-invalid config (http service_url) is refused. This guards against
// a future change that returns a non-nil-but-inert validator.
func TestNewGuestValidatorRoundTrips(t *testing.T) {
	v := newValidator(t)

	ok, err := os.ReadFile("testdata/accept/guest_minimal.json")
	if err != nil {
		t.Fatalf("read accept fixture: %v", err)
	}
	if err := v.Validate(ok); err != nil {
		t.Fatalf("minimal config should validate, got: %v", err)
	}

	bad, err := os.ReadFile("testdata/reject/http_service_url.json")
	if err != nil {
		t.Fatalf("read reject fixture: %v", err)
	}
	if err := v.Validate(bad); err == nil {
		t.Fatal("a config with a non-https service_url must fail the schema")
	}
}

// TestValidateMalformedDocument feeds unparseable document bytes to a real
// validator. The parse failure must surface as an error naming the document
// stage; a guest must never treat an unparseable config as a passing document.
func TestValidateMalformedDocument(t *testing.T) {
	v := newValidator(t)

	cases := []struct {
		name  string
		bytes []byte
	}{
		{name: "unterminated_object", bytes: []byte("{nope")},
		{name: "trailing_garbage", bytes: []byte(`{} extra`)},
		{name: "empty", bytes: []byte("")},
		{name: "bare_word", bytes: []byte("notjson")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.bytes)
			if err == nil {
				t.Fatal("expected a parse error for a malformed document")
			}
			if !strings.Contains(err.Error(), "parse document") {
				t.Fatalf("error should name the document parse stage, got: %v", err)
			}
		})
	}
}

// TestValidateSchemaRejection confirms a syntactically valid document that
// violates the guest schema returns the schema-validation error verbatim (the
// validator does not wrap it), distinguishing it from the parse-stage errors
// above.
func TestValidateSchemaRejection(t *testing.T) {
	v := newValidator(t)

	// Parses cleanly as JSON but is not a valid mount config: missing every
	// required field.
	err := v.Validate([]byte(`{"unexpected":"document"}`))
	if err == nil {
		t.Fatal("expected the guest schema to reject an empty-shaped document")
	}
	if strings.Contains(err.Error(), "parse document") {
		t.Fatalf("a schema violation must not be reported as a parse failure, got: %v", err)
	}
}
