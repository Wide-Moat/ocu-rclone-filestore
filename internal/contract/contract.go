// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package contract compiles the vendored mount-config schema and validates
// documents against it.
//
// The schema is a single mount-config shape (one top-level object with a
// mounts array). This package compiles and validates against that root, so a
// document is accepted exactly when it conforms to the frozen contract.
package contract

import (
	"bytes"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// GuestValidator validates documents against the vendored mount-config schema.
type GuestValidator struct {
	schema *jsonschema.Schema
}

// NewGuestValidator compiles the schema whose bytes are schemaBytes. schemaID
// must be the schema's own $id (the URL it is registered under); the validator
// is compiled against that root.
func NewGuestValidator(schemaBytes []byte, schemaID string) (*GuestValidator, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return nil, fmt.Errorf("parse vendored schema: %w", err)
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaID, doc); err != nil {
		return nil, fmt.Errorf("register vendored schema under %q: %w", schemaID, err)
	}

	sch, err := c.Compile(schemaID)
	if err != nil {
		return nil, fmt.Errorf("compile vendored schema %q: %w", schemaID, err)
	}
	return &GuestValidator{schema: sch}, nil
}

// Validate reports whether documentBytes conforms to the mount-config schema.
// It returns a non-nil error when the document fails the schema.
func (v *GuestValidator) Validate(documentBytes []byte) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(documentBytes))
	if err != nil {
		return fmt.Errorf("parse document: %w", err)
	}
	if err := v.schema.Validate(doc); err != nil {
		return err
	}
	return nil
}
