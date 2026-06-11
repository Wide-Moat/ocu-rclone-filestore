// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package contract compiles the guest-variant entry point of the vendored
// mount-config schema and validates documents against it.
//
// The vendored schema root is oneOf[GuestMountConfig, ProvisionMountConfig]. A
// document carrying a provision-side credential marker is a valid
// ProvisionMountConfig, so validating against the root would accept it. To make
// the guest's refusal observable, this package compiles and validates against
// the #/$defs/GuestMountConfig subschema entry point, never the root.
package contract

import (
	"bytes"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// guestEntryPoint is the JSON-pointer fragment for the guest-variant subschema.
const guestEntryPoint = "#/$defs/GuestMountConfig"

// GuestValidator validates documents against the GuestMountConfig subschema of a
// vendored mount-config schema.
type GuestValidator struct {
	schema *jsonschema.Schema
}

// NewGuestValidator compiles the GuestMountConfig entry point of the schema
// whose bytes are schemaBytes. schemaID must be the schema's own $id (the URL it
// is registered under); the guest subschema is then compiled at
// schemaID + "#/$defs/GuestMountConfig".
func NewGuestValidator(schemaBytes []byte, schemaID string) (*GuestValidator, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return nil, fmt.Errorf("parse vendored schema: %w", err)
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaID, doc); err != nil {
		return nil, fmt.Errorf("register vendored schema under %q: %w", schemaID, err)
	}

	sch, err := c.Compile(schemaID + guestEntryPoint)
	if err != nil {
		return nil, fmt.Errorf("compile guest entry point %q: %w", schemaID+guestEntryPoint, err)
	}
	return &GuestValidator{schema: sch}, nil
}

// Validate reports whether documentBytes is a valid GuestMountConfig. It returns
// a non-nil error when the document fails the guest subschema.
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
