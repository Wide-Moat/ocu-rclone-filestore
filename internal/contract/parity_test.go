// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// TestLoaderSchemaParity feeds every config fixture — this package's
// accept/reject sets and the loader's own testdata — through both
// mountcfg.Load (the enforcement point in the binary) and the single-shape
// schema-root validator (the frozen contract) and asserts the two reach the
// same accept/reject verdict on every document.
//
// The two halves of config validation must provably agree: a document the
// schema rejects but the loader accepts is a contract divergence in the
// binary, and the reverse silently narrows the contract. Reject fixtures are
// expected to fail both for their own (possibly different) stated reasons;
// only the verdicts must match.
func TestLoaderSchemaParity(t *testing.T) {
	v := newValidator(t)

	dirs := []struct {
		dir string
		// wantAccept gives the expected shared verdict for a fixture name, so
		// the test also fails when both halves drift together.
		wantAccept func(name string) bool
	}{
		{
			dir:        filepath.Join("testdata", "accept"),
			wantAccept: func(string) bool { return true },
		},
		{
			dir:        filepath.Join("testdata", "reject"),
			wantAccept: func(string) bool { return false },
		},
		{
			dir: filepath.Join("..", "mountcfg", "testdata"),
			wantAccept: func(name string) bool {
				return strings.HasPrefix(name, "valid_")
			},
		},
	}

	seen := 0
	for _, d := range dirs {
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			t.Fatalf("read fixture dir %s: %v", d.dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			seen++
			name := e.Name()
			path := filepath.Join(d.dir, name)
			t.Run(path, func(t *testing.T) {
				doc, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}

				schemaErr := v.Validate(doc)
				_, loaderErr := mountcfg.Load(path)

				schemaAccepts := schemaErr == nil
				loaderAccepts := loaderErr == nil
				if schemaAccepts != loaderAccepts {
					t.Fatalf("loader/schema divergence on %s:\n  loader: accepts=%t err=%v\n  schema: accepts=%t err=%v",
						path, loaderAccepts, loaderErr, schemaAccepts, schemaErr)
				}
				if want := d.wantAccept(name); loaderAccepts != want {
					t.Fatalf("both halves agree on %s but the shared verdict is wrong: got accepts=%t, want accepts=%t (loader err=%v, schema err=%v)",
						path, loaderAccepts, want, loaderErr, schemaErr)
				}
			})
		}
	}
	if seen == 0 {
		t.Fatal("no fixtures found for the parity sweep")
	}
}
