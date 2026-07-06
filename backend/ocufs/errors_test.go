// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
)

// TestMapBrokerError pins the broker→fs sentinel translation: rclone recognises
// its own fs.Error* values, so a brokerrpc sentinel must map to the matching one
// (and be reachable through a fmt.Errorf %w wrap), while an unknown error and nil
// pass through unchanged.
func TestMapBrokerError(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error // nil means "returned unchanged"
	}{
		{"permission", brokerrpc.ErrPermissionDenied, fs.ErrorPermissionDenied},
		{"not found", brokerrpc.ErrNotFound, fs.ErrorObjectNotFound},
		{"wrapped permission", fmt.Errorf("op: %w", brokerrpc.ErrPermissionDenied), fs.ErrorPermissionDenied},
		{"unknown passthrough", brokerrpc.ErrAlreadyExists, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapBrokerError(c.in)
			if c.want == nil {
				if !errors.Is(got, c.in) {
					t.Errorf("unknown error should pass through: got %v, want %v", got, c.in)
				}
				return
			}
			if !errors.Is(got, c.want) {
				t.Errorf("mapBrokerError(%v) = %v, want it to match %v", c.in, got, c.want)
			}
		})
	}

	if mapBrokerError(nil) != nil {
		t.Error("mapBrokerError(nil) must be nil")
	}
}
