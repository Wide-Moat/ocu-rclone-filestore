// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"errors"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs"
)

// mapBrokerError translates a brokerrpc sentinel into the corresponding rclone
// fs sentinel so callers up the stack (rclone's VFS and retry layers) can
// recognise it. Wrapping a brokerrpc error with fmt.Errorf preserves it for
// errors.Is against brokerrpc's own sentinels, but rclone tests errors against
// its OWN fs.Error* values by identity/Is, so a raw brokerrpc error read as an
// opaque failure would defeat rclone's permission and not-found handling.
//
// A nil error maps to nil. An error that matches no known sentinel is returned
// unchanged so the underlying cause is never hidden.
func mapBrokerError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, brokerrpc.ErrPermissionDenied):
		return fs.ErrorPermissionDenied
	case errors.Is(err, brokerrpc.ErrNotFound):
		return fs.ErrorObjectNotFound
	default:
		return err
	}
}
