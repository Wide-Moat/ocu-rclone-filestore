// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"context"
	"io"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
)

// brokerClient is the interface the Fs holds for all broker RPC calls. It is
// the seam a test double can implement without touching the real transport.
//
// Every method signature matches the corresponding method on *brokerrpc.Client
// exactly. ListDirectoryAll returns the pinned union []ListDirEntry (D6, raised
// in Phase 3 from the prior dir-only []Directory — a response-decoder
// correction, no new transport/op/auth path, SEC-25).
//
// The backend never constructs AuthorizationMetadata and never sets
// downloadable; those concerns are handled centrally inside brokerrpc (SEC-25,
// SEC-73). This interface exposes only the typed operation methods.
type brokerClient interface {
	// Listing and metadata. ListDirectoryStream yields entries page-by-page so
	// List can filter to depth-1 without buffering the full recursive tree;
	// ListDirectoryAll is the buffering wrapper kept for callers that want a slice.
	ListDirectoryStream(ctx context.Context, path string, yield func(brokerrpc.ListDirEntry) error) error
	ListDirectoryAll(ctx context.Context, path string) ([]brokerrpc.ListDirEntry, error)
	ReadMetadata(ctx context.Context, path string) (*brokerrpc.ReadMetadataResponse, error)

	// Content delivery (uuid-axis, D7). Both return a streaming reader the
	// caller must Close; the backend never buffers the whole object in memory.
	Download(ctx context.Context, uuid string) (io.ReadCloser, error)
	DownloadRange(ctx context.Context, uuid string, offset, length int64) (io.ReadCloser, error)

	// Mutating file ops.
	Upload(ctx context.Context, path string, src io.Reader, totalBytes int64, overwrite bool) error
	CopyFile(ctx context.Context, sourcePath, destinationPath string) (*brokerrpc.AckResponse, error)
	MoveFile(ctx context.Context, sourcePath, destinationPath string) (*brokerrpc.AckResponse, error)
	RemoveFile(ctx context.Context, path string) (*brokerrpc.AckResponse, error)

	// Mutating directory ops.
	MakeDirectory(ctx context.Context, path string) (*brokerrpc.AckResponse, error)
	RemoveDirectory(ctx context.Context, path string) (*brokerrpc.AckResponse, error)
	MoveDirectory(ctx context.Context, sourcePath, destinationPath string) (*brokerrpc.AckResponse, error)
}

// *brokerrpc.Client satisfies brokerClient directly — every method matches — so
// no forwarding adapter is needed; the Fs holds the Client through this
// interface seam. This assertion fails to compile if the two drift.
var _ brokerClient = (*brokerrpc.Client)(nil)
