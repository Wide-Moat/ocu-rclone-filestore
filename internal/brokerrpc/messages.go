// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

// AuthorizationMetadata is stamped on every request. It carries the op-derived
// intent and the downloadable flag (always false; the perimeter-exit decision
// is broker-resolved per SEC-73). filesystem_id is a top-level request field
// and is NOT carried inside AuthorizationMetadata (divergence D3).
type AuthorizationMetadata struct {
	Intent       string `json:"intent"`
	Downloadable bool   `json:"downloadable"`
}

// File represents a file entry in a response. Decoded tolerantly: unknown
// fields are silently ignored so a later field-pin per D6 does not break
// existing decoders. Tags are opaque, non-authorizing carriers.
type File struct {
	Path  string `json:"path,omitempty"`
	Size  int64  `json:"size,omitempty"`
	Mtime string `json:"mtime,omitempty"`
	Mode  string `json:"mode,omitempty"`
	SHA   string `json:"sha,omitempty"`
	MIME  string `json:"mime,omitempty"`
	UUID  string `json:"uuid,omitempty"`
}

// FilesystemFile is a file entry in the context of a named filesystem.
// Decoded tolerantly (same rationale as File).
type FilesystemFile struct {
	Path  string `json:"path,omitempty"`
	Size  int64  `json:"size,omitempty"`
	Mtime string `json:"mtime,omitempty"`
	Mode  string `json:"mode,omitempty"`
	SHA   string `json:"sha,omitempty"`
	MIME  string `json:"mime,omitempty"`
	UUID  string `json:"uuid,omitempty"`
}

// Directory represents a directory entry in a response. Decoded tolerantly.
type Directory struct {
	Path  string `json:"path,omitempty"`
	Mode  string `json:"mode,omitempty"`
	Mtime string `json:"mtime,omitempty"`
}

// Range specifies a byte range for a readFile request.
type Range struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// AckResponse is the bare-ack response for ops that return an empty body {}.
// Decoded tolerantly — any future fields added by the broker are ignored.
type AckResponse struct{}

// ---------------------------------------------------------------------------
// Per-op request types
// ---------------------------------------------------------------------------
// Every path-scoped request carries filesystem_id at the top level.
// uuid-axis ops (getFileMetadata, fileDownload, listFiles) address by UUID.
// No request carries a metadata_retention_days field (D6 reject).
// ---------------------------------------------------------------------------

// ListDirectoryRequest is the request for the listDirectory op.
type ListDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// MakeDirectoryRequest is the request for the makeDirectory op.
type MakeDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// MoveDirectoryRequest is the request for the moveDirectory op.
type MoveDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	SourcePath            string                `json:"source_path"`
	DestinationPath       string                `json:"destination_path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// RemoveDirectoryRequest is the request for the removeDirectory op.
type RemoveDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// CreateFileRequest is the request for the createFile op.
type CreateFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// ReadFileRequest is the request for the readFile op. It carries an optional
// Range for partial reads; when Range is the zero value the broker returns
// the full file. readFile is a unary op; the reassembly logic for chunked
// delivery is in a later phase.
type ReadFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	Range                 Range                 `json:"range"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// ReadMetadataRequest is the request for the readMetadata op.
type ReadMetadataRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// GetFileMetadataRequest is the request for the getFileMetadata op.
// Addresses by broker-minted UUID handle (D7). The guest never derives
// scope from the UUID.
type GetFileMetadataRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	UUID                  string                `json:"uuid"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// ListFilesRequest is the request for the listFiles op (uuid-axis).
type ListFilesRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	UUID                  string                `json:"uuid"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// CopyFileRequest is the request for the copyFile op.
type CopyFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	SourcePath            string                `json:"source_path"`
	DestinationPath       string                `json:"destination_path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// MoveFileRequest is the request for the moveFile op.
type MoveFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	SourcePath            string                `json:"source_path"`
	DestinationPath       string                `json:"destination_path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// RemoveFileRequest is the request for the removeFile op.
type RemoveFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// FileUploadRequest is the params frame for the fileUpload client-streaming
// op. The streaming transport (frame envelope, chunk frames, half-close) is
// wired in a later phase; the type is defined here for use in that phase.
type FileUploadRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	DeclaredSizeBytes     int64                 `json:"declared_size_bytes"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// FileDownloadRequest is the request for the fileDownload server-streaming
// op (uuid-axis). The streaming transport is wired in a later phase.
type FileDownloadRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	UUID                  string                `json:"uuid"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// ImportFilesRequest is the request for the importFiles op.
type ImportFilesRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// ImportZipRequest is the request for the importZip op.
type ImportZipRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// MigrateFilesystemRequest is the request for the migrateFilesystem op.
type MigrateFilesystemRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// RemoveFilesystemRequest is the request for the removeFilesystem op.
type RemoveFilesystemRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// ---------------------------------------------------------------------------
// Per-op response types
// ---------------------------------------------------------------------------
// Decoded tolerantly (no DisallowUnknownFields) so future broker field pins
// per D6 do not break existing decoders.
// ---------------------------------------------------------------------------

// ListDirectoryResponse wraps the directory listing result for a single page.
// Cursor is the opaque continuation token: when it is non-empty the broker has
// more entries and this response is only page 1 — callers that need the
// complete listing must use ListDirectoryAll. Exposing the field makes silent
// truncation detectable instead of presenting page 1 as the whole listing.
type ListDirectoryResponse struct {
	Entries []Directory  `json:"entries,omitempty"`
	Cursor  OpaqueCursor `json:"cursor,omitempty"`
}

// MakeDirectoryResponse is the bare-ack response for makeDirectory.
type MakeDirectoryResponse = AckResponse

// MoveDirectoryResponse is the bare-ack response for moveDirectory.
type MoveDirectoryResponse = AckResponse

// RemoveDirectoryResponse is the bare-ack response for removeDirectory.
type RemoveDirectoryResponse = AckResponse

// CreateFileResponse wraps the newly created file.
type CreateFileResponse struct {
	File FilesystemFile `json:"file"`
}

// ReadFileResponse wraps the file content for a unary readFile result. Full
// reassembly for chunked delivery is in a later phase.
type ReadFileResponse struct {
	File File `json:"file"`
}

// ReadMetadataResponse returns both a file and a directory (one may be empty
// depending on what path resolves to).
type ReadMetadataResponse struct {
	File      File      `json:"file"`
	Directory Directory `json:"directory"`
}

// GetFileMetadataResponse wraps the file metadata for a uuid-addressed lookup.
type GetFileMetadataResponse struct {
	File FilesystemFile `json:"file"`
}

// ListFilesResponse wraps the list of files returned for a uuid-axis listing
// page. AfterUUID is the opaque continuation token: when it is non-empty the
// broker has more files and this response is only page 1 — callers that need
// the complete listing must use ListFilesAll. Exposing the field makes silent
// truncation detectable.
type ListFilesResponse struct {
	Files     []FilesystemFile `json:"files,omitempty"`
	AfterUUID OpaqueCursor     `json:"after_uuid,omitempty"`
}

// CopyFileResponse is the bare-ack response for copyFile.
type CopyFileResponse = AckResponse

// MoveFileResponse is the bare-ack response for moveFile.
type MoveFileResponse = AckResponse

// RemoveFileResponse is the bare-ack response for removeFile.
type RemoveFileResponse = AckResponse

// FileUploadResponse is the final response after a completed fileUpload stream.
type FileUploadResponse struct {
	File FilesystemFile `json:"file"`
}

// FileDownloadResponse is the per-frame payload for a fileDownload stream.
// The streaming frame envelope is wired in a later phase.
type FileDownloadResponse struct {
	File File `json:"file"`
}

// ImportFilesResponse is the bare-ack response for importFiles.
type ImportFilesResponse = AckResponse

// ImportZipResponse is the bare-ack response for importZip.
type ImportZipResponse = AckResponse

// MigrateFilesystemResponse is the bare-ack response for migrateFilesystem.
type MigrateFilesystemResponse = AckResponse

// RemoveFilesystemResponse is the bare-ack response for removeFilesystem.
type RemoveFilesystemResponse = AckResponse
