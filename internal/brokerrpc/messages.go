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

// FilesystemFile is a file entry in the context of a named filesystem. It is a
// SEPARATE wire message from File per the contract (D6 lists File and
// FilesystemFile as distinct response bodies), so the two are intentionally NOT
// aliased even though their fields currently coincide: a later field pin per D6
// may add a field to only one of them, and an alias would silently couple them.
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

// MoveDirectoryRequest is the request for the moveDirectory op. The endpoints
// are the bare source/destination fields (not source_path/destination_path).
type MoveDirectoryRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Source                string                `json:"source"`
	Destination           string                `json:"destination"`
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

// CopyFileRequest is the request for the copyFile op. The endpoints are the
// bare source/destination fields. OverwriteExisting selects whether an
// existing destination is replaced (true) or the op fails on a present
// destination (false); the mount sends true because the operations layer has
// already decided the copy should proceed by the time it reaches the backend.
type CopyFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Source                string                `json:"source"`
	Destination           string                `json:"destination"`
	OverwriteExisting     bool                  `json:"overwrite_existing"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// MoveFileRequest is the request for the moveFile op. The endpoints are the
// bare source/destination fields. OverwriteExisting selects whether an
// existing destination is replaced (true) or the op fails on a present
// destination (false); the mount sends true because a rename over an existing
// path replaces it under filesystem semantics.
type MoveFileRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Source                string                `json:"source"`
	Destination           string                `json:"destination"`
	OverwriteExisting     bool                  `json:"overwrite_existing"`
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
// op (uuid-axis). Range is the optional {offset, length} window: when it is
// the zero value (omitted on the wire) the broker streams the whole object;
// when set, the broker streams only that window. A ranged read therefore
// transfers just the requested bytes rather than the full object. *Range is a
// pointer with omitempty so a full Download serialises no range field at all,
// keeping that request body byte-identical to the no-range form.
type FileDownloadRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	UUID                  string                `json:"uuid"`
	Range                 *Range                `json:"range,omitempty"`
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

// ListDirEntry is the pinned listDirectory union entry (D6, Phase 3).
// Each entry is either a file (the `file` key, carrying a full FilesystemFile
// with uuid+size+mime+mtime) XOR a directory (the `directory` key, carrying
// path+mtime). The union discriminator is the presence of one key or the
// other; only one arm will be non-nil after decoding. Decoded tolerantly
// (no DisallowUnknownFields) so future broker field pins per D6 do not break
// existing decoders. The guest never derives scope from the uuid (D7).
type ListDirEntry struct {
	File      *FilesystemFile `json:"file,omitempty"`
	Directory *Directory      `json:"directory,omitempty"`
}

// ListDirectoryResponse wraps the directory listing result for a single page.
// Cursor is the opaque continuation token: when it is non-empty the broker has
// more entries and this response is only page 1 — callers that need the
// complete listing must use ListDirectoryAll. Exposing the field makes silent
// truncation detectable instead of presenting page 1 as the whole listing.
// Entries is the pinned union []ListDirEntry (raised from the Phase-2
// dir-only []Directory in Phase 3; the decoder corrects the response shape
// without adding any new transport/op/auth path — SEC-25).
type ListDirectoryResponse struct {
	Entries []ListDirEntry `json:"entries,omitempty"`
	Cursor  OpaqueCursor   `json:"cursor,omitempty"`
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

// ReadFileResponse is the unary readFile result. It is METADATA-ONLY as shipped:
// File carries no content/data field, so this type cannot return file bytes —
// the content body is a TBD per D6 and is never invented here. Bulk content is
// delivered by the server-streaming fileDownload op (download.go), not by this
// unary op. When a content body is pinned in the contract it will be added here;
// until then a broker that returns a content field has it silently dropped by
// the tolerant decoder. The Range field on the request selects within that
// (currently absent) content body; a zero-value Range relies on the broker
// reading length 0 as "full file".
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

// FileUploadResponse is the optional response message frame (data flag 0x00)
// the broker MAY emit before the EndStreamResponse trailer on a completed
// fileUpload stream — the standard Connect client-streaming success shape. The
// upload reader tolerates its presence or absence; the trailer carries the
// authoritative success verdict (D5). It carries the assembled object's
// metadata as a FilesystemFile (D6).
type FileUploadResponse struct {
	File FilesystemFile `json:"file"`
}

// Note: fileDownload content frames carry {"data": <base64 bytes>}
// (downloadContentFrame in download.go), per D5 — NOT a {"file": ...} unary
// body. There is no separate per-frame download response type; the
// FilesystemFile-bearing metadata, when present, rides the trailer/metadata
// per D6.

// ImportFilesResponse is the bare-ack response for importFiles.
type ImportFilesResponse = AckResponse

// ImportZipResponse is the bare-ack response for importZip.
type ImportZipResponse = AckResponse

// MigrateFilesystemResponse is the bare-ack response for migrateFilesystem.
type MigrateFilesystemResponse = AckResponse

// RemoveFilesystemResponse is the bare-ack response for removeFilesystem.
type RemoveFilesystemResponse = AckResponse
