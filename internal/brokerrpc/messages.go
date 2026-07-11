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

// Range is the {offset, length} byte window carried (optionally) by a
// FileDownloadRequest: the sourced nested-range shape for a partial read.
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
// Every path-scoped request carries filesystem_id at the top level. The one
// uuid-axis request implemented here (fileDownload) addresses by broker-minted
// UUID. Ops whose bodies are TBD at the frozen contract have no request type
// in this file — only their operation NAMES are pinned (intent.go); a TBD body
// is never invented.
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

// ReadMetadataRequest is the request for the readMetadata op.
type ReadMetadataRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
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

// FileUploadRequest is the params field for the fileUpload op. It is carried as
// the JSON "params" field of a multipart/form-data POST alongside the streamed
// file part (see upload.go).
type FileUploadRequest struct {
	FilesystemID          string                `json:"filesystem_id"`
	Path                  string                `json:"path"`
	DeclaredSizeBytes     int64                 `json:"declared_size_bytes"`
	AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
}

// FileDownloadRequest is the request for the fileDownload op (uuid-axis), whose
// response is a chunked octet-stream (see download.go). Range is the optional
// {offset, length} window: when it is
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

// ReadMetadataResponse returns both a file and a directory (one may be empty
// depending on what path resolves to).
type ReadMetadataResponse struct {
	File      File      `json:"file"`
	Directory Directory `json:"directory"`
}

// Note: a fileDownload 2xx delivers the object bytes directly as a chunked
// octet-stream body — there is no per-chunk JSON envelope. The
// FilesystemFile-bearing metadata, when needed, is fetched via the metadata
// ops, not the download body. A fileUpload 2xx body is likewise never decoded:
// success is the HTTP status, the response body is TBD at the frozen contract,
// and the transport reads it only as a bounded diagnostics prefix (upload.go).
