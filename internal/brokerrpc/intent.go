// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import "fmt"

// Op identifies one of the 18 file-operations service methods under the
// ocu.filestore.v1alpha namespace.
type Op string

// The 18 op constants. Names match the camelCase method names used in the
// Connect-RPC route path (/ocu.filestore.v1alpha.FilesystemService/<Op>).
const (
	// Read-class ops: intent resolves to "read".
	OpListDirectory   Op = "listDirectory"
	OpReadFile        Op = "readFile"
	OpReadMetadata    Op = "readMetadata"
	OpGetFileMetadata Op = "getFileMetadata"
	OpListFiles       Op = "listFiles"
	OpFileDownload    Op = "fileDownload"

	// Write/mutate-class ops: intent resolves to "write".
	OpMakeDirectory     Op = "makeDirectory"
	OpMoveDirectory     Op = "moveDirectory"
	OpRemoveDirectory   Op = "removeDirectory"
	OpCreateFile        Op = "createFile"
	OpCopyFile          Op = "copyFile"
	OpMoveFile          Op = "moveFile"
	OpRemoveFile        Op = "removeFile"
	OpFileUpload        Op = "fileUpload"
	OpImportFiles       Op = "importFiles"
	OpImportZip         Op = "importZip"
	OpMigrateFilesystem Op = "migrateFilesystem"
	OpRemoveFilesystem  Op = "removeFilesystem"
)

// opIntentTable is the single authoritative mapping from op to its intent
// string. The "preview" intent exists in the service vocabulary but the mount
// never requests it (SEC-73 / threat T-02-01).
var opIntentTable = map[Op]string{
	// Read-class: the guest needs only read access for these ops.
	OpListDirectory:   "read",
	OpReadFile:        "read",
	OpReadMetadata:    "read",
	OpGetFileMetadata: "read",
	OpListFiles:       "read",
	OpFileDownload:    "read",

	// Write/mutate-class: the guest requests write access for these ops.
	OpMakeDirectory:     "write",
	OpMoveDirectory:     "write",
	OpRemoveDirectory:   "write",
	OpCreateFile:        "write",
	OpCopyFile:          "write",
	OpMoveFile:          "write",
	OpRemoveFile:        "write",
	OpFileUpload:        "write",
	OpImportFiles:       "write",
	OpImportZip:         "write",
	OpMigrateFilesystem: "write",
	OpRemoveFilesystem:  "write",
}

// IntentFor returns the intent string for the given op. An unknown op is an
// implementation error and returns a non-nil error.
func IntentFor(op Op) (string, error) {
	intent, ok := opIntentTable[op]
	if !ok {
		return "", fmt.Errorf("brokerrpc: unknown op %q — not in intent table", op)
	}
	return intent, nil
}

// StampAuthMeta returns the AuthorizationMetadata for the given op: the
// op-derived intent and downloadable hardcoded to false (SEC-73 — the
// perimeter-exit decision is broker-resolved; the guest never requests it).
// An unknown op returns a non-nil error.
func StampAuthMeta(op Op) (AuthorizationMetadata, error) {
	intent, err := IntentFor(op)
	if err != nil {
		return AuthorizationMetadata{}, err
	}
	return AuthorizationMetadata{
		Intent:       intent,
		Downloadable: false,
	}, nil
}
