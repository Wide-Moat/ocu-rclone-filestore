// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxRequestBytes bounds a JSON request body read so a malformed request cannot
// exhaust the peer's memory. It is generous relative to any real op body.
const maxRequestBytes = 1 << 20 // 1 MiB

// readAllLimited reads up to maxRequestBytes from r.
func readAllLimited(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxRequestBytes))
}

// pemEncodeCert wraps a DER certificate in a PEM block.
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// resolveUnder cleans rel and joins it under root, rejecting any path that would
// escape the scope volume (a ".." traversal or an absolute path that resolves
// outside root). It returns the cleaned absolute path on success.
func resolveUnder(root, rel string) (string, error) {
	// A leading slash is treated as relative to the scope root, mirroring the
	// guest's filesystem-relative paths.
	clean := filepath.Clean("/" + strings.TrimPrefix(rel, "/"))
	abs := filepath.Join(root, clean)

	// Confirm the result is still within root, guarding against a crafted rel
	// that escapes via traversal.
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absAbs, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	if absAbs != rootAbs && !strings.HasPrefix(absAbs, rootAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("filestore: path %q escapes the scope volume", rel)
	}
	return absAbs, nil
}

// uuidForRelPath derives a stable, deterministic uuid for a file at the given
// scope-relative path. fileDownload addresses by uuid, so tests learn a file's
// uuid by computing it from the path the file was created at. The derivation is
// scoped by filesystem_id so the same relative path in two scopes yields
// distinct uuids.
func uuidForRelPath(fsID, rel string) string {
	clean := filepath.Clean("/" + strings.TrimPrefix(rel, "/"))
	sum := sha256.Sum256([]byte(fsID + "\x00" + clean))
	return hex.EncodeToString(sum[:16])
}

// relPathForUUID resolves a uuid back to its scope-relative path by scanning the
// scope volume and matching the deterministic derivation. It returns the
// relative path and true on a hit. The scan is acceptable for a near-mock peer
// serving small test volumes.
func relPathForUUID(scope Scope, uuid string) (string, bool) {
	var match string
	found := false
	_ = filepath.WalkDir(scope.Root, func(path string, d os.DirEntry, err error) error {
		// Tolerate a per-entry walk error by skipping just that entry and
		// continuing the scan, rather than aborting the whole walk: a transiently
		// unreadable entry must not hide a matching file elsewhere in the volume.
		if err != nil || found {
			return nil //nolint:nilerr // intentional: skip the erroring entry and keep walking
		}
		if d == nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(scope.Root, path)
		if rerr != nil {
			return nil //nolint:nilerr // intentional: skip an unrelatable path and keep walking
		}
		if uuidForRelPath(scope.FilesystemID, rel) == uuid {
			match = rel
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return match, found
}

// fileMeta builds the wire file-metadata fields for the file at abs (scope-rel
// rel), used to fill the guest's File/FilesystemFile response shapes.
func fileMeta(scope Scope, rel, abs string) (size int64, mtime, mode, uuid string, err error) {
	info, statErr := os.Stat(abs)
	if statErr != nil {
		return 0, "", "", "", statErr
	}
	return info.Size(),
		info.ModTime().UTC().Format(time.RFC3339Nano),
		info.Mode().String(),
		uuidForRelPath(scope.FilesystemID, rel),
		nil
}
