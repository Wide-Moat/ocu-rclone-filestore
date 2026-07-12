// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/httpjson"
)

// wireFile mirrors the guest's File/FilesystemFile response fields.
type wireFile struct {
	Path  string `json:"path,omitempty"`
	Size  int64  `json:"size,omitempty"`
	Mtime string `json:"mtime,omitempty"`
	Mode  string `json:"mode,omitempty"`
	MIME  string `json:"mime,omitempty"`
	UUID  string `json:"uuid,omitempty"`
}

// wireDir mirrors the guest's Directory response fields.
type wireDir struct {
	Path  string `json:"path,omitempty"`
	Mode  string `json:"mode,omitempty"`
	Mtime string `json:"mtime,omitempty"`
}

// pathBody decodes the op-specific {path} field from the raw request body.
type pathBody struct {
	Path string `json:"path"`
}

// srcDstBody decodes the op-specific {source,destination,overwrite_existing}
// fields, mirroring the guest's copy/move bodies.
type srcDstBody struct {
	Source            string `json:"source"`
	Destination       string `json:"destination"`
	OverwriteExisting bool   `json:"overwrite_existing"`
}

// pathFromBody decodes the {path} field from a request body.
func pathFromBody(body commonBody) (string, error) {
	var p pathBody
	if err := json.Unmarshal(body.raw, &p); err != nil {
		return "", err
	}
	return p.Path, nil
}

// writeMetaError maps a filesystem error from a metadata/path op to an HTTP
// status. A missing target is 404; a traversal escape is 400; anything else is
// a 500-class permanent error.
func writeMetaError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		httpjson.Error(w, http.StatusNotFound, "not found")
	case errors.Is(err, os.ErrExist):
		httpjson.Error(w, http.StatusConflict, "already exists")
	default:
		httpjson.Error(w, http.StatusInternalServerError, "operation failed")
	}
}

// handleCreateFile creates an empty file at the requested path and returns its
// metadata.
func (s *Server) handleCreateFile(w http.ResponseWriter, scope Scope, body commonBody) {
	rel, err := pathFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	if mkErr := os.MkdirAll(filepath.Dir(abs), 0o750); mkErr != nil {
		httpjson.Error(w, http.StatusInternalServerError, fmt.Sprintf("mkdir parent failed: %v", mkErr))
		return
	}
	// O_TRUNC so createFile produces an EMPTY file even when the path already
	// exists: without it a pre-existing file would keep its old contents, which
	// createFile's "empty file" contract forbids.
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // G304: abs is traversal-guarded by resolveUnder, confined to the scope volume
	if err != nil {
		writeMetaError(w, err)
		return
	}
	_ = f.Close()

	size, mtime, mode, uuid, statErr := fileMeta(scope, rel, abs)
	if statErr != nil {
		writeMetaError(w, statErr)
		return
	}
	httpjson.OK(w, struct {
		File wireFile `json:"file"`
	}{File: wireFile{Path: rel, Size: size, Mtime: mtime, Mode: mode, UUID: uuid}})
}

// handleReadFile is the unary readFile op: metadata-only, consistent with the
// guest's current readFile (bulk bytes flow through fileDownload).
func (s *Server) handleReadFile(w http.ResponseWriter, scope Scope, body commonBody) {
	rel, err := pathFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	size, mtime, mode, uuid, statErr := fileMeta(scope, rel, abs)
	if statErr != nil {
		writeMetaError(w, statErr)
		return
	}
	httpjson.OK(w, struct {
		File wireFile `json:"file"`
	}{File: wireFile{Path: rel, Size: size, Mtime: mtime, Mode: mode, UUID: uuid}})
}

// handleReadMetadata stats the path and returns the file XOR directory arm.
func (s *Server) handleReadMetadata(w http.ResponseWriter, scope Scope, body commonBody) {
	rel, err := pathFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	info, statErr := os.Stat(abs)
	if statErr != nil {
		writeMetaError(w, statErr)
		return
	}
	// Pointer arms with omitempty so the ABSENT arm is dropped from the wire: a
	// file response carries only {"file":{…}}, a directory only {"directory":{…}}
	// — value structs would serialise an empty {"directory":{}} for a file (and
	// vice versa), muddying the file-XOR-directory union the guest decodes.
	resp := struct {
		File      *wireFile `json:"file,omitempty"`
		Directory *wireDir  `json:"directory,omitempty"`
	}{}
	if info.IsDir() {
		resp.Directory = &wireDir{
			Path:  rel,
			Mode:  info.Mode().String(),
			Mtime: info.ModTime().UTC().Format(time.RFC3339Nano),
		}
	} else {
		resp.File = &wireFile{
			Path:  rel,
			Size:  info.Size(),
			Mtime: info.ModTime().UTC().Format(time.RFC3339Nano),
			Mode:  info.Mode().String(),
			UUID:  uuidForRelPath(scope.FilesystemID, rel),
		}
	}
	httpjson.OK(w, resp)
}

// listDirEntry mirrors the guest's union listDirectory entry.
type listDirEntry struct {
	File      *wireFile `json:"file,omitempty"`
	Directory *wireDir  `json:"directory,omitempty"`
}

// handleListDirectory lists a single page of the directory at path, returning
// the file/directory union entries.
func (s *Server) handleListDirectory(w http.ResponseWriter, scope Scope, body commonBody) {
	rel, err := pathFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	entries, readErr := os.ReadDir(abs)
	if readErr != nil {
		writeMetaError(w, readErr)
		return
	}
	out := struct {
		Entries []listDirEntry `json:"entries"`
	}{}
	for _, e := range entries {
		childRel := filepath.Join(rel, e.Name())
		info, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		if e.IsDir() {
			out.Entries = append(out.Entries, listDirEntry{Directory: &wireDir{
				Path:  childRel,
				Mode:  info.Mode().String(),
				Mtime: info.ModTime().UTC().Format(time.RFC3339Nano),
			}})
			continue
		}
		out.Entries = append(out.Entries, listDirEntry{File: &wireFile{
			Path:  childRel,
			Size:  info.Size(),
			Mtime: info.ModTime().UTC().Format(time.RFC3339Nano),
			Mode:  info.Mode().String(),
			UUID:  uuidForRelPath(scope.FilesystemID, childRel),
		}})
	}
	httpjson.OK(w, out)
}

// handleMakeDirectory creates the directory at path. It is idempotent: an
// already-present directory is a success.
func (s *Server) handleMakeDirectory(w http.ResponseWriter, scope Scope, body commonBody) {
	rel, err := pathFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	if mkErr := os.MkdirAll(abs, 0o750); mkErr != nil {
		writeMetaError(w, mkErr)
		return
	}
	httpjson.OK(w, struct{}{})
}

// handleRemoveDirectory removes the directory at path.
func (s *Server) handleRemoveDirectory(w http.ResponseWriter, scope Scope, body commonBody) {
	rel, err := pathFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	if rmErr := os.RemoveAll(abs); rmErr != nil {
		writeMetaError(w, rmErr)
		return
	}
	httpjson.OK(w, struct{}{})
}

// handleRemoveFile removes the file at path.
func (s *Server) handleRemoveFile(w http.ResponseWriter, scope Scope, body commonBody) {
	rel, err := pathFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	abs, err := resolveUnder(scope.Root, rel)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "path escapes scope")
		return
	}
	if rmErr := os.Remove(abs); rmErr != nil {
		writeMetaError(w, rmErr)
		return
	}
	httpjson.OK(w, struct{}{})
}

// srcDstFromBody decodes the {source,destination,overwrite_existing} fields.
func srcDstFromBody(body commonBody) (srcDstBody, error) {
	var sd srcDstBody
	if err := json.Unmarshal(body.raw, &sd); err != nil {
		return srcDstBody{}, err
	}
	return sd, nil
}

// resolveSrcDst resolves and validates the source and destination paths under
// the scope root.
func resolveSrcDst(scope Scope, sd srcDstBody) (srcAbs, dstAbs string, status int, msg string) {
	srcAbs, err := resolveUnder(scope.Root, sd.Source)
	if err != nil {
		return "", "", http.StatusBadRequest, "source escapes scope"
	}
	dstAbs, err = resolveUnder(scope.Root, sd.Destination)
	if err != nil {
		return "", "", http.StatusBadRequest, "destination escapes scope"
	}
	return srcAbs, dstAbs, 0, ""
}

// applySrcDstOp runs the shared copy/move preamble — decode the
// source/destination body, resolve both under the scope, refuse to clobber an
// existing destination unless overwrite_existing is set (409), and create the
// destination parent — then invokes op(srcAbs, dstAbs). It writes the same error
// responses the individual handlers wrote inline and an empty 200 on success, so
// the three ops differ only in their terminal filesystem action.
func (s *Server) applySrcDstOp(w http.ResponseWriter, scope Scope, body commonBody, op func(srcAbs, dstAbs string) error) {
	sd, err := srcDstFromBody(body)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "malformed body")
		return
	}
	srcAbs, dstAbs, status, msg := resolveSrcDst(scope, sd)
	if status != 0 {
		httpjson.Error(w, status, msg)
		return
	}
	if !sd.OverwriteExisting {
		if _, statErr := os.Stat(dstAbs); statErr == nil {
			httpjson.Error(w, http.StatusConflict, "destination exists")
			return
		}
	}
	if mkErr := os.MkdirAll(filepath.Dir(dstAbs), 0o750); mkErr != nil {
		httpjson.Error(w, http.StatusInternalServerError, fmt.Sprintf("mkdir parent failed: %v", mkErr))
		return
	}
	if opErr := op(srcAbs, dstAbs); opErr != nil {
		writeMetaError(w, opErr)
		return
	}
	httpjson.OK(w, struct{}{})
}

// handleCopyFile copies source to destination, honouring overwrite_existing.
func (s *Server) handleCopyFile(w http.ResponseWriter, scope Scope, body commonBody) {
	s.applySrcDstOp(w, scope, body, copyFileContents)
}

// copyFileContents streams src to dst so a large file copy does not read the
// whole file into memory (os.ReadFile+os.WriteFile would). dst is created with
// 0o600 and truncated; both paths are already scope-confined by the caller.
func copyFileContents(srcAbs, dstAbs string) error {
	in, err := os.Open(srcAbs) //nolint:gosec // G304: srcAbs is traversal-guarded by resolveSrcDst, confined to the scope volume
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dstAbs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // G304: dstAbs is traversal-guarded by resolveSrcDst, confined to the scope volume
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// handleMoveFile moves source to destination, honouring overwrite_existing.
func (s *Server) handleMoveFile(w http.ResponseWriter, scope Scope, body commonBody) {
	s.applySrcDstOp(w, scope, body, os.Rename)
}

// handleMoveDirectory moves the directory at source to destination. Like
// handleMoveFile it refuses to clobber an existing destination unless
// overwrite_existing is set, returning 409 Conflict — without this a move onto a
// present path would silently replace it.
func (s *Server) handleMoveDirectory(w http.ResponseWriter, scope Scope, body commonBody) {
	s.applySrcDstOp(w, scope, body, os.Rename)
}
