// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc_test

import (
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
)

// TestListDirectoryRequestMarshal verifies that a path-scoped request
// marshals filesystem_id at the top level and that authorization_metadata
// is a nested object containing only intent and downloadable — no
// filesystem_id inside it.
func TestListDirectoryRequestMarshal(t *testing.T) {
	req := brokerrpc.ListDirectoryRequest{
		FilesystemID: "fs-abc",
		Path:         "/some/dir",
		AuthorizationMetadata: brokerrpc.AuthorizationMetadata{
			Intent:       "read",
			Downloadable: false,
		},
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal ListDirectoryRequest: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// filesystem_id must be at the top level
	if _, ok := top["filesystem_id"]; !ok {
		t.Error("expected filesystem_id at top level; not found")
	}

	// authorization_metadata must be present as a nested object
	rawAM, ok := top["authorization_metadata"]
	if !ok {
		t.Fatal("expected authorization_metadata at top level; not found")
	}

	var am map[string]json.RawMessage
	if err := json.Unmarshal(rawAM, &am); err != nil {
		t.Fatalf("unmarshal authorization_metadata: %v", err)
	}

	// authorization_metadata must NOT contain filesystem_id
	if _, bad := am["filesystem_id"]; bad {
		t.Error("filesystem_id must NOT appear inside authorization_metadata")
	}

	// authorization_metadata must contain intent and downloadable
	if _, ok := am["intent"]; !ok {
		t.Error("expected intent inside authorization_metadata")
	}
	if _, ok := am["downloadable"]; !ok {
		t.Error("expected downloadable inside authorization_metadata")
	}
}

// TestFileDecodeToleratesUnknownFields verifies that decoding a JSON body
// with unknown extra fields into File/FilesystemFile/Directory succeeds and
// populates the known fields without error.
func TestFileDecodeToleratesUnknownFields(t *testing.T) {
	raw := `{
		"path": "/a/b.txt",
		"size": 42,
		"mtime": "2025-01-02T03:04:05Z",
		"mode": "0644",
		"sha": "deadbeef",
		"mime": "text/plain",
		"uuid": "u-1234",
		"unknown_future_field": "ignored"
	}`

	var f brokerrpc.File
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("decode File with unknown field: %v", err)
	}
	if f.Path != "/a/b.txt" {
		t.Errorf("File.Path = %q; want /a/b.txt", f.Path)
	}
	if f.Size != 42 {
		t.Errorf("File.Size = %d; want 42", f.Size)
	}
	if f.SHA != "deadbeef" {
		t.Errorf("File.SHA = %q; want deadbeef", f.SHA)
	}
	if f.UUID != "u-1234" {
		t.Errorf("File.UUID = %q; want u-1234", f.UUID)
	}
}

// TestFilesystemFileDecodeToleratesUnknownFields verifies tolerant decoding
// for FilesystemFile.
func TestFilesystemFileDecodeToleratesUnknownFields(t *testing.T) {
	raw := `{
		"path": "/x/y.go",
		"size": 100,
		"mtime": "2025-06-11T00:00:00Z",
		"mode": "0755",
		"sha": "aabbcc",
		"mime": "text/x-go",
		"uuid": "u-5678",
		"extra_broker_field": 999
	}`

	var ff brokerrpc.FilesystemFile
	if err := json.Unmarshal([]byte(raw), &ff); err != nil {
		t.Fatalf("decode FilesystemFile with unknown field: %v", err)
	}
	if ff.Path != "/x/y.go" {
		t.Errorf("FilesystemFile.Path = %q; want /x/y.go", ff.Path)
	}
	if ff.UUID != "u-5678" {
		t.Errorf("FilesystemFile.UUID = %q; want u-5678", ff.UUID)
	}
}

// TestDirectoryDecodeToleratesUnknownFields verifies tolerant decoding for
// Directory.
func TestDirectoryDecodeToleratesUnknownFields(t *testing.T) {
	raw := `{
		"path": "/some/dir",
		"mode": "0755",
		"mtime": "2025-06-11T00:00:00Z",
		"future_dir_field": true
	}`

	var d brokerrpc.Directory
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("decode Directory with unknown field: %v", err)
	}
	if d.Path != "/some/dir" {
		t.Errorf("Directory.Path = %q; want /some/dir", d.Path)
	}
}

// TestBareAckDecodes verifies that a bare empty JSON object decodes into the
// ack response type without error.
func TestBareAckDecodes(t *testing.T) {
	raw := `{}`
	var ack brokerrpc.AckResponse
	if err := json.Unmarshal([]byte(raw), &ack); err != nil {
		t.Fatalf("decode bare-ack {}: %v", err)
	}
}

// TestFileUploadRequestOverwriteMarshals pins the single fileUpload params
// declaration two-sidedly: OverwriteExisting=true serialises the
// overwrite_existing key, and the zero value omits it entirely (omitempty),
// keeping the create-new form key-free on the wire.
func TestFileUploadRequestOverwriteMarshals(t *testing.T) {
	am := brokerrpc.AuthorizationMetadata{Intent: "write", Downloadable: false}

	withOverwrite := brokerrpc.FileUploadRequest{
		FilesystemID:          "fs-1",
		Path:                  "/f.bin",
		DeclaredSizeBytes:     7,
		OverwriteExisting:     true,
		AuthorizationMetadata: am,
	}
	b, err := json.Marshal(withOverwrite)
	if err != nil {
		t.Fatalf("marshal FileUploadRequest: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if string(top["overwrite_existing"]) != "true" {
		t.Errorf("overwrite_existing = %s; want true", top["overwrite_existing"])
	}

	withoutOverwrite := brokerrpc.FileUploadRequest{
		FilesystemID:          "fs-1",
		Path:                  "/f.bin",
		DeclaredSizeBytes:     7,
		AuthorizationMetadata: am,
	}
	b, err = json.Marshal(withoutOverwrite)
	if err != nil {
		t.Fatalf("marshal FileUploadRequest (no overwrite): %v", err)
	}
	top = nil
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, present := top["overwrite_existing"]; present {
		t.Error("zero-value OverwriteExisting must omit the overwrite_existing key")
	}
}

// TestListDirectoryRequestCursorMarshals pins the single listDirectory request
// declaration two-sidedly: a non-empty Cursor serialises the cursor key
// (page-2+ continuation), and the zero value omits it, keeping the page-1
// unary form unchanged.
func TestListDirectoryRequestCursorMarshals(t *testing.T) {
	am := brokerrpc.AuthorizationMetadata{Intent: "read", Downloadable: false}

	withCursor := brokerrpc.ListDirectoryRequest{
		FilesystemID:          "fs-1",
		Path:                  "/d",
		AuthorizationMetadata: am,
		Cursor:                brokerrpc.OpaqueCursor("opaque-token"),
	}
	b, err := json.Marshal(withCursor)
	if err != nil {
		t.Fatalf("marshal ListDirectoryRequest: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if string(top["cursor"]) != `"opaque-token"` {
		t.Errorf("cursor = %s; want \"opaque-token\"", top["cursor"])
	}

	withoutCursor := brokerrpc.ListDirectoryRequest{
		FilesystemID:          "fs-1",
		Path:                  "/d",
		AuthorizationMetadata: am,
	}
	b, err = json.Marshal(withoutCursor)
	if err != nil {
		t.Fatalf("marshal ListDirectoryRequest (page 1): %v", err)
	}
	top = nil
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, present := top["cursor"]; present {
		t.Error("an empty Cursor must omit the cursor key (page-1 form unchanged)")
	}
}

// TestUUIDAxisRequestsDoNotHavePath verifies that the uuid-addressed
// fileDownload request carries a uuid field, not a path — the guest never
// addresses that op by path.
func TestUUIDAxisRequestsDoNotHavePath(t *testing.T) {
	req := brokerrpc.FileDownloadRequest{
		FilesystemID: "fs-1",
		UUID:         "u-abc",
		AuthorizationMetadata: brokerrpc.AuthorizationMetadata{
			Intent:       "read",
			Downloadable: false,
		},
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal FileDownloadRequest: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	if _, ok := top["uuid"]; !ok {
		t.Error("expected uuid at top level; not found")
	}
	// path must not appear on uuid-axis ops
	if _, bad := top["path"]; bad {
		t.Error("path must NOT appear on uuid-axis requests")
	}
}
