// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadGolden reads a golden fixture file from testdata/golden/<name>.
// It uses os.ReadFile so callers can assert or regenerate.
func loadGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("load golden %s: %v", name, err)
	}
	return data
}

// TestConformanceUploadParamsFrame checks that the upload params frame golden
// matches the live serialisation output from the chunker.
func TestConformanceUploadParamsFrame(t *testing.T) {
	golden := loadGolden(t, "upload-params-frame.json")

	// Build the params struct the upload path would send.
	am, err := StampAuthMeta(OpFileUpload)
	if err != nil {
		t.Fatalf("StampAuthMeta: %v", err)
	}
	params := struct {
		FilesystemID          string                `json:"filesystem_id"`
		Path                  string                `json:"path"`
		DeclaredSizeBytes     int64                 `json:"declared_size_bytes"`
		AuthorizationMetadata AuthorizationMetadata `json:"authorization_metadata"`
	}{
		FilesystemID:          "fs-golden-01",
		Path:                  "/golden.bin",
		DeclaredSizeBytes:     42,
		AuthorizationMetadata: am,
	}
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	var buf bytes.Buffer
	if err := writeFrame(&buf, 0x00, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	// The golden stores the JSON payload portion only (not the 5-byte prefix).
	gotPayload := buf.Bytes()[frameHeaderLen:]
	if !jsonEqual(gotPayload, golden) {
		t.Errorf("upload params frame mismatch\ngot:  %s\nwant: %s", gotPayload, golden)
	}
}

// TestConformanceUploadFramePrefixBytes asserts the prefix bytes in the frame
// golden are exactly the 5-byte Connect frame header format.
func TestConformanceUploadFramePrefixBytes(t *testing.T) {
	payload := []byte(`{"declared_size_bytes":42}`)
	var buf bytes.Buffer
	_ = writeFrame(&buf, 0x00, payload)

	data := buf.Bytes()
	if data[0] != 0x00 {
		t.Errorf("flag byte: got %02x, want 00", data[0])
	}
	gotLen := binary.BigEndian.Uint32(data[1:5])
	if gotLen != uint32(len(payload)) {
		t.Errorf("length field: got %d, want %d", gotLen, len(payload))
	}
}

// TestConformanceEndStreamSuccess checks the end-stream success golden.
func TestConformanceEndStreamSuccess(t *testing.T) {
	golden := loadGolden(t, "endstream-success.json")

	var buf bytes.Buffer
	if err := writeEndStream(&buf, nil); err != nil {
		t.Fatalf("writeEndStream: %v", err)
	}

	// The golden stores the JSON payload portion only.
	gotPayload := buf.Bytes()[frameHeaderLen:]
	if !jsonEqual(gotPayload, golden) {
		t.Errorf("endstream success mismatch\ngot:  %s\nwant: %s", gotPayload, golden)
	}
}

// TestConformanceEndStreamError checks the end-stream error golden.
func TestConformanceEndStreamError(t *testing.T) {
	golden := loadGolden(t, "endstream-error.json")

	connErr := &ConnectError{Code: "not_found", Message: "object missing"}
	var buf bytes.Buffer
	if err := writeEndStream(&buf, connErr); err != nil {
		t.Fatalf("writeEndStream: %v", err)
	}

	gotPayload := buf.Bytes()[frameHeaderLen:]
	if !jsonEqual(gotPayload, golden) {
		t.Errorf("endstream error mismatch\ngot:  %s\nwant: %s", gotPayload, golden)
	}
}

// TestConformanceDownloadRequest checks the fileDownload request golden:
// route, Content-Type, Connect-Protocol-Version header, and auth/uuid shape.
func TestConformanceDownloadRequest(t *testing.T) {
	golden := loadGolden(t, "download-request.json")

	// Build the request as download.go would.
	am, err := StampAuthMeta(OpFileDownload)
	if err != nil {
		t.Fatalf("StampAuthMeta: %v", err)
	}
	req := FileDownloadRequest{
		FilesystemID:          "fs-golden-01",
		UUID:                  "uuid-golden-42",
		AuthorizationMetadata: am,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	// Build the golden shape: route, Content-Type, version, body.
	type requestGolden struct {
		Route          string              `json:"route"`
		ContentType    string              `json:"content_type"`
		ConnectVersion string              `json:"connect_protocol_version"`
		Body           FileDownloadRequest `json:"body"`
	}
	var want requestGolden
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	// Verify static fields.
	wantRoute := "/ocu.filestore.v1alpha.FilesystemService/fileDownload"
	if want.Route != wantRoute {
		t.Errorf("golden route: got %q, want %q", want.Route, wantRoute)
	}
	if want.ContentType != "application/connect+json" {
		t.Errorf("golden content-type: got %q, want application/connect+json", want.ContentType)
	}
	if want.ConnectVersion != "1" {
		t.Errorf("golden connect-version: got %q, want 1", want.ConnectVersion)
	}

	// Verify body shape against live output.
	var gotBody FileDownloadRequest
	if err := json.Unmarshal(payload, &gotBody); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	if gotBody.UUID != want.Body.UUID {
		t.Errorf("uuid: got %q, want %q", gotBody.UUID, want.Body.UUID)
	}
	if gotBody.AuthorizationMetadata.Intent != want.Body.AuthorizationMetadata.Intent {
		t.Errorf("intent: got %q, want %q",
			gotBody.AuthorizationMetadata.Intent,
			want.Body.AuthorizationMetadata.Intent)
	}
	if gotBody.AuthorizationMetadata.Downloadable != want.Body.AuthorizationMetadata.Downloadable {
		t.Errorf("downloadable: got %v, want %v",
			gotBody.AuthorizationMetadata.Downloadable,
			want.Body.AuthorizationMetadata.Downloadable)
	}
}

// TestConformanceUnaryRequestBody checks the unary request golden.
func TestConformanceUnaryRequestBody(t *testing.T) {
	golden := loadGolden(t, "unary-request-body.json")

	am, err := StampAuthMeta(OpListDirectory)
	if err != nil {
		t.Fatalf("StampAuthMeta: %v", err)
	}
	req := ListDirectoryRequest{
		FilesystemID:          "fs-golden-01",
		Path:                  "/golden-dir",
		AuthorizationMetadata: am,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if !jsonEqual(payload, golden) {
		t.Errorf("unary request body mismatch\ngot:  %s\nwant: %s", payload, golden)
	}
}

// jsonEqual compares two JSON byte slices for structural equality by
// unmarshalling both into map[string]any and comparing.
func jsonEqual(a, b []byte) bool {
	var ma, mb interface{}
	if err := json.Unmarshal(a, &ma); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &mb); err != nil {
		return false
	}
	ra, _ := json.Marshal(ma)
	rb, _ := json.Marshal(mb)
	return bytes.Equal(ra, rb)
}
