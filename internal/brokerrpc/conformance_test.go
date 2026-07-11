// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// loadGolden reads a golden fixture file from testdata/golden/<name>.
func loadGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("load golden %s: %v", name, err)
	}
	return data
}

// jsonEqual compares two JSON byte slices for structural equality.
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

// TestGoldenUnaryRequest checks the unary request body golden matches the live
// listDirectory request marshalled by the client.
func TestGoldenUnaryRequest(t *testing.T) {
	golden := loadGolden(t, "rest-unary-request.json")

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

// TestGoldenUploadParams checks the upload params golden matches the live params
// JSON the upload path puts in the multipart 'params' field — captured by
// reading the actual multipart body the client produced.
func TestGoldenUploadParams(t *testing.T) {
	golden := loadGolden(t, "rest-upload-params.json")

	var params []byte
	c, _ := newTLSTestClient(t, "fs-golden-01", func(w http.ResponseWriter, r *http.Request) {
		_, mp, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("parse Content-Type: %v", err)
		}
		mr := multipart.NewReader(r.Body, mp["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("read part: %v", err)
			}
			if part.FormName() == "params" {
				params, _ = io.ReadAll(part)
			} else {
				_, _ = io.Copy(io.Discard, part)
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	content := bytes.Repeat([]byte("x"), 42)
	if err := c.Upload(context.Background(), "/golden.bin", bytes.NewReader(content), 42, false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !jsonEqual(params, golden) {
		t.Errorf("upload params mismatch\ngot:  %s\nwant: %s", params, golden)
	}
}

// TestGoldenDownloadRequest checks the fileDownload request golden matches the
// live request body (no Connect route/content-type/protocol-version envelope).
func TestGoldenDownloadRequest(t *testing.T) {
	golden := loadGolden(t, "rest-download-request.json")

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
	if !jsonEqual(payload, golden) {
		t.Errorf("download request mismatch\ngot:  %s\nwant: %s", payload, golden)
	}
}

// TestGoldenDownloadRequestRanged checks the ranged fileDownload request golden:
// the {offset, length} window serialises as a nested "range" object with exactly
// those keys. The fixture is independent text, so a JSON-tag typo on
// Range/Offset/Length fails here even when a test-side decoder would round-trip
// through the same struct — this is the absolute-key pin for the live
// ranged-read hot path.
func TestGoldenDownloadRequestRanged(t *testing.T) {
	golden := loadGolden(t, "rest-download-request-ranged.json")

	am, err := StampAuthMeta(OpFileDownload)
	if err != nil {
		t.Fatalf("StampAuthMeta: %v", err)
	}
	req := FileDownloadRequest{
		FilesystemID:          "fs-golden-01",
		UUID:                  "uuid-golden-42",
		Range:                 &Range{Offset: 100, Length: 512},
		AuthorizationMetadata: am,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if !jsonEqual(payload, golden) {
		t.Errorf("ranged download request mismatch\ngot:  %s\nwant: %s", payload, golden)
	}
}
