// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestDownloadStreamRouteAndHeaders checks that fileDownload POSTs to the
// correct route with Content-Type application/connect+json and
// Connect-Protocol-Version: 1.
func TestDownloadStreamRouteAndHeaders(t *testing.T) {
	var gotPath, gotCT, gotProto string
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotProto = r.Header.Get("Connect-Protocol-Version")

		// Send one content frame + success end-stream.
		var buf bytes.Buffer
		frame, _ := json.Marshal(map[string][]byte{"data": []byte("hello")})
		_ = writeFrame(&buf, 0x00, frame)
		_ = writeEndStream(&buf, nil)

		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-dl-01")
	_, _ = c.Download(context.Background(), "uuid-abc")

	wantPath := "/ocu.filestore.v1alpha.FilesystemService/fileDownload"
	if gotPath != wantPath {
		t.Errorf("path: got %q, want %q", gotPath, wantPath)
	}
	wantCT := "application/connect+json"
	if gotCT != wantCT {
		t.Errorf("Content-Type: got %q, want %q", gotCT, wantCT)
	}
	if gotProto != "1" {
		t.Errorf("Connect-Protocol-Version: got %q, want 1", gotProto)
	}
}

// TestDownloadAuthMetadata asserts the fileDownload request body carries
// authorization_metadata{intent: read, downloadable: false} and addresses
// by uuid, not path (D7).
func TestDownloadAuthMetadata(t *testing.T) {
	var reqBody []byte
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// The download request is a single JSON frame (not framed for unary
		// compat). Read it directly from the body.
		flag, payload, err := readFrame(r.Body)
		if err != nil {
			t.Errorf("read request frame: %v", err)
			return
		}
		_ = flag
		reqBody = payload

		var buf bytes.Buffer
		frame, _ := json.Marshal(map[string][]byte{"data": []byte("x")})
		_ = writeFrame(&buf, 0x00, frame)
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-dl-01")
	_, _ = c.Download(context.Background(), "uuid-test-42")

	var req struct {
		FilesystemID string                `json:"filesystem_id"`
		UUID         string                `json:"uuid"`
		Path         string                `json:"path,omitempty"`
		AuthMeta     AuthorizationMetadata `json:"authorization_metadata"`
	}
	if err := json.Unmarshal(reqBody, &req); err != nil {
		t.Fatalf("parse request body: %v", err)
	}
	if req.UUID != "uuid-test-42" {
		t.Errorf("uuid: got %q, want %q", req.UUID, "uuid-test-42")
	}
	if req.Path != "" {
		t.Errorf("path must be absent in download request, got %q", req.Path)
	}
	if req.AuthMeta.Intent != "read" {
		t.Errorf("auth intent: got %q, want read", req.AuthMeta.Intent)
	}
	if req.AuthMeta.Downloadable {
		t.Error("auth downloadable: must be false")
	}
	if req.FilesystemID == "" {
		t.Error("filesystem_id must be set")
	}
}

// TestDownloadFullReassembly verifies that the download helper reassembles
// multiple content frames into the complete content.
func TestDownloadFullReassembly(t *testing.T) {
	part1 := []byte("hello ")
	part2 := []byte("world")

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		f1, _ := json.Marshal(map[string][]byte{"data": part1})
		f2, _ := json.Marshal(map[string][]byte{"data": part2})
		_ = writeFrame(&buf, 0x00, f1)
		_ = writeFrame(&buf, 0x00, f2)
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-dl-01")
	got, err := c.Download(context.Background(), "uuid-abc")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := append(part1, part2...)
	if !bytes.Equal(got, want) {
		t.Errorf("content: got %q, want %q", got, want)
	}
}

// TestDownloadRangeHelper verifies the distinct download-by-range helper
// (DownloadRange) returns the requested {offset, length} slice from the
// fileDownload stream — NOT the unary readFile op.
func TestDownloadRangeHelper(t *testing.T) {
	content := []byte("abcdefghij") // 10 bytes

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		frame, _ := json.Marshal(map[string][]byte{"data": content})
		_ = writeFrame(&buf, 0x00, frame)
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-dl-01")
	// Request bytes [2, 5) → "cde"
	got, err := c.DownloadRange(context.Background(), "uuid-abc", 2, 3)
	if err != nil {
		t.Fatalf("DownloadRange: %v", err)
	}
	want := content[2:5]
	if !bytes.Equal(got, want) {
		t.Errorf("range slice: got %q, want %q", got, want)
	}
}

// TestDownloadTrailerDeterminesSuccess verifies that success/failure comes from
// the EndStreamResponse trailer, not the HTTP status (streams always 200).
func TestDownloadTrailerDeterminesSuccess(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		// Stream returns HTTP 200 but trailer carries an error.
		connErr := &ConnectError{Code: "not_found", Message: "uuid missing"}
		_ = writeEndStream(&buf, connErr)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK) // always 200 for streams
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-dl-01")
	_, err := c.Download(context.Background(), "uuid-gone")
	if err == nil {
		t.Fatal("expected error from EndStreamResponse, got nil (HTTP 200 must not indicate success)")
	}
}
