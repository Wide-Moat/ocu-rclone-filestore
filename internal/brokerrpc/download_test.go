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
		if flag != 0x00 {
			t.Errorf("download request frame flag: want 0x00 (data frame), got 0x%02x", flag)
		}
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

// TestDownloadMalformedFrameIsHardError verifies that an undecodable content
// frame aborts the download with a non-nil error rather than silently dropping
// the frame and returning truncated content as success (CR-01). For a
// FUSE-backed mount, silent truncation is undetectable file corruption.
func TestDownloadMalformedFrameIsHardError(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		good, _ := json.Marshal(map[string][]byte{"data": []byte("hello ")})
		_ = writeFrame(&buf, 0x00, good)
		// A frame whose payload is not valid JSON for downloadContentFrame.
		_ = writeFrame(&buf, 0x00, []byte("this is not json"))
		good2, _ := json.Marshal(map[string][]byte{"data": []byte("world")})
		_ = writeFrame(&buf, 0x00, good2)
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-dl-01")
	got, err := c.Download(context.Background(), "uuid-corrupt")
	if err == nil {
		t.Fatalf("expected hard error on malformed frame, got nil with content %q", got)
	}
	if got != nil {
		t.Errorf("malformed frame must not return partial content; got %q", got)
	}
}

// TestDownloadTruncatedStreamErrors verifies that a stream ending before the
// EndStreamResponse trailer is reported as an error (LO-01: the EOF branch must
// use errors.Is because readFrame wraps the underlying EOF).
func TestDownloadTruncatedStreamErrors(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		frame, _ := json.Marshal(map[string][]byte{"data": []byte("partial")})
		_ = writeFrame(&buf, 0x00, frame)
		// No end-stream frame — the stream is truncated.
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-dl-01")
	_, err := c.Download(context.Background(), "uuid-trunc")
	if err == nil {
		t.Fatal("expected error on truncated stream, got nil")
	}
}

// downloadRangeContentServer serves the given content as a single download
// content frame followed by a success trailer.
func downloadRangeContentServer(t *testing.T, content []byte) string {
	t.Helper()
	return uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		frame, _ := json.Marshal(map[string][]byte{"data": content})
		_ = writeFrame(&buf, 0x00, frame)
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
}

// TestDownloadRangeNegativeLength verifies that a negative length returns an
// error rather than panicking the process (HI-02). A make([]byte, negative)
// would crash the entire mount instead of returning EINVAL to the VFS.
func TestDownloadRangeNegativeLength(t *testing.T) {
	sock := downloadRangeContentServer(t, []byte("abcdefghij"))
	c, _ := New(sock, "fs-dl-01")
	got, err := c.DownloadRange(context.Background(), "uuid-abc", 5, -3)
	if err == nil {
		t.Fatalf("expected error on negative length, got nil with content %q", got)
	}
}

// TestDownloadRangePastEOF verifies that a length extending past EOF is clamped
// to the remaining bytes rather than panicking or over-reading (HI-02).
func TestDownloadRangePastEOF(t *testing.T) {
	content := []byte("abcdefghij") // 10 bytes
	sock := downloadRangeContentServer(t, content)
	c, _ := New(sock, "fs-dl-01")
	// Offset 7, length 100 → expect the final 3 bytes "hij".
	got, err := c.DownloadRange(context.Background(), "uuid-abc", 7, 100)
	if err != nil {
		t.Fatalf("DownloadRange past EOF: %v", err)
	}
	if want := content[7:]; !bytes.Equal(got, want) {
		t.Errorf("range past EOF: got %q, want %q", got, want)
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
