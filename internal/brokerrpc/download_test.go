// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
// (DownloadRange) sends the {offset, length} window in the request so the
// broker streams only that window, and returns exactly those bytes — NOT the
// unary readFile op. The test server is range-aware: it reads the range from
// the request params frame and streams only the windowed bytes, the real
// broker's ranged behaviour. This both proves the helper transmits the range
// (a server that ignored it would return the whole object and fail the slice
// assertion) and that the returned content is the window.
func TestDownloadRangeHelper(t *testing.T) {
	content := []byte("abcdefghij") // 10 bytes

	sock := rangeAwareDownloadServer(t, content)

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

// TestDownloadRangeRequestCarriesRange verifies that DownloadRange puts the
// requested window on the wire as a non-nil range{offset,length}, while a full
// Download serialises no range field at all (so the full-download request body
// stays byte-identical to the no-range form).
func TestDownloadRangeRequestCarriesRange(t *testing.T) {
	var rangeReq, fullReq []byte

	mk := func(capture *[]byte) string {
		return uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, payload, _ := readFrame(r.Body)
			*capture = payload
			var buf bytes.Buffer
			frame, _ := json.Marshal(map[string][]byte{"data": []byte("z")})
			_ = writeFrame(&buf, 0x00, frame)
			_ = writeEndStream(&buf, nil)
			w.Header().Set("Content-Type", "application/connect+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(buf.Bytes())
		})
	}

	cr, _ := New(mk(&rangeReq), "fs-dl-01")
	_, _ = cr.DownloadRange(context.Background(), "uuid-abc", 4, 6)
	cf, _ := New(mk(&fullReq), "fs-dl-01")
	_, _ = cf.Download(context.Background(), "uuid-abc")

	var ranged struct {
		Range *Range `json:"range"`
	}
	if err := json.Unmarshal(rangeReq, &ranged); err != nil {
		t.Fatalf("parse ranged request: %v", err)
	}
	if ranged.Range == nil {
		t.Fatal("DownloadRange request carried no range field")
	}
	if ranged.Range.Offset != 4 || ranged.Range.Length != 6 {
		t.Errorf("range: got {offset:%d length:%d}, want {4 6}", ranged.Range.Offset, ranged.Range.Length)
	}

	var full struct {
		Range *Range `json:"range"`
	}
	if err := json.Unmarshal(fullReq, &full); err != nil {
		t.Fatalf("parse full request: %v", err)
	}
	if full.Range != nil {
		t.Errorf("full Download request carried a range field %+v, want none", full.Range)
	}
}

// TestDownloadRangeClampsOverDelivery verifies the defensive clamp: a broker
// that ignores the range and streams MORE than the requested length is trimmed
// to the contract length, so the caller never sees over-delivery.
func TestDownloadRangeClampsOverDelivery(t *testing.T) {
	// Server ignores the range and returns the whole 10-byte object.
	sock := downloadRangeContentServer(t, []byte("abcdefghij"))
	c, _ := New(sock, "fs-dl-01")
	// Ask for 3 bytes; an over-delivering broker returns 10. The clamp trims
	// to the first 3 of what was streamed (offset already applied broker-side
	// when honoured; here it was not, so this documents the trim-only guard).
	got, err := c.DownloadRange(context.Background(), "uuid-abc", 0, 3)
	if err != nil {
		t.Fatalf("DownloadRange: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("over-delivery not clamped: got %d bytes, want 3", len(got))
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
// content frame followed by a success trailer, IGNORING any requested range.
// It models a broker that streams the whole object regardless of range, used to
// exercise the helper's defensive over-delivery clamp.
func downloadRangeContentServer(t *testing.T, content []byte) string {
	t.Helper()
	return uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		frame, _ := json.Marshal(map[string][]byte{"data": content})
		_ = writeFrame(&buf, 0x00, frame)
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
}

// rangeAwareDownloadServer serves only the windowed bytes of content selected
// by the request's range{offset,length}, the real broker's ranged behaviour: a
// nil/zero range streams the whole object; a non-nil range streams content
// clamped to [offset, offset+length). offset is applied server-side, so the
// streamed bytes already begin at offset.
func rangeAwareDownloadServer(t *testing.T, content []byte) string {
	t.Helper()
	return uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, payload, _ := readFrame(r.Body)
		_, _ = io.ReadAll(r.Body)
		var req struct {
			Range *Range `json:"range"`
		}
		_ = json.Unmarshal(payload, &req)

		out := content
		if req.Range != nil && (req.Range.Offset != 0 || req.Range.Length != 0) {
			off := req.Range.Offset
			if off > int64(len(content)) {
				off = int64(len(content))
			}
			end := off + req.Range.Length
			if end > int64(len(content)) {
				end = int64(len(content))
			}
			out = content[off:end]
		}

		var buf bytes.Buffer
		frame, _ := json.Marshal(map[string][]byte{"data": out})
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
	sock := rangeAwareDownloadServer(t, content)
	c, _ := New(sock, "fs-dl-01")
	// Offset 7, length 100 → the broker clamps to the final 3 bytes "hij".
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
