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

// TestUploadZeroByteSendsNoChunkFrame verifies the positive zero-byte upload
// boundary: a source that yields no bytes must produce exactly the params frame
// (flag 0x00) followed immediately by the end-stream frame (flag 0x02) — and NO
// chunk frame in between — and must complete successfully. An empty file is a
// real filesystem object; a spurious empty chunk frame or a missing end-stream
// terminator would either be rejected by the broker or leave the stream
// open-ended.
func TestUploadZeroByteSendsNoChunkFrame(t *testing.T) {
	type frame struct {
		flag    byte
		payload []byte
	}
	var frames []frame

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		for {
			fl, payload, err := readFrame(r.Body)
			if err != nil {
				break
			}
			frames = append(frames, frame{flag: fl, payload: payload})
		}
		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-zero-01")
	// A zero-length source with declared size 0 — an empty-file upload.
	if err := c.Upload(context.Background(), "/empty.txt", bytes.NewReader(nil), 0, false); err != nil {
		t.Fatalf("zero-byte upload must succeed: %v", err)
	}

	if len(frames) != 2 {
		t.Fatalf("zero-byte upload sent %d frames, want exactly 2 (params + end-stream)", len(frames))
	}
	// Frame 1: the params frame (flag 0x00) carrying declared_size_bytes 0.
	if frames[0].flag != 0x00 {
		t.Errorf("frame 0 flag: got 0x%02x, want 0x00 (params)", frames[0].flag)
	}
	var params struct {
		DeclaredSizeBytes int64 `json:"declared_size_bytes"`
	}
	if err := json.Unmarshal(frames[0].payload, &params); err != nil {
		t.Fatalf("frame 0 is not a params frame: %v", err)
	}
	if params.DeclaredSizeBytes != 0 {
		t.Errorf("declared_size_bytes: got %d, want 0", params.DeclaredSizeBytes)
	}
	// Frame 2: the end-stream terminator (flag 0x02) — NOT a chunk frame.
	if frames[1].flag != endStreamFlag {
		t.Errorf("frame 1 flag: got 0x%02x, want 0x%02x (end-stream)", frames[1].flag, endStreamFlag)
	}
	var esr EndStreamResponse
	if err := json.Unmarshal(frames[1].payload, &esr); err != nil {
		t.Fatalf("frame 1 is not an EndStreamResponse: %v", err)
	}
	if esr.Error != nil {
		t.Errorf("request-side end-stream carried an error %+v, want empty {}", esr.Error)
	}
}

// TestDownloadRangeOffsetAtSizeLengthZero verifies the empty-window boundary:
// a DownloadRange at offset == size with length 0 must return an empty (zero
// length) slice and no error. This is the tail-of-file empty read the VFS
// issues at EOF; it must not error or over-read.
func TestDownloadRangeOffsetAtSizeLengthZero(t *testing.T) {
	content := []byte("abcdefghij") // size 10
	sock := emptyWindowDownloadServer(t, content)

	c, _ := New(sock, "fs-edge-01")
	got, err := c.DownloadRange(context.Background(), "uuid-eof", int64(len(content)), 0)
	if err != nil {
		t.Fatalf("DownloadRange at EOF with length 0: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty window: got %d bytes (%q), want 0", len(got), got)
	}
}

// emptyWindowDownloadServer serves only the windowed bytes selected by the
// request range, honouring offset == size and length 0 as a genuine empty
// window (returning a single zero-length data frame, then the success trailer).
// It models the broker's behaviour for a tail read at EOF.
func emptyWindowDownloadServer(t *testing.T, content []byte) string {
	t.Helper()
	return uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, payload, _ := readFrame(r.Body)
		_, _ = io.ReadAll(r.Body)
		var req struct {
			Range *Range `json:"range"`
		}
		_ = json.Unmarshal(payload, &req)

		out := content
		if req.Range != nil {
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

// TestListDirectoryAllZeroEntriesSinglePage verifies the empty-listing boundary
// for the recursive listDirectory path: a single page carrying zero entries and
// an empty cursor must terminate after exactly ONE call and return a usable
// (non-nil-deref) result of length zero — never a hang, never an extra page
// fetch, never a panic when the caller ranges over it.
func TestListDirectoryAllZeroEntriesSinglePage(t *testing.T) {
	var callCount int
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = io.ReadAll(r.Body)
		// Empty page: no entries, no cursor.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	c, _ := New(sock, "fs-empty-01")
	entries, err := c.ListDirectoryAll(context.Background(), "/")
	if err != nil {
		t.Fatalf("ListDirectoryAll on empty page: %v", err)
	}
	if callCount != 1 {
		t.Errorf("empty cursor must terminate after one call, got %d calls", callCount)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
	// The result must be range-safe (non-nil-deref): iterating it is a no-op.
	for range entries {
		t.Error("ranged over a supposedly empty entry list")
	}
}

// TestListFilesAllZeroEntriesSinglePage verifies the same empty-listing
// boundary for the uuid-paginated listFiles path: zero files plus an empty
// after_uuid must terminate after exactly one call with a range-safe empty
// result.
func TestListFilesAllZeroEntriesSinglePage(t *testing.T) {
	var callCount int
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	c, _ := New(sock, "fs-empty-02")
	files, err := c.ListFilesAll(context.Background(), "root-uuid")
	if err != nil {
		t.Fatalf("ListFilesAll on empty page: %v", err)
	}
	if callCount != 1 {
		t.Errorf("empty after_uuid must terminate after one call, got %d calls", callCount)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
	for range files {
		t.Error("ranged over a supposedly empty file list")
	}
}
