// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/rclone/rclone/fs/fserrors"
)

// uploadTestServer runs a minimal HTTP server over a unix socket and invokes
// handler for each request. It returns the socket path. The server is closed
// when t.Cleanup runs.
func uploadTestServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "brpc")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	sock := dir + "/b.sock"
	t.Cleanup(func() { os.RemoveAll(dir) })

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen unix %s: %v", sock, err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// TestUploadStreamRouteAndHeaders checks that the fileUpload POST goes to the
// correct route with Content-Type application/connect+json and
// Connect-Protocol-Version: 1.
func TestUploadStreamRouteAndHeaders(t *testing.T) {
	var gotPath, gotCT, gotProto string
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotProto = r.Header.Get("Connect-Protocol-Version")
		// Write a minimal success end-stream frame.
		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-test-01")
	payload := bytes.NewReader([]byte("hello"))
	_ = c.Upload(context.Background(), "/a.txt", payload, 5, false)

	wantPath := "/ocu.filestore.v1alpha.FilesystemService/fileUpload"
	if gotPath != wantPath {
		t.Errorf("path: got %q, want %q", gotPath, wantPath)
	}
	wantCT := "application/connect+json"
	if gotCT != wantCT {
		t.Errorf("Content-Type: got %q, want %q", gotCT, wantCT)
	}
	if gotProto != "1" {
		t.Errorf("Connect-Protocol-Version: got %q, want %q", gotProto, "1")
	}
}

// TestUploadParamsFrameDeclaredSizeBytes checks that the first frame is a
// params frame carrying the correct declared_size_bytes.
func TestUploadParamsFrameDeclaredSizeBytes(t *testing.T) {
	var paramsData []byte
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Read all frames from the request body.
		flag, payload, err := readFrame(r.Body)
		if err != nil {
			t.Errorf("read params frame: %v", err)
			return
		}
		if flag != 0x00 {
			t.Errorf("params frame flag: want 0x00, got 0x%02x", flag)
		}
		paramsData = payload
		// Drain rest of body.
		_, _ = io.ReadAll(r.Body)

		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	content := []byte("hello world") // 11 bytes
	c, _ := New(sock, "fs-test-01")
	_ = c.Upload(context.Background(), "/b.txt", bytes.NewReader(content), int64(len(content)), false)

	var params struct {
		DeclaredSizeBytes int64                 `json:"declared_size_bytes"`
		OverwriteExisting bool                  `json:"overwrite_existing"`
		AuthMetadata      AuthorizationMetadata `json:"authorization_metadata"`
	}
	if err := json.Unmarshal(paramsData, &params); err != nil {
		t.Fatalf("parse params: %v", err)
	}
	if params.DeclaredSizeBytes != int64(len(content)) {
		t.Errorf("declared_size_bytes: got %d, want %d", params.DeclaredSizeBytes, len(content))
	}
	// This call passed overwrite=false (create-new write); the field must
	// round-trip on the params frame.
	if params.OverwriteExisting {
		t.Error("overwrite_existing: got true, want false for a create-new upload")
	}
	if params.AuthMetadata.Intent != "write" {
		t.Errorf("params auth intent: got %q, want %q", params.AuthMetadata.Intent, "write")
	}
	if params.AuthMetadata.Downloadable {
		t.Error("params auth downloadable: must be false")
	}
}

// TestUploadChunkFramesTotalExact verifies that the chunker sends exactly
// declared_size_bytes across all chunk frames.
func TestUploadChunkFramesTotalExact(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 100)
	var totalChunkBytes int

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Skip params frame.
		_, _, err := readFrame(r.Body)
		if err != nil {
			t.Errorf("read params frame: %v", err)
			return
		}
		// Read chunk frames until half-close (EOF) or end-stream.
		for {
			flag, payload, err := readFrame(r.Body)
			if err != nil {
				break
			}
			if flag == endStreamFlag {
				break
			}
			var chunk struct {
				Chunk []byte `json:"chunk"`
			}
			if jsonErr := json.Unmarshal(payload, &chunk); jsonErr == nil {
				totalChunkBytes += len(chunk.Chunk)
			}
		}

		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-test-01")
	_ = c.Upload(context.Background(), "/c.txt", bytes.NewReader(content), int64(len(content)), false)

	if totalChunkBytes != len(content) {
		t.Errorf("total chunk bytes: got %d, want %d", totalChunkBytes, len(content))
	}
}

// TestUploadCeilingChunksUnderLimit verifies that a payload larger than the
// message ceiling is split into multiple frames and that the ENCODED frame
// payload — the base64-plus-JSON-envelope bytes actually put on the wire, the
// thing the broker measures against the ceiling (D4) — stays strictly under
// the ceiling. The previous version of this test only checked the *decoded*
// chunk length and waved away the envelope, so it did not pin the real
// invariant; base64 inflation pushed every full frame ~4/3 over the ceiling.
func TestUploadCeilingChunksUnderLimit(t *testing.T) {
	const ceiling = 64                                // small test ceiling
	content := bytes.Repeat([]byte("a"), ceiling*3+7) // definitely >1 frame
	var frameCount int
	var maxFramePayload int

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Skip params frame.
		_, _, _ = readFrame(r.Body)
		for {
			flag, payload, err := readFrame(r.Body)
			if err != nil {
				break
			}
			if flag == endStreamFlag {
				break
			}
			// Measure the ENCODED frame payload (what the broker sees), not
			// the decoded chunk bytes.
			frameCount++
			if len(payload) > maxFramePayload {
				maxFramePayload = len(payload)
			}
			if len(payload) >= ceiling {
				t.Errorf("encoded frame payload %d bytes is not strictly under ceiling %d", len(payload), ceiling)
			}
		}

		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := NewWithOptions(sock, "fs-test-01", ClientOptions{MessageCeiling: ceiling})
	_ = c.Upload(context.Background(), "/d.txt", bytes.NewReader(content), int64(len(content)), false)

	if frameCount <= 1 {
		t.Errorf("expected >1 chunk frame for payload larger than ceiling, got %d", frameCount)
	}
	if maxFramePayload == 0 {
		t.Error("no chunk frames observed")
	}
}

// TestUploadResourceExhaustedIsRetryable verifies that a resource_exhausted
// EndStreamResponse from the broker maps to a retryable error (backpressure),
// not a permanent error.
func TestUploadResourceExhaustedIsRetryable(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		connErr := &ConnectError{Code: "resource_exhausted", Message: "throttled"}
		_ = writeEndStream(&buf, connErr)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-test-01")
	err := c.Upload(context.Background(), "/e.txt", bytes.NewReader([]byte("x")), 1, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Errorf("resource_exhausted from EndStream must be retryable: %v", err)
	}
}

// TestUploadToleratesResponseMessageFrame verifies that a successful upload
// where the broker emits the optional response message frame (data flag 0x00,
// a FileUploadResponse) before the end-stream trailer is accepted — the
// standard Connect client-streaming success shape (MD-02). Reading the trailer
// directly would have hard-failed on the leading 0x00 frame.
func TestUploadToleratesResponseMessageFrame(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		// Optional response message frame (flag 0x00) before the trailer.
		msg, _ := json.Marshal(FileUploadResponse{File: FilesystemFile{Path: "/g.txt", Size: 1}})
		_ = writeFrame(&buf, 0x00, msg)
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-test-01")
	err := c.Upload(context.Background(), "/g.txt", bytes.NewReader([]byte("x")), 1, false)
	if err != nil {
		t.Fatalf("upload with leading response message frame must succeed: %v", err)
	}
}

// TestUploadEarlyTrailerSurvivesPipeError verifies that when the broker
// terminates the upload early with a resource_exhausted trailer without
// draining the request body (the SEC-46 throttle case), the retryable trailer
// verdict survives to the caller and is NOT masked by the io.ErrClosedPipe
// write error (CR-02). The payload is large enough that the writer goroutine
// is still streaming when the broker replies and closes the request body.
func TestUploadEarlyTrailerSurvivesPipeError(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Reply immediately WITHOUT draining the request body, so the
		// transport closes the pipe under the still-writing goroutine.
		var buf bytes.Buffer
		connErr := &ConnectError{Code: "resource_exhausted", Message: "throttled mid-stream"}
		_ = writeEndStream(&buf, connErr)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	// 8 MiB of source — far larger than the default 256 KiB ceiling, so the
	// writer goroutine is mid-stream when the broker replies.
	big := bytes.Repeat([]byte("a"), 8*1024*1024)
	c, _ := New(sock, "fs-test-01")
	err := c.Upload(context.Background(), "/big.bin", bytes.NewReader(big), int64(len(big)), false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Errorf("early resource_exhausted trailer must surface as retryable, not be masked by the pipe error: %v", err)
	}
}

// TestUploadSizeMismatchIsPermanent verifies that a broker invalid_argument
// (size_exceeded) response maps to a permanent no-retry error.
func TestUploadSizeMismatchIsPermanent(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		connErr := &ConnectError{Code: "invalid_argument", Message: "size_exceeded"}
		_ = writeEndStream(&buf, connErr)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-test-01")
	err := c.Upload(context.Background(), "/f.txt", bytes.NewReader([]byte("x")), 99, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if fserrors.IsRetryError(err) {
		t.Errorf("size_exceeded from EndStream must NOT be retryable: %v", err)
	}
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("size_exceeded: errors.Is(ErrInvalidArgument) false")
	}
}

// TestUploadSendsTerminatingEndStreamFrame verifies that the upload request
// body ends with an explicit end-stream frame (flag 0x02) carrying an empty
// EndStreamResponse {}, not a bare body half-close. The Connect
// client-streaming protocol uses this frame as the completion signal: without
// it the broker keeps waiting on a frame that never arrives and then aborts the
// already-assembled stream as malformed, so a retry sees the object as already
// present. This test reads every frame of the request body and asserts the LAST
// one is the 0x02 {} terminator after all data frames.
func TestUploadSendsTerminatingEndStreamFrame(t *testing.T) {
	var lastFlag byte
	var lastPayload []byte
	var sawEndStream bool

	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		for {
			flag, payload, err := readFrame(r.Body)
			if err != nil {
				break
			}
			lastFlag = flag
			lastPayload = payload
			if flag == endStreamFlag {
				sawEndStream = true
			}
		}
		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	content := bytes.Repeat([]byte("z"), 40)
	c, _ := New(sock, "fs-test-01")
	if err := c.Upload(context.Background(), "/term.txt", bytes.NewReader(content), int64(len(content)), false); err != nil {
		t.Fatalf("upload: %v", err)
	}

	if !sawEndStream {
		t.Fatal("upload request body never sent an end-stream frame (flag 0x02)")
	}
	if lastFlag != endStreamFlag {
		t.Errorf("final request frame flag: got 0x%02x, want 0x%02x (end-stream must be last)", lastFlag, endStreamFlag)
	}
	// The empty EndStreamResponse {} is the success terminator the broker
	// expects: an error trailer on the REQUEST side would be wrong.
	var esr EndStreamResponse
	if err := json.Unmarshal(lastPayload, &esr); err != nil {
		t.Fatalf("terminating frame payload is not a valid EndStreamResponse: %v", err)
	}
	if esr.Error != nil {
		t.Errorf("terminating frame carried an error %+v, want empty {}", esr.Error)
	}
}

// TestUploadOverwriteTrueRoundTrips verifies that an overwrite-in-place upload
// (Update's path) sets overwrite_existing=true on the params frame.
func TestUploadOverwriteTrueRoundTrips(t *testing.T) {
	var paramsData []byte
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, payload, err := readFrame(r.Body)
		if err != nil {
			t.Errorf("read params frame: %v", err)
			return
		}
		paramsData = payload
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})

	c, _ := New(sock, "fs-test-01")
	if err := c.Upload(context.Background(), "/ow.txt", bytes.NewReader([]byte("y")), 1, true); err != nil {
		t.Fatalf("upload: %v", err)
	}

	var params struct {
		OverwriteExisting bool `json:"overwrite_existing"`
	}
	if err := json.Unmarshal(paramsData, &params); err != nil {
		t.Fatalf("parse params: %v", err)
	}
	if !params.OverwriteExisting {
		t.Error("overwrite_existing: got false, want true for an overwrite-in-place upload")
	}
}
