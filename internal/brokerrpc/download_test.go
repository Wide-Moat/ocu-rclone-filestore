// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rclone/rclone/fs/fserrors"
)

// readDownloadRequest decodes the JSON fileDownload request body.
func readDownloadRequest(t *testing.T, r *http.Request) FileDownloadRequest {
	t.Helper()
	body, _ := io.ReadAll(r.Body)
	var req FileDownloadRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("parse download request: %v", err)
	}
	return req
}

// chunkedOctetStream writes content as an application/octet-stream body in a few
// flushed chunks so the client exercises chunked reassembly.
func chunkedOctetStream(w http.ResponseWriter, content []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	const chunk = 4
	for i := 0; i < len(content); i += chunk {
		end := i + chunk
		if end > len(content) {
			end = len(content)
		}
		_, _ = w.Write(content[i:end])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// TestDownloadRouteHeadersAndAuthMetadata verifies fileDownload POSTs to the
// REST route with the Bearer header, addresses by uuid (not path), and carries
// authorization_metadata{intent:read, downloadable:false}.
func TestDownloadRouteHeadersAndAuthMetadata(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var req FileDownloadRequest

	c, _ := newTLSTestClient(t, "fs-dl-01", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		req = readDownloadRequest(t, r)
		chunkedOctetStream(w, []byte("x"))
	})

	_, _ = c.Download(context.Background(), "uuid-test-42")

	if gotPath != "/v1/filestore/fs/fileDownload" {
		t.Errorf("path = %q, want /v1/filestore/fs/fileDownload", gotPath)
	}
	if gotAuth != "Bearer "+testAuthToken {
		t.Errorf("Authorization = %q, want Bearer %s", gotAuth, testAuthToken)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if req.UUID != "uuid-test-42" {
		t.Errorf("uuid = %q, want uuid-test-42", req.UUID)
	}
	if req.AuthorizationMetadata.Intent != "read" {
		t.Errorf("intent = %q, want read", req.AuthorizationMetadata.Intent)
	}
	if req.AuthorizationMetadata.Downloadable {
		t.Error("downloadable = true, must be false")
	}
	if req.FilesystemID == "" {
		t.Error("filesystem_id must be set")
	}
}

// TestDownloadFullReassembly verifies the chunked octet-stream body reassembles
// into the complete content.
func TestDownloadFullReassembly(t *testing.T) {
	content := []byte("hello world, this spans several chunks")
	c, _ := newTLSTestClient(t, "fs-dl-02", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		chunkedOctetStream(w, content)
	})
	got, err := c.Download(context.Background(), "uuid-abc")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

// TestDownloadRangeSendsRangeAndReturnsWindow verifies DownloadRange puts the
// {offset,length} on the wire and returns the window; a full Download serialises
// no range field.
func TestDownloadRangeSendsRangeAndReturnsWindow(t *testing.T) {
	content := []byte("abcdefghij") // 10 bytes
	c, _ := newTLSTestClient(t, "fs-dl-03", func(w http.ResponseWriter, r *http.Request) {
		req := readDownloadRequest(t, r)
		out := content
		if req.Range != nil {
			off := req.Range.Offset
			end := off + req.Range.Length
			if off > int64(len(content)) {
				off = int64(len(content))
			}
			if end > int64(len(content)) {
				end = int64(len(content))
			}
			out = content[off:end]
		}
		chunkedOctetStream(w, out)
	})

	got, err := c.DownloadRange(context.Background(), "uuid-abc", 2, 3)
	if err != nil {
		t.Fatalf("DownloadRange: %v", err)
	}
	if want := content[2:5]; !bytes.Equal(got, want) {
		t.Errorf("range slice = %q, want %q", got, want)
	}
}

// TestDownloadRangeRequestShape verifies the range is serialised on a ranged
// request and absent on a full one.
func TestDownloadRangeRequestShape(t *testing.T) {
	var rangeReq, fullReq FileDownloadRequest

	cr, _ := newTLSTestClient(t, "fs-dl-04", func(w http.ResponseWriter, r *http.Request) {
		rangeReq = readDownloadRequest(t, r)
		chunkedOctetStream(w, []byte("z"))
	})
	_, _ = cr.DownloadRange(context.Background(), "uuid-abc", 4, 6)
	if rangeReq.Range == nil {
		t.Fatal("DownloadRange request carried no range field")
	}
	if rangeReq.Range.Offset != 4 || rangeReq.Range.Length != 6 {
		t.Errorf("range = {%d,%d}, want {4,6}", rangeReq.Range.Offset, rangeReq.Range.Length)
	}

	cf, _ := newTLSTestClient(t, "fs-dl-05", func(w http.ResponseWriter, r *http.Request) {
		fullReq = readDownloadRequest(t, r)
		chunkedOctetStream(w, []byte("z"))
	})
	_, _ = cf.Download(context.Background(), "uuid-abc")
	if fullReq.Range != nil {
		t.Errorf("full Download carried a range field %+v, want none", fullReq.Range)
	}
}

// TestDownloadRangeClampsOverDelivery verifies the defensive clamp trims a
// broker that streamed more than the requested length.
func TestDownloadRangeClampsOverDelivery(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-dl-06", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		chunkedOctetStream(w, []byte("abcdefghij")) // ignores range, returns 10
	})
	got, err := c.DownloadRange(context.Background(), "uuid-abc", 0, 3)
	if err != nil {
		t.Fatalf("DownloadRange: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("over-delivery not clamped: got %d bytes, want 3", len(got))
	}
}

// TestDownloadNotFoundMapsSentinel verifies a 404 maps to ErrNotFound.
func TestDownloadNotFoundMapsSentinel(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-dl-07", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("uuid missing"))
	})
	_, err := c.Download(context.Background(), "uuid-gone")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("404 must map to ErrNotFound; got %v", err)
	}
}

// TestDownloadThrottledIsRetryable verifies a 429 on download is retryable.
func TestDownloadThrottledIsRetryable(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-dl-08", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("throttled"))
	})
	_, err := c.Download(context.Background(), "uuid-busy")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Errorf("429 download must be retryable: %v", err)
	}
}

// TestDownloadRangePastEOF verifies a length past EOF is clamped server-side and
// returned without over-read.
func TestDownloadRangePastEOF(t *testing.T) {
	content := []byte("abcdefghij")
	c, _ := newTLSTestClient(t, "fs-dl-09", func(w http.ResponseWriter, r *http.Request) {
		req := readDownloadRequest(t, r)
		out := content
		if req.Range != nil {
			off := req.Range.Offset
			end := off + req.Range.Length
			if off > int64(len(content)) {
				off = int64(len(content))
			}
			if end > int64(len(content)) {
				end = int64(len(content))
			}
			out = content[off:end]
		}
		chunkedOctetStream(w, out)
	})
	got, err := c.DownloadRange(context.Background(), "uuid-abc", 7, 100)
	if err != nil {
		t.Fatalf("DownloadRange past EOF: %v", err)
	}
	if want := content[7:]; !bytes.Equal(got, want) {
		t.Errorf("range past EOF: got %q, want %q", got, want)
	}
}

// TestDownloadRangeEmptyWindow verifies offset==size, length 0 returns empty.
func TestDownloadRangeEmptyWindow(t *testing.T) {
	content := []byte("abcdefghij")
	c, _ := newTLSTestClient(t, "fs-dl-10", func(w http.ResponseWriter, r *http.Request) {
		req := readDownloadRequest(t, r)
		out := []byte{}
		if req.Range != nil {
			off := req.Range.Offset
			end := off + req.Range.Length
			if off > int64(len(content)) {
				off = int64(len(content))
			}
			if end > int64(len(content)) {
				end = int64(len(content))
			}
			out = content[off:end]
		}
		chunkedOctetStream(w, out)
	})
	got, err := c.DownloadRange(context.Background(), "uuid-eof", int64(len(content)), 0)
	if err != nil {
		t.Fatalf("DownloadRange empty window: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty window: got %d bytes (%q), want 0", len(got), got)
	}
}

// TestDownloadThrottledTypedRetryAfter asserts the 429 download path produces a
// retryable error that carries the broker's Retry-After deadline (not merely a
// non-nil error): doDownload's non-2xx arm hands the status, body, and
// Retry-After through MapHTTPStatus, and a positive in-bound hint becomes an
// ErrorRetryAfter the upstream pacer can honour.
func TestDownloadThrottledTypedRetryAfter(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-dl-throttle-ra", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("slow down"))
	})
	_, err := c.Download(context.Background(), "uuid-busy")
	if err == nil {
		t.Fatal("expected retryable error, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Fatalf("429 download must be retryable: %v", err)
	}
	if !fserrors.IsRetryAfterError(err) {
		t.Errorf("expected a Retry-After deadline on the 429 download, got %v", err)
	}
	if when := fserrors.RetryAfterErrorTime(err); when.IsZero() {
		t.Errorf("expected a non-zero Retry-After time on the 429 download, got zero")
	}
}

// TestDownloadServiceUnavailableIsRetryable asserts a 503 on download maps to a
// retryable error (the second backpressure-class status), with no Retry-After
// honoured on this status.
func TestDownloadServiceUnavailableIsRetryable(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-dl-503", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	})
	_, err := c.Download(context.Background(), "uuid-503")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Errorf("503 download must be retryable: %v", err)
	}
}

// TestDownloadBodyReadFailureSurfaces drives doDownload's io.ReadAll error arm:
// a 2xx handler that promises a long Content-Length but writes fewer bytes and
// hangs up makes the body read fail with an unexpected EOF, which must surface as
// a read-body error rather than a silent short success (silent truncation would
// be file corruption on a FUSE-backed mount).
func TestDownloadBodyReadFailureSurfaces(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-dl-shortbody", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		// Promise more than we deliver, then hang up mid-body.
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, herr := hj.Hijack()
			if herr == nil {
				_ = conn.Close()
			}
		}
	})
	_, err := c.Download(context.Background(), "uuid-short")
	if err == nil {
		t.Fatal("expected a body-read error from a truncated stream, got nil")
	}
	if !strings.Contains(err.Error(), "fileDownload") {
		t.Errorf("error %q does not name fileDownload", err.Error())
	}
}
