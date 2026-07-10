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

// readAllClose drains a download ReadCloser to bytes and closes it. Download and
// DownloadRange now return a streaming reader, so a test that asserts on the
// content reads it here; a read error (e.g. a truncated stream) surfaces from
// io.ReadAll, mirroring how the real VFS caller observes it.
func readAllClose(t *testing.T, rc io.ReadCloser) ([]byte, error) {
	t.Helper()
	if rc == nil {
		return nil, nil
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

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
	rc, err := c.Download(context.Background(), "uuid-abc")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := readAllClose(t, rc)
	if err != nil {
		t.Fatalf("Download read: %v", err)
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

	rc, err := c.DownloadRange(context.Background(), "uuid-abc", 2, 3)
	if err != nil {
		t.Fatalf("DownloadRange: %v", err)
	}
	got, err := readAllClose(t, rc)
	if err != nil {
		t.Fatalf("DownloadRange read: %v", err)
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
	rc, err := c.DownloadRange(context.Background(), "uuid-abc", 0, 3)
	if err != nil {
		t.Fatalf("DownloadRange: %v", err)
	}
	got, err := readAllClose(t, rc)
	if err != nil {
		t.Fatalf("DownloadRange read: %v", err)
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
	rc, err := c.DownloadRange(context.Background(), "uuid-abc", 7, 100)
	if err != nil {
		t.Fatalf("DownloadRange past EOF: %v", err)
	}
	got, err := readAllClose(t, rc)
	if err != nil {
		t.Fatalf("DownloadRange past EOF read: %v", err)
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
	rc, err := c.DownloadRange(context.Background(), "uuid-eof", int64(len(content)), 0)
	if err != nil {
		t.Fatalf("DownloadRange empty window: %v", err)
	}
	got, err := readAllClose(t, rc)
	if err != nil {
		t.Fatalf("DownloadRange empty window read: %v", err)
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

// scriptedBody is an io.ReadCloser that first serves its data bytes, then
// replays the scripted tail results one Read at a time (a step with n == 1
// yields its payload byte), and finally reports io.EOF. It lets a test place
// an exact (n, err) sequence at the boundedBody cap boundary.
type scriptedBody struct {
	data []byte
	tail []scriptedRead
}

type scriptedRead struct {
	b   byte // payload byte when n == 1
	n   int
	err error
}

func (s *scriptedBody) Read(p []byte) (int, error) {
	if len(s.data) > 0 {
		n := copy(p, s.data)
		s.data = s.data[n:]
		return n, nil
	}
	if len(s.tail) == 0 {
		return 0, io.EOF
	}
	step := s.tail[0]
	s.tail = s.tail[1:]
	if step.n > 0 && len(p) > 0 {
		p[0] = step.b
		return 1, step.err
	}
	return 0, step.err
}

func (s *scriptedBody) Close() error { return nil }

// TestBoundedBodyPropagatesErrorAtCapBoundary pins that a transport failure
// landing exactly at the byte cap surfaces as an error: the strict path's
// one-byte probe must never relabel a mid-body fault as clean end-of-stream,
// or a truncated prefix of a larger object would pass to the caller as the
// complete file content.
func TestBoundedBodyPropagatesErrorAtCapBoundary(t *testing.T) {
	const limit = 8
	body := &scriptedBody{
		data: bytes.Repeat([]byte("D"), limit),
		tail: []scriptedRead{{n: 0, err: errors.New("connection reset mid-body")}},
	}
	bb := newBoundedBody(body, true, limit)
	got, err := io.ReadAll(bb)
	if len(got) != limit {
		t.Errorf("delivered %d in-cap bytes, want %d", len(got), limit)
	}
	if err == nil {
		t.Fatal("a transport failure at the cap boundary must surface, got clean EOF")
	}
	if !strings.Contains(err.Error(), "connection reset mid-body") {
		t.Errorf("error %q does not carry the underlying transport fault", err.Error())
	}
}

// TestBoundedBodyProbeRetriesTransientZeroRead pins that a legal transient
// (0, nil) probe result is retried until decisive per the io.Reader contract:
// over-cap bytes hidden behind one empty read must still trip the over-cap
// error, never clean EOF.
func TestBoundedBodyProbeRetriesTransientZeroRead(t *testing.T) {
	const limit = 8
	body := &scriptedBody{
		data: bytes.Repeat([]byte("D"), limit),
		tail: []scriptedRead{{n: 0, err: nil}, {n: 1, b: 'X', err: nil}},
	}
	bb := newBoundedBody(body, true, limit)
	got, err := io.ReadAll(bb)
	if err == nil {
		t.Fatalf("over-cap bytes behind a transient (0, nil) read must error, got clean EOF with %d bytes", len(got))
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error %q does not name the over-cap condition", err.Error())
	}
}

// TestDownloadBodyReadFailureSurfaces drives the streaming body-read error arm:
// a 2xx handler that promises a long Content-Length but writes fewer bytes and
// hangs up mid-body makes the body read fail with an unexpected EOF. Download
// now returns a streaming reader, so the error surfaces when the caller reads
// the stream (exactly where the real VFS caller sees it) rather than being
// swallowed as a silent short success — silent truncation would be file
// corruption on a FUSE-backed mount.
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
	rc, err := c.Download(context.Background(), "uuid-short")
	if err != nil {
		t.Fatalf("Download returned an error before streaming: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("expected a body-read error from a truncated stream, got nil")
	}
}
