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
	"sync/atomic"
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

// TestDownloadRangeZeroLengthWindowIsEmptyReadWithoutRPC pins the length-0
// short-circuit: a zero-length window is trivially the empty read (the POSIX
// at-EOF answer — Object.Open clamps at/past-EOF windows to length 0), and this
// broker family reads a length-0 fileDownload as "full file", so issuing the
// RPC would stream the whole object only to discard it. DownloadRange must
// return an immediately-EOF reader without touching the wire.
func TestDownloadRangeZeroLengthWindowIsEmptyReadWithoutRPC(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTLSTestClient(t, "fs-dl-zerowin", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.ReadAll(r.Body)
		// The broker family's length-0 semantics: the full file comes back.
		chunkedOctetStream(w, []byte("abcdefghij"))
	})
	rc, err := c.DownloadRange(context.Background(), "uuid-zerowin", 5, 0)
	if err != nil {
		t.Fatalf("DownloadRange length 0: %v", err)
	}
	got, err := readAllClose(t, rc)
	if err != nil {
		t.Fatalf("zero-length window read: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("zero-length window delivered %d bytes (%q), want 0", len(got), got)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("zero-length window issued %d fileDownload RPCs, want 0 — the empty window needs no wire call", n)
	}
}

// TestDownloadRangeOverDeliveryIsAnError pins the fail-closed window bound: the
// wire carries no range echo (the fileDownload response field set is TBD in the
// frozen contract), so the requested offset itself is unverifiable — but byte
// count is. A broker that ignores the range and streams from byte 0
// over-delivers whenever the requested window ends before EOF, so over-delivery
// must surface as an ERROR, never as a silent truncation that relabels the
// object's head as the requested window (wrong bytes passed to the VFS as a
// successful read). This deliberately reverses the earlier truncate-to-window
// behaviour.
func TestDownloadRangeOverDeliveryIsAnError(t *testing.T) {
	content := bytes.Repeat([]byte("Z"), 100)

	t.Run("declared_length_fast_fail", func(t *testing.T) {
		// The response declares its full length up front (the harness south
		// face answers ranged downloads with a plain 200 + Content-Length), so
		// the dishonoured range is provable before any body byte is read.
		c, _ := newTLSTestClient(t, "fs-dl-over-cl", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
		})
		rc, err := c.DownloadRange(context.Background(), "uuid-over-cl", 50, 10)
		if err == nil {
			got, rerr := readAllClose(t, rc)
			t.Fatalf("a declared 100-byte body for a 10-byte window must fail, got a reader (read %d bytes, read err %v)", len(got), rerr)
		}
		if !strings.Contains(err.Error(), "window") {
			t.Errorf("error %q does not name the dishonoured window", err.Error())
		}
	})

	t.Run("chunked_overdelivery_errors_on_read", func(t *testing.T) {
		// No declared length (chunked): over-delivery is only observable while
		// streaming, so the error must surface from the reader, and the caller
		// must never see a clean EOF carrying just the window-sized prefix.
		c, _ := newTLSTestClient(t, "fs-dl-over-chunk", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			chunkedOctetStream(w, content)
		})
		rc, err := c.DownloadRange(context.Background(), "uuid-over-chunk", 50, 10)
		if err != nil {
			t.Fatalf("DownloadRange with an undeclared-length response must hand out a reader: %v", err)
		}
		got, err := readAllClose(t, rc)
		if err == nil {
			t.Fatalf("reading a 100-byte stream for a 10-byte window must error, got clean EOF with %d bytes", len(got))
		}
		if !strings.Contains(err.Error(), "over-delivered") {
			t.Errorf("error %q does not name the over-delivery", err.Error())
		}
	})

	t.Run("offset_zero_overdelivery_still_errors", func(t *testing.T) {
		// The offset-0 flavour of the same dishonour (previously pinned as
		// silent truncation): a broker returning the whole object for a
		// 3-byte window at offset 0 must also fail on read.
		c, _ := newTLSTestClient(t, "fs-dl-over-zero", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			chunkedOctetStream(w, []byte("abcdefghij"))
		})
		rc, err := c.DownloadRange(context.Background(), "uuid-over-zero", 0, 3)
		if err != nil {
			t.Fatalf("DownloadRange: %v", err)
		}
		if got, err := readAllClose(t, rc); err == nil {
			t.Fatalf("a 10-byte stream for a 3-byte window must error on read, got clean EOF with %d bytes", len(got))
		}
	})

	t.Run("honest_window_reads_clean", func(t *testing.T) {
		// Control: a broker delivering exactly the window reads clean to EOF —
		// the strict bound must not misfire on an honest range.
		c, _ := newTLSTestClient(t, "fs-dl-honest", func(w http.ResponseWriter, r *http.Request) {
			req := readDownloadRequest(t, r)
			if req.Range == nil {
				t.Error("ranged request carried no range field")
				chunkedOctetStream(w, nil)
				return
			}
			chunkedOctetStream(w, content[req.Range.Offset:req.Range.Offset+req.Range.Length])
		})
		rc, err := c.DownloadRange(context.Background(), "uuid-honest", 50, 10)
		if err != nil {
			t.Fatalf("DownloadRange: %v", err)
		}
		got, err := readAllClose(t, rc)
		if err != nil {
			t.Fatalf("an honest 10-byte window must read clean, got %v", err)
		}
		if len(got) != 10 {
			t.Errorf("honest window delivered %d bytes, want 10", len(got))
		}
	})
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
// landing exactly at the byte cap surfaces as an error: the cap-boundary
// one-byte probe must never relabel a mid-body fault as clean end-of-stream,
// or a truncated prefix of a larger object would pass to the caller as the
// complete file content.
func TestBoundedBodyPropagatesErrorAtCapBoundary(t *testing.T) {
	const limit = 8
	body := &scriptedBody{
		data: bytes.Repeat([]byte("D"), limit),
		tail: []scriptedRead{{n: 0, err: errors.New("connection reset mid-body")}},
	}
	bb := newBoundedBody(body, false, limit)
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
	bb := newBoundedBody(body, false, limit)
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
