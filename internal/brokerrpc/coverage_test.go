// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// White-box error-path coverage for the broker RPC client. These tests reach
// the failure branches that the happy-path tests do not: construction guards,
// the unary call helper's marshal/read/non-2xx branches, the REST upload/
// download error paths, the unknown-op intent path, and the dial-failure paths.
// Every assertion pins an observable behaviour (returned error identity,
// wrapped sentinel, or decoded bytes), never just touches a line.

package brokerrpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rclone/rclone/fs/fserrors"
)

// errReader is an io.Reader that returns a forced error on the first read,
// driving the upload source-read branch.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("errReader: forced read failure")
}

// unmarshalable is a value json.Marshal cannot encode (a function field), used
// to drive the marshal-error branch in call().
type unmarshalable struct {
	Fn func() `json:"fn"`
}

// ---------------------------------------------------------------------------
// NewWithOptions construction guards
// ---------------------------------------------------------------------------

func TestNewWithOptionsRejectsEmptyInputs(t *testing.T) {
	cert := unrelatedCAPEM(t)
	if _, err := NewWithOptions("", "fs", testAuthToken, cert, ClientOptions{}); err == nil {
		t.Error("empty serviceURL: expected error, got nil")
	}
	if _, err := NewWithOptions("https://b", "", testAuthToken, cert, ClientOptions{}); err == nil {
		t.Error("empty fsID: expected error, got nil")
	}
	if _, err := NewWithOptions("https://b", "fs", "", cert, ClientOptions{}); err == nil {
		t.Error("empty authToken: expected error, got nil")
	}
	if _, err := NewWithOptions("https://b", "fs", testAuthToken, nil, ClientOptions{}); err == nil {
		t.Error("empty caCertPEM: expected error, got nil")
	}
	// Valid: default ceiling applies.
	c, err := NewWithOptions("https://b", "fs", testAuthToken, cert, ClientOptions{})
	if err != nil {
		t.Fatalf("valid construction: %v", err)
	}
	if c.messageCeiling != defaultMessageCeiling {
		t.Errorf("default ceiling: got %d, want %d", c.messageCeiling, defaultMessageCeiling)
	}
	// Explicit positive ceiling overrides the default.
	c2, err := NewWithOptions("https://b", "fs", testAuthToken, cert, ClientOptions{MessageCeiling: 4096})
	if err != nil {
		t.Fatalf("valid construction with ceiling: %v", err)
	}
	if c2.messageCeiling != 4096 {
		t.Errorf("explicit ceiling: got %d, want 4096", c2.messageCeiling)
	}
}

// TestOpURLBuildsRESTPath verifies opURL handles a trailing slash on the
// service_url without doubling it.
func TestOpURLBuildsRESTPath(t *testing.T) {
	cert := unrelatedCAPEM(t)
	c, _ := New("https://broker.example/", "fs", testAuthToken, cert)
	got := c.opURL(OpListDirectory)
	want := "https://broker.example/v1/filestore/fs/listDirectory"
	if got != want {
		t.Errorf("opURL = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// call() error branches
// ---------------------------------------------------------------------------

// TestCallMarshalErrorReturnsWrapped drives the request-marshal failure branch.
func TestCallMarshalErrorReturnsWrapped(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-call-01", func(w http.ResponseWriter, r *http.Request) {
		t.Error("call must fail at marshal before reaching the server")
	})
	err := c.call(context.Background(), OpListDirectory, unmarshalable{}, nil)
	if err == nil {
		t.Fatal("expected marshal error, got nil")
	}
	if !strings.Contains(err.Error(), "marshal") {
		t.Errorf("error %q does not mention marshal", err.Error())
	}
}

// TestCallNonParseableBodyMapsByStatus drives the non-2xx branch: a 502 body
// that is not JSON maps to ErrPermanentOther carrying the status.
func TestCallNonParseableBodyMapsByStatus(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-call-02", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream blew up, not json"))
	})
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected error on non-2xx body, got nil")
	}
	if !errors.Is(err, ErrPermanentOther) {
		t.Errorf("502 must map to ErrPermanentOther; got %v", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should carry the status code 502; got %q", err.Error())
	}
}

// TestCallForbiddenMapsToPermissionDenied drives the 403 branch.
func TestCallForbiddenMapsToPermissionDenied(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-call-04", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("scope_mismatch"))
	})
	_, err := c.RemoveFile(context.Background(), "/secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("403 must map to ErrPermissionDenied; got %v", err)
	}
}

// TestCallTooManyRequestsHonoursRetryAfter drives the 429 + Retry-After path.
func TestCallTooManyRequestsHonoursRetryAfter(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-call-05", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("throttled"))
	})
	_, err := c.MakeDirectory(context.Background(), "/new-dir")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Errorf("429 must be retryable; got %v", err)
	}
}

// TestCallResponseUnmarshalError drives the 2xx-but-bad-JSON branch.
func TestCallResponseUnmarshalError(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-call-06", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`["this","is","an","array"]`))
	})
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("error %q does not mention unmarshal", err.Error())
	}
}

// TestCallDialErrorSurfaces drives the transport (Do) error branch: a client
// pointed at an unreachable host fails on dial.
func TestCallDialErrorSurfaces(t *testing.T) {
	c, _ := New("https://127.0.0.1:1", "fs-call-07", testAuthToken, unrelatedCAPEM(t))
	_, err := c.ReadMetadata(context.Background(), "/x")
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// TestCallResponseBodyReadError drives the io.ReadAll-failure branch in call():
// a server that declares a larger Content-Length than it writes, then closes the
// connection, makes the body read fail with an unexpected EOF.
func TestCallResponseBodyReadError(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-read-err", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "200")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partial":`))
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
			}
		}
	})
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected body-read error, got nil")
	}
}

// ---------------------------------------------------------------------------
// stamp() and intent error branches
// ---------------------------------------------------------------------------

func TestStampReturnsBoundFSID(t *testing.T) {
	c, _ := New("https://b", "fs-bound-99", testAuthToken, unrelatedCAPEM(t))
	fsID, am, err := c.stamp(OpReadFile)
	if err != nil {
		t.Fatalf("stamp known op: %v", err)
	}
	if fsID != "fs-bound-99" {
		t.Errorf("stamp fsID: got %q, want fs-bound-99", fsID)
	}
	if am.Intent != "read" || am.Downloadable {
		t.Errorf("stamp am: got %+v, want {read false}", am)
	}
}

func TestStampUnknownOpErrors(t *testing.T) {
	c, _ := New("https://b", "fs-bound-99", testAuthToken, unrelatedCAPEM(t))
	if _, _, err := c.stamp(Op("notARealOp")); err == nil {
		t.Fatal("expected stamp error for unknown op, got nil")
	}
}

func TestIntentForUnknownOpErrors(t *testing.T) {
	intent, err := IntentFor(Op("phantomOp"))
	if err == nil {
		t.Fatal("IntentFor(unknown): expected error, got nil")
	}
	if intent != "" {
		t.Errorf("IntentFor(unknown) intent: got %q, want empty", intent)
	}
	if !strings.Contains(err.Error(), "phantomOp") {
		t.Errorf("error should name the unknown op; got %q", err.Error())
	}
}

func TestStampAuthMetaUnknownOpErrors(t *testing.T) {
	am, err := StampAuthMeta(Op("phantomOp"))
	if err == nil {
		t.Fatal("StampAuthMeta(unknown): expected error, got nil")
	}
	if am != (AuthorizationMetadata{}) {
		t.Errorf("StampAuthMeta(unknown) am: got %+v, want zero value", am)
	}
}

// ---------------------------------------------------------------------------
// sourceChunkSize floor
// ---------------------------------------------------------------------------

func TestSourceChunkSizeFloorIsThree(t *testing.T) {
	if got := sourceChunkSize(1); got != 3 {
		t.Errorf("sourceChunkSize(1): got %d, want 3 (floor)", got)
	}
	if got := sourceChunkSize(2); got != 3 {
		t.Errorf("sourceChunkSize(2): got %d, want 3 (floor)", got)
	}
	// The file part now streams raw bytes, so the chunk is simply the ceiling
	// once above the floor — no base64 or JSON-envelope arithmetic.
	if got := sourceChunkSize(64 * 1024); got != 64*1024 {
		t.Errorf("sourceChunkSize(64KiB): got %d, want %d (flat ceiling)", got, 64*1024)
	}
}

// ---------------------------------------------------------------------------
// Upload transport error branches
// ---------------------------------------------------------------------------

// TestUploadDialErrorSurfaces drives the Do-error branch.
func TestUploadDialErrorSurfaces(t *testing.T) {
	c, _ := New("https://127.0.0.1:1", "fs-up-dial", testAuthToken, unrelatedCAPEM(t))
	err := c.Upload(context.Background(), "/a.txt", bytes.NewReader([]byte("x")), 1, false)
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// TestUploadWriteFaultSurfacesOn2xx drives the writeErr branch: a source-read
// failure with a server that returns 200 means the genuine (non-pipe) write
// fault surfaces.
func TestUploadWriteFaultSurfacesOn2xx(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-up-wf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	err := c.Upload(context.Background(), "/a.txt", errReader{}, 3, false)
	if err == nil {
		t.Fatal("expected write-fault error to surface, got nil")
	}
	if !strings.Contains(err.Error(), "write body") && !strings.Contains(err.Error(), "read source") {
		t.Errorf("error %q does not mention the write/read fault", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Download transport error branches
// ---------------------------------------------------------------------------

func TestDownloadRangeNegativeOffsetErrors(t *testing.T) {
	c, _ := New("https://b", "fs-dl-neg", testAuthToken, unrelatedCAPEM(t))
	_, err := c.DownloadRange(context.Background(), "uuid", -1, 4)
	if err == nil {
		t.Fatal("expected error on negative offset, got nil")
	}
	if !strings.Contains(err.Error(), "negative offset") {
		t.Errorf("error %q does not mention negative offset", err.Error())
	}
}

func TestDownloadRangeNegativeLengthErrors(t *testing.T) {
	c, _ := New("https://b", "fs-dl-negl", testAuthToken, unrelatedCAPEM(t))
	_, err := c.DownloadRange(context.Background(), "uuid", 0, -3)
	if err == nil {
		t.Fatal("expected error on negative length, got nil")
	}
}

func TestDownloadDialErrorSurfaces(t *testing.T) {
	c, _ := New("https://127.0.0.1:1", "fs-dl-dial", testAuthToken, unrelatedCAPEM(t))
	if _, err := c.Download(context.Background(), "uuid"); err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

func TestDownloadRangeDialErrorSurfaces(t *testing.T) {
	c, _ := New("https://127.0.0.1:1", "fs-dl-dial2", testAuthToken, unrelatedCAPEM(t))
	if _, err := c.DownloadRange(context.Background(), "uuid", 0, 4); err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// TestDownloadRangeErrorStatusSurfaces drives DownloadRange's non-2xx branch.
func TestDownloadRangeErrorStatusSurfaces(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-dl-range-err", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("gone"))
	})
	_, err := c.DownloadRange(context.Background(), "uuid", 0, 4)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("404 must map to ErrNotFound; got %v", err)
	}
}

// TestListDirectoryAllCallErrorSurfaces drives the call-error branch inside the
// ListDirectoryAll paging loop.
func TestListDirectoryAllCallErrorSurfaces(t *testing.T) {
	c, _ := newTLSTestClient(t, "fs-lda-err", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("no"))
	})
	_, err := c.ListDirectoryAll(context.Background(), "/")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ListDirectoryAll") {
		t.Errorf("error %q does not name ListDirectoryAll", err.Error())
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("underlying 403 must be preserved; got %v", err)
	}
}

// TestDownloadOversizedBodyIsError drives the download cap branch: a body over
// the cap is rejected rather than read unbounded, while a body under the cap
// round-trips. The 16 GiB production cap cannot be streamed cheaply, so the
// over-cap arm exercises the same boundedBody logic Download returns, with a
// tiny limit — a real assertion, not a documented placeholder.
func TestDownloadOversizedBodyIsError(t *testing.T) {
	if defaultMaxDownloadBytes <= 0 {
		t.Fatal("defaultMaxDownloadBytes must be a positive cap")
	}

	// Control: a normal body under the cap round-trips through the real client.
	c, _ := newTLSTestClient(t, "fs-dl-ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("small body"))
	})
	rc, err := c.Download(context.Background(), "uuid")
	if err != nil {
		t.Fatalf("Download under cap: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Download under cap read: %v", err)
	}
	if string(got) != "small body" {
		t.Errorf("got %q, want %q", got, "small body")
	}

	// Over-cap: a whole-object stream that carries more bytes than the bound
	// must fail on read rather than deliver unbounded content. boundedBody with
	// ranged=false is exactly what Download returns on the full-read path.
	over := newBoundedBody(io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("A"), 100))), false, 10)
	if _, err := io.ReadAll(over); err == nil {
		t.Error("over-cap whole-object stream must fail on read, got no error")
	}

	// The ranged path is equally strict: over-delivery past the requested
	// window is the observable signature of a broker that did not honour the
	// range, so it errors rather than truncating (truncation would relabel the
	// object's head as the requested window). This pin deliberately reverses
	// the earlier truncate-to-window behaviour — see
	// TestDownloadRangeOverDeliveryIsAnError for the wire-level pins.
	ranged := newBoundedBody(io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("B"), 100))), true, 10)
	if _, err := io.ReadAll(ranged); err == nil {
		t.Error("ranged over-delivery must fail on read, got silent truncation")
	}
}
