// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
)

// TestMapHTTPStatusNonRetryable checks that the permanent statuses each produce
// a non-retryable error with the right sentinel.
func TestMapHTTPStatusNonRetryable(t *testing.T) {
	cases := []struct {
		status       int
		wantSentinel error
	}{
		{http.StatusUnauthorized, ErrPermissionDenied}, // 401 token expiry
		{http.StatusForbidden, ErrPermissionDenied},    // 403 foreign scope
		{http.StatusBadRequest, ErrInvalidArgument},    // 400
		{http.StatusUnprocessableEntity, ErrInvalidArgument},
		{http.StatusNotFound, ErrNotFound},      // 404
		{http.StatusConflict, ErrAlreadyExists}, // 409
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			mapped := MapHTTPStatus(tc.status, []byte("body"), "")
			if mapped == nil {
				t.Fatal("MapHTTPStatus returned nil")
			}
			if fserrors.IsRetryError(mapped) {
				t.Errorf("status %d: expected non-retryable, got retryable", tc.status)
			}
			if !errors.Is(mapped, tc.wantSentinel) {
				t.Errorf("status %d: errors.Is(%v) false", tc.status, tc.wantSentinel)
			}
		})
	}
}

// TestMapHTTPStatusAuthCollapseIsOneWay pins the one-way collapse: 401 and 403
// map to the SAME sentinel (ErrPermissionDenied), never split into distinct
// unauthenticated/permission classes.
func TestMapHTTPStatusAuthCollapseIsOneWay(t *testing.T) {
	e401 := MapHTTPStatus(http.StatusUnauthorized, nil, "")
	e403 := MapHTTPStatus(http.StatusForbidden, nil, "")
	if !errors.Is(e401, ErrPermissionDenied) {
		t.Errorf("401 must map to ErrPermissionDenied, got %v", e401)
	}
	if !errors.Is(e403, ErrPermissionDenied) {
		t.Errorf("403 must map to ErrPermissionDenied, got %v", e403)
	}
	if fserrors.IsRetryError(e401) {
		t.Error("401 (token expiry) must be non-retryable — the guest does not loop or re-mint")
	}
}

// TestMapHTTPStatusBoundsHugeBody pins the diagnostics budget: the error body
// is diagnostics-only (the mapping keys on the status, Retry-After is a
// header), so a multi-MiB body must not balloon the error string. The bound is
// maxErrorBodyBytes plus a small allowance for the sentinel prefix and the
// truncation marker.
func TestMapHTTPStatusBoundsHugeBody(t *testing.T) {
	huge := bytes.Repeat([]byte("A"), 4<<20) // 4 MiB
	err := MapHTTPStatus(http.StatusInternalServerError, huge, "")
	if err == nil {
		t.Fatal("MapHTTPStatus returned nil")
	}
	const slack = 256 // sentinel prefix + status text + truncation marker
	if got, limit := int64(len(err.Error())), maxErrorBodyBytes+slack; got > limit {
		t.Errorf("error string is %d bytes; the diagnostics budget bounds it at %d", got, limit)
	}
	if !errors.Is(err, ErrPermanentOther) {
		t.Errorf("500 must still map to ErrPermanentOther; got %v", err)
	}
}

// TestCallErrorBodyCaptureIsBounded is the transport-level pin: a unary op
// answered with a non-2xx and a body far larger than the diagnostics budget
// must surface a bounded error string — the guest never buffers a runaway
// error page into the error value.
func TestCallErrorBodyCaptureIsBounded(t *testing.T) {
	huge := bytes.Repeat([]byte("B"), 1<<20) // 1 MiB error page
	c, _ := newTLSTestClient(t, "fs-err-bound", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(huge)
	})
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("400 must map to ErrInvalidArgument; got sentinel of %v", err)
	}
	const slack = 256
	if got, limit := int64(len(err.Error())), maxErrorBodyBytes+slack; got > limit {
		t.Errorf("error string is %d bytes; the diagnostics budget bounds it at %d", got, limit)
	}
}

// TestCaptureErrorBodyTwoSided pins the shared capture helper on both sides of
// the diagnostics budget: a body within (or exactly at) the cap comes back
// verbatim with no marker — a complete page is never mislabelled as truncated —
// and a body past the cap comes back capped at maxErrorBodyBytes with the
// truncation marker appended.
func TestCaptureErrorBodyTwoSided(t *testing.T) {
	t.Run("under cap is verbatim with no marker", func(t *testing.T) {
		in := []byte("deny: scope mismatch")
		got := captureErrorBody(bytes.NewReader(in))
		if !bytes.Equal(got, in) {
			t.Errorf("capture altered a %d-byte body under the cap: got %d bytes", len(in), len(got))
		}
		if strings.Contains(string(got), " ...[truncated]") {
			t.Error("a body under the cap must not carry the truncation marker")
		}
	})
	t.Run("exactly at cap is verbatim with no marker", func(t *testing.T) {
		in := bytes.Repeat([]byte("x"), int(maxErrorBodyBytes))
		got := captureErrorBody(bytes.NewReader(in))
		if !bytes.Equal(got, in) {
			t.Errorf("capture altered a body exactly at the cap: got %d bytes, want %d", len(got), len(in))
		}
	})
	t.Run("over cap is capped plus marker", func(t *testing.T) {
		in := bytes.Repeat([]byte("y"), int(maxErrorBodyBytes)+1)
		got := captureErrorBody(bytes.NewReader(in))
		const marker = " ...[truncated]"
		if want := maxErrorBodyBytes + int64(len(marker)); int64(len(got)) != want {
			t.Errorf("capture of an over-cap body is %d bytes, want exactly %d (cap + marker)", len(got), want)
		}
		if !strings.HasSuffix(string(got), marker) {
			t.Errorf("capture of an over-cap body must end with the marker %q", marker)
		}
		if !bytes.Equal(got[:maxErrorBodyBytes], in[:maxErrorBodyBytes]) {
			t.Error("capture must preserve the body prefix up to the cap verbatim")
		}
	})
}

// TestCallErrorBodyCaptureStopsReadingAtCap is the two-sided transport pin for
// the unary error-path capture bound: the client must stop READING the wire at
// the diagnostics budget, not merely truncate a fully-buffered page afterwards.
// The server streams a 1 MiB error page in small flushed chunks, counting the
// bytes it managed to write; a capped capture stops reading around 64 KiB, so
// the connection tears down long before 512 KiB crosses the wire. A capture
// bounded at the 64 MiB decode ceiling would drain the full 1 MiB and red the
// byte-count assertion — the marker assertion alone cannot distinguish the two,
// because MapHTTPStatus re-truncates the error string either way.
func TestCallErrorBodyCaptureStopsReadingAtCap(t *testing.T) {
	const (
		chunkSize    = 8 << 10   // 8 KiB per flushed write
		totalBody    = 1 << 20   // 1 MiB error page
		writtenLimit = 512 << 10 // wide margin above the ~64 KiB capped read
	)
	var written atomic.Int64
	chunk := bytes.Repeat([]byte("E"), chunkSize)
	c, _ := newTLSTestClient(t, "fs-err-cap", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		f, canFlush := w.(http.Flusher)
		for sent := 0; sent < totalBody; sent += chunkSize {
			n, werr := w.Write(chunk)
			written.Add(int64(n))
			if werr != nil {
				return // the client stopped reading and closed the connection
			}
			if canFlush {
				f.Flush()
			}
			// Pace the stream so kernel socket buffering cannot swallow a
			// large share of the page before the client-side close lands.
			time.Sleep(500 * time.Microsecond)
		}
	})
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("400 must map to ErrInvalidArgument; got %v", err)
	}
	if !strings.Contains(err.Error(), " ...[truncated]") {
		t.Errorf("error must carry the truncation marker; got a %d-byte message without it", len(err.Error()))
	}
	if got := written.Load(); got >= writtenLimit {
		t.Errorf("server wrote %d bytes before the client stopped reading; a capped capture must keep this under %d", got, writtenLimit)
	}
}

// TestMapHTTPStatusRetryable checks that 429 and 503 produce retryable errors.
func TestMapHTTPStatusRetryable(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			mapped := MapHTTPStatus(status, []byte("backpressure"), "")
			if mapped == nil {
				t.Fatal("MapHTTPStatus returned nil")
			}
			if !fserrors.IsRetryError(mapped) {
				t.Errorf("status %d: expected retryable, got non-retryable", status)
			}
		})
	}
}

// TestMapHTTPStatusRetryAfter checks that 429 with a Retry-After header produces
// an IsRetryAfterError carrying the deadline.
func TestMapHTTPStatusRetryAfter(t *testing.T) {
	mapped := MapHTTPStatus(http.StatusTooManyRequests, nil, "5")
	if mapped == nil {
		t.Fatal("MapHTTPStatus returned nil")
	}
	if !fserrors.IsRetryAfterError(mapped) {
		t.Errorf("expected IsRetryAfterError true, got false")
	}
	if !fserrors.IsRetryError(mapped) {
		t.Errorf("retry-after error should also satisfy IsRetryError")
	}
	d := time.Until(fserrors.RetryAfterErrorTime(mapped))
	if d < 4*time.Second || d > 6*time.Second {
		t.Errorf("retry-after duration out of expected range: %v", d)
	}
}

// TestMapHTTPStatusRetryAfterAbsentNoDeadline checks that 429 without a
// Retry-After header is retryable but carries no deadline.
func TestMapHTTPStatusRetryAfterAbsentNoDeadline(t *testing.T) {
	mapped := MapHTTPStatus(http.StatusTooManyRequests, nil, "")
	if !fserrors.IsRetryError(mapped) {
		t.Error("429 without Retry-After must remain retryable")
	}
	if fserrors.IsRetryAfterError(mapped) {
		t.Error("429 without Retry-After must not carry a deadline")
	}
}

// TestMapHTTPStatusRetryAfterRejectsNonFinite verifies that a non-finite or
// absurdly large Retry-After value is not turned into a garbage deadline. The
// error must stay retryable (429) but carry no RetryAfter deadline.
func TestMapHTTPStatusRetryAfterRejectsNonFinite(t *testing.T) {
	for _, raw := range []string{"inf", "Inf", "+Inf", "1e300", "-5", "0", "NaN"} {
		t.Run(raw, func(t *testing.T) {
			mapped := MapHTTPStatus(http.StatusTooManyRequests, nil, raw)
			if mapped == nil {
				t.Fatal("MapHTTPStatus returned nil")
			}
			if !fserrors.IsRetryError(mapped) {
				t.Errorf("%q: 429 must remain retryable", raw)
			}
			if fserrors.IsRetryAfterError(mapped) {
				t.Errorf("%q: malformed Retry-After must not produce a RetryAfter deadline", raw)
			}
		})
	}
}

// TestMapHTTPStatusRetryAfterCapBoundary pins the upper bound of the accepted
// Retry-After window (maxRetryAfterSeconds = 3600). The guard is
// `secs < maxRetryAfterSeconds`, so the boundary is exclusive.
func TestMapHTTPStatusRetryAfterCapBoundary(t *testing.T) {
	cases := []struct {
		name         string
		raw          string
		wantDeadline bool
	}{
		{name: "just under cap", raw: "3599", wantDeadline: true},
		{name: "exactly at cap", raw: "3600", wantDeadline: false},
		{name: "over cap", raw: "3601", wantDeadline: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapped := MapHTTPStatus(http.StatusTooManyRequests, nil, tc.raw)
			if mapped == nil {
				t.Fatal("MapHTTPStatus returned nil")
			}
			if !fserrors.IsRetryError(mapped) {
				t.Errorf("%s: 429 must remain retryable", tc.name)
			}
			if got := fserrors.IsRetryAfterError(mapped); got != tc.wantDeadline {
				t.Fatalf("%s (raw=%q): IsRetryAfterError = %t, want %t", tc.name, tc.raw, got, tc.wantDeadline)
			}
			if tc.wantDeadline {
				d := time.Until(fserrors.RetryAfterErrorTime(mapped))
				if d < 3500*time.Second || d > 3600*time.Second {
					t.Errorf("%s: deadline %v out of expected near-cap range", tc.name, d)
				}
			}
		})
	}
}

// TestMapHTTPStatusUnknownIsPermanent verifies that statuses outside the mapped
// table map to a permanent, non-retryable error with NO retryable fallthrough.
func TestMapHTTPStatusUnknownIsPermanent(t *testing.T) {
	for _, status := range []int{http.StatusTeapot, http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			mapped := MapHTTPStatus(status, []byte("oops"), "")
			if mapped == nil {
				t.Fatal("MapHTTPStatus returned nil")
			}
			if fserrors.IsRetryError(mapped) {
				t.Errorf("status %d: must NOT be retryable (no retryable fallthrough)", status)
			}
			if !errors.Is(mapped, ErrPermanentOther) {
				t.Errorf("status %d: errors.Is(ErrPermanentOther) false", status)
			}
		})
	}
}

// TestMapHTTPStatusCarriesBodyAndStatus verifies the body text and status are
// carried into the wrapped error message for diagnostics.
func TestMapHTTPStatusCarriesBodyAndStatus(t *testing.T) {
	mapped := MapHTTPStatus(http.StatusBadGateway, []byte("upstream blew up"), "")
	if mapped == nil {
		t.Fatal("MapHTTPStatus returned nil")
	}
	if msg := mapped.Error(); !contains(msg, "502") || !contains(msg, "upstream blew up") {
		t.Errorf("error %q must carry both the status 502 and the body text", msg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestMapHTTPStatusEndToEnd drives the real unary path against a TLS server and
// asserts the status→sentinel mapping flows through Client.call.
func TestMapHTTPStatusEndToEnd(t *testing.T) {
	cases := []struct {
		status       int
		wantSentinel error
		retryable    bool
	}{
		{http.StatusForbidden, ErrPermissionDenied, false},
		{http.StatusNotFound, ErrNotFound, false},
		{http.StatusConflict, ErrAlreadyExists, false},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, _ := newTLSTestClient(t, "fs-err-e2e", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("verdict"))
			})
			_, err := c.ListDirectory(context.Background(), "/")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tc.wantSentinel) {
				t.Errorf("errors.Is(%v) false; got %v", tc.wantSentinel, err)
			}
			if fserrors.IsRetryError(err) != tc.retryable {
				t.Errorf("retryable = %v, want %v", fserrors.IsRetryError(err), tc.retryable)
			}
		})
	}
}
