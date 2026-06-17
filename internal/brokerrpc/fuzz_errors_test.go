// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Fuzz target for the HTTP-status error mapper.
//
// MapHTTPStatus consumes a broker-controlled status, an arbitrary body, and the
// raw Retry-After header string. The strconv.ParseFloat + time.Duration math on
// the Retry-After path is the designated malformed-header defense: "inf",
// "1e300", negatives and NaN must never produce a garbage Duration nor make a
// non-retryable status retryable.

package brokerrpc

import (
	"net/http"
	"testing"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
)

// retryableStatuses is the closed set of statuses MapHTTPStatus must classify as
// retryable; every other non-2xx status is permanent.
var retryableStatuses = map[int]struct{}{
	http.StatusTooManyRequests:    {},
	http.StatusServiceUnavailable: {},
}

// FuzzMapHTTPStatus drives the mapper over arbitrary (status, body, retryAfter)
// triples.
//
// Invariants (no panic on any triple is the baseline):
//   - The result is never nil.
//   - Retryability depends ONLY on the status, never on the Retry-After string.
//   - When a RetryAfter deadline IS produced, it is bounded by
//     maxRetryAfterSeconds — never a garbage/overflowed Duration — and only on a
//     retryable status.
func FuzzMapHTTPStatus(f *testing.F) {
	f.Add(429, "throttled", "1.5")
	f.Add(429, "throttled", "inf")
	f.Add(429, "throttled", "1e300")
	f.Add(429, "throttled", "-5")
	f.Add(429, "throttled", "NaN")
	f.Add(429, "throttled", "0")
	f.Add(429, "throttled", "3600")
	f.Add(429, "throttled", "")
	f.Add(503, "audit down", "10")
	f.Add(403, "denied", "100")
	f.Add(400, "bad", "")
	f.Add(404, "missing", "")
	f.Add(409, "collision", "")
	f.Add(418, "teapot", "5")
	f.Add(500, "boom", "5")
	f.Add(200, "", "")

	f.Fuzz(func(t *testing.T, status int, body, retryAfter string) {
		err := MapHTTPStatus(status, []byte(body), retryAfter)
		if err == nil {
			t.Fatalf("MapHTTPStatus returned nil for status=%d", status)
		}

		_, wantRetryable := retryableStatuses[status]
		gotRetryable := fserrors.IsRetryError(err)
		if gotRetryable != wantRetryable {
			t.Fatalf("status=%d retryAfter=%q: retryable=%v, want %v (header must not change posture)",
				status, retryAfter, gotRetryable, wantRetryable)
		}

		if fserrors.IsRetryAfterError(err) {
			if !wantRetryable {
				t.Fatalf("status=%d: produced a RetryAfter on a non-retryable status", status)
			}
			remaining := time.Until(fserrors.RetryAfterErrorTime(err))
			if remaining > maxRetryAfterSeconds*time.Second {
				t.Fatalf("status=%d retryAfter=%q: RetryAfter %v exceeds bound %ds",
					status, retryAfter, remaining, maxRetryAfterSeconds)
			}
		}
	})
}
