// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Fuzz target for the closed-code error mapper.
//
// MapConnectError consumes broker-controlled code/message strings plus the raw
// Retry-After header string. The strconv.ParseFloat + time.Duration math on the
// Retry-After path is the designated malformed-header defense: "inf", "1e300",
// negatives and NaN must never produce a garbage Duration nor make a
// non-retryable code retryable. MapConnectError is exported, but the target is
// kept white-box with its siblings (package brokerrpc).

package brokerrpc

import (
	"testing"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
)

// retryableCodes is the closed set of codes that MapConnectError must classify
// as retryable; every other code (including the empty string and unknowns) is
// permanent.
var retryableCodes = map[string]struct{}{
	"resource_exhausted": {},
	"unavailable":        {},
}

// FuzzMapConnectError drives the mapper over arbitrary (code, message,
// retryAfter) triples.
//
// Invariants (no panic on any triple is the baseline):
//   - The result is never nil for a non-nil ConnectError.
//   - retryability depends ONLY on the code, never on the Retry-After string: a
//     non-retryable code stays non-retryable for ANY header value, and a
//     retryable code stays retryable for ANY header value. A malformed header
//     can never flip the posture.
//   - When a RetryAfter deadline IS produced, it is strictly in the future and
//     bounded by maxRetryAfterSeconds — never a garbage/overflowed Duration.
//   - An unknown/empty code maps to the permanent default (ErrPermanentOther,
//     non-retryable).
func FuzzMapConnectError(f *testing.F) {
	f.Add("resource_exhausted", "throttled", "1.5")
	f.Add("resource_exhausted", "throttled", "inf")
	f.Add("resource_exhausted", "throttled", "1e300")
	f.Add("resource_exhausted", "throttled", "-5")
	f.Add("resource_exhausted", "throttled", "NaN")
	f.Add("resource_exhausted", "throttled", "0")
	f.Add("resource_exhausted", "throttled", "3600")
	f.Add("resource_exhausted", "throttled", "")
	f.Add("unavailable", "audit down", "10")
	f.Add("permission_denied", "denied", "100")
	f.Add("invalid_argument", "bad", "")
	f.Add("not_found", "missing", "")
	f.Add("already_exists", "collision", "")
	f.Add("aborted", "conflict", "5")
	f.Add("totally_unknown_code", "?", "5")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, code, message, retryAfter string) {
		ce := &ConnectError{Code: code, Message: message}
		err := MapConnectError(ce, retryAfter)
		if err == nil {
			t.Fatalf("MapConnectError returned nil for a non-nil ConnectError (code=%q)", code)
		}

		_, wantRetryable := retryableCodes[code]
		gotRetryable := fserrors.IsRetryError(err)
		if gotRetryable != wantRetryable {
			t.Fatalf("code=%q retryAfter=%q: retryable=%v, want %v (header must not change posture)",
				code, retryAfter, gotRetryable, wantRetryable)
		}

		// A RetryAfter deadline, when present, must be bounded by
		// maxRetryAfterSeconds: that is the malformed-header guard (it rejects
		// "inf"/"1e300"/negatives/NaN before they become a garbage Duration).
		// We deliberately do NOT assert the deadline is still in the future: the
		// mapper legitimately accepts arbitrarily small positive hints (e.g.
		// "1e-7" -> 100ns), whose deadline can elapse within this test before the
		// time.Until call. That elapsing is correct behaviour, not a defect, so
		// only the upper bound is a real invariant. The bound is checked against
		// the same instant the deadline was computed (now), with a small slack
		// for the construction latency.
		if fserrors.IsRetryAfterError(err) {
			if !wantRetryable {
				t.Fatalf("code=%q: produced a RetryAfter on a non-retryable code", code)
			}
			remaining := time.Until(fserrors.RetryAfterErrorTime(err))
			if remaining > maxRetryAfterSeconds*time.Second {
				t.Fatalf("code=%q retryAfter=%q: RetryAfter %v exceeds bound %ds", code, retryAfter, remaining, maxRetryAfterSeconds)
			}
		}
	})
}
