// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — HTTP-status error mapping.
//
// The broker communicates errors over REST as HTTP status codes. This file
// maps each status to a typed filesystem error with the correct retry posture.
// The mapping keys on the HTTP status FIRST; the response body is carried into
// the wrapped error message for diagnostics only and never drives the mapping.
//
// Retry posture summary:
//
//	429 (too many requests), 503 (unavailable)  → retryable with backoff (SEC-46)
//	all other non-2xx statuses                  → permanent, no retry
//	every unmapped status                       → permanent, no retry (explicit default)
//
// Authentication-class collapse: 401 (token expiry) and 403 (foreign scope)
// BOTH collapse to ErrPermissionDenied. This is a one-way collapse — there is
// no 401→unauthenticated / 403→permission split. A token that simply expires
// yields a clean, non-retryable EACCES; the guest does not loop and does not
// re-mint a credential (no refresh — the credential is read once at
// construction).

package brokerrpc

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
)

// ---------------------------------------------------------------------------
// Typed filesystem-error sentinels — call sites can errors.Is these.
// ---------------------------------------------------------------------------

// ErrPermissionDenied is the sentinel for permission-denied outcomes
// (HTTP 401 token expiry and HTTP 403 foreign scope both collapse here).
var ErrPermissionDenied = errors.New("brokerrpc: permission denied")

// ErrInvalidArgument is the sentinel for permanent invalid-input errors
// (HTTP 400 / 422; includes size-policy failures).
var ErrInvalidArgument = errors.New("brokerrpc: invalid argument")

// ErrNotFound is the sentinel for missing-object errors (HTTP 404; includes
// the cross-scope anti-enumeration degrade — the client treats it uniformly).
var ErrNotFound = errors.New("brokerrpc: not found")

// ErrAlreadyExists is the sentinel for path-collision errors (HTTP 409).
var ErrAlreadyExists = errors.New("brokerrpc: already exists")

// maxRetryAfterSeconds bounds an accepted Retry-After hint. A value at or above
// this (or non-finite) is treated as no usable hint: the error is still
// retryable but carries no deadline. One hour is far longer than any sane
// broker back-off and excludes "inf" and overflowing floats.
const maxRetryAfterSeconds = 3600

// maxErrorBodyBytes is the shared diagnostics budget for a non-2xx response
// body. The body is diagnostics-only on this wire: the mapping keys on the
// HTTP status, Retry-After arrives as a header, and nothing in the body is
// ever parsed. The frozen contract's structured deny envelope is bounded well
// under 1 KiB (a short reason code plus a bounded message), so 64 KiB keeps
// two orders of magnitude of headroom for verbose broker error pages while
// stopping a runaway error body from ballooning guest memory or the error
// string. It is the package's one bound for every error-body read (unary,
// upload, download error paths).
const maxErrorBodyBytes int64 = 64 << 10 // 64 KiB

// errorBodyTruncationMarker is appended to a capped error-body capture so a
// truncated diagnostics page is never mistaken for the complete broker output.
const errorBodyTruncationMarker = " ...[truncated]"

// ErrPermanentOther is the sentinel for any non-2xx status not in the mapped
// table. These map to a permanent no-retry error. The explicit default
// prevents a wrong retryable fallthrough from looping a write forever.
var ErrPermanentOther = errors.New("brokerrpc: permanent error")

// ---------------------------------------------------------------------------
// Error mapper
// ---------------------------------------------------------------------------

// MapHTTPStatus converts a non-2xx HTTP status (with the raw response body and
// the Retry-After header value) into a typed filesystem error with the correct
// retry posture.
//
// retryAfterRaw is the raw value of the Retry-After response header (seconds as
// a decimal string). It is honoured only for 429; pass an empty string when
// there is no header.
//
// The mapping is keyed on the HTTP status; the body text is appended to the
// error message for diagnostics only and never changes the mapping. The copy
// into the error string is truncated at maxErrorBodyBytes as a choke-point
// defense: even a caller that read the body unbounded cannot balloon the
// error value.
func MapHTTPStatus(status int, body []byte, retryAfterRaw string) error {
	msg := boundErrorBody(body)

	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		// 401 is token expiry (clean, non-retryable — the credential is read
		// once and never re-minted) and 403 is foreign-scope. Both collapse to
		// the same EACCES sentinel; no retry. This is the one-way collapse: no
		// 401→unauth / 403→permission split.
		return fmt.Errorf("%w: status %d: %s", ErrPermissionDenied, status, msg)

	case http.StatusNotFound:
		// Permanent; no retry. Treated uniformly including the cross-scope
		// anti-enumeration degrade.
		return fmt.Errorf("%w: status %d: %s", ErrNotFound, status, msg)

	case http.StatusConflict:
		// Permanent; no retry (overwrite disabled on an existing path).
		return fmt.Errorf("%w: status %d: %s", ErrAlreadyExists, status, msg)

	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		// Permanent; no retry. Covers size-policy failures and malformed
		// requests.
		return fmt.Errorf("%w: status %d: %s", ErrInvalidArgument, status, msg)

	case http.StatusTooManyRequests:
		// Backpressure: retry with backoff (SEC-46). When a Retry-After header
		// is present, produce an ErrorRetryAfter so the upstream pacer can
		// honour the broker's back-off hint.
		if retryAfterRaw != "" {
			// Bound the parse: reject non-positive, non-finite ("inf"), and
			// absurdly large values ("1e300"). strconv.ParseFloat accepts "inf"
			// with +Inf > 0, and time.Duration(math.Inf(1)*1e9) is an
			// out-of-range float→int conversion yielding a garbage duration.
			// This parse path is the designated malformed-header defense.
			if secs, err := strconv.ParseFloat(retryAfterRaw, 64); err == nil && secs > 0 && secs < maxRetryAfterSeconds {
				d := time.Duration(secs * float64(time.Second))
				base := fmt.Errorf("brokerrpc: resource exhausted: status %d: %s", status, msg)
				return fserrors.RetryError(
					fmt.Errorf("%w: %w", base, fserrors.NewErrorRetryAfter(d)),
				)
			}
		}
		return fserrors.RetryError(
			fmt.Errorf("brokerrpc: resource exhausted: status %d: %s", status, msg),
		)

	case http.StatusServiceUnavailable:
		// Audit subsystem down / transient unavailability; retryable with
		// backoff (no Retry-After honoured on this status).
		return fserrors.RetryError(
			fmt.Errorf("brokerrpc: unavailable: status %d: %s", status, msg),
		)

	default:
		// Explicit permanent-no-retry default. Any non-2xx status outside the
		// mapped table falls here. A wrong retryable default could loop a write
		// forever; the default MUST stay non-retryable.
		return fmt.Errorf("%w: status %d: %s", ErrPermanentOther, status, msg)
	}
}

// captureErrorBody is the single capture point for a non-2xx response body.
// It reads at most maxErrorBodyBytes from r; when the cap was reached and at
// least one more byte is pending, it appends the truncation marker so a capped
// page is never mistaken for the complete broker output. All three transport
// error paths (unary call, upload, download) capture through this helper —
// none reads the wire past the diagnostics budget. Read errors are swallowed:
// the body is diagnostics-only and the HTTP status already carries the
// verdict.
func captureErrorBody(r io.Reader) []byte {
	body, _ := io.ReadAll(io.LimitReader(r, maxErrorBodyBytes))
	if int64(len(body)) == maxErrorBodyBytes {
		// Probe for one pending byte to distinguish a body exactly at the cap
		// (complete, no marker) from one that overflows it (marked truncated).
		var probe [1]byte
		if n, _ := io.ReadFull(r, probe[:]); n > 0 {
			return append(body, errorBodyTruncationMarker...)
		}
	}
	return body
}

// boundErrorBody is the in-mapper choke point: it truncates an
// already-materialized body to maxErrorBodyBytes with the explicit marker, so
// even a caller that captured unbounded cannot balloon the error string. On
// the production transport paths the capture is already capped and marked by
// captureErrorBody; re-bounding such a capture is idempotent (the marked
// capture is body[:cap]+marker, and re-truncation reproduces exactly that
// string).
func boundErrorBody(body []byte) string {
	if int64(len(body)) <= maxErrorBodyBytes {
		return string(body)
	}
	return string(body[:maxErrorBodyBytes]) + errorBodyTruncationMarker
}
