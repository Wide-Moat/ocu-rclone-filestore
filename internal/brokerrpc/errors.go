// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — closed Connect-code error mapping.
//
// The broker communicates errors via the closed Connect-code set. This file
// maps each code to a typed filesystem error with the correct retry posture.
// The mapping keys on the Connect code FIRST; the x-deny-reason response
// header is a secondary informational hint carried only on authz verdicts
// (permission_denied, unauthenticated) and never drives the mapping.
//
// Retry posture summary (per the locked wire contract):
//
//	resource_exhausted, unavailable  → retryable with backoff (SEC-46)
//	all other closed codes           → permanent, no retry
//	aborted + any unlisted code      → permanent, no retry (explicit default)

package brokerrpc

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
)

// ---------------------------------------------------------------------------
// Typed filesystem-error sentinels — call sites can errors.Is these.
// ---------------------------------------------------------------------------

// ErrPermissionDenied is the sentinel for permission-denied outcomes
// (Connect codes: permission_denied, unauthenticated).
var ErrPermissionDenied = errors.New("brokerrpc: permission denied")

// ErrInvalidArgument is the sentinel for permanent invalid-input errors
// (Connect code: invalid_argument; includes size_exceeded policy failures).
var ErrInvalidArgument = errors.New("brokerrpc: invalid argument")

// ErrNotFound is the sentinel for missing-object errors (Connect code:
// not_found; includes cross-scope-uuid degrade where the wire degrades to
// not_found with no x-deny-reason header — the client treats it uniformly).
var ErrNotFound = errors.New("brokerrpc: not found")

// ErrAlreadyExists is the sentinel for path-collision errors
// (Connect code: already_exists).
var ErrAlreadyExists = errors.New("brokerrpc: already exists")

// maxRetryAfterSeconds bounds an accepted Retry-After hint. A value at or above
// this (or non-finite) is treated as no usable hint: the error is still
// retryable but carries no deadline. One hour is far longer than any sane
// broker back-off and excludes "inf" and overflowing floats.
const maxRetryAfterSeconds = 3600

// ErrPermanentOther is the sentinel for any Connect code not in the closed
// table — including `aborted` and any future or unknown code. These map to a
// permanent no-retry error. The explicit default prevents a wrong retryable
// fallthrough from looping a write forever (D4, T-02-09).
var ErrPermanentOther = errors.New("brokerrpc: permanent error")

// ---------------------------------------------------------------------------
// Error mapper
// ---------------------------------------------------------------------------

// MapConnectError converts a ConnectError (from either a unary non-2xx body
// or a streaming EndStreamResponse trailer) into a typed filesystem error with
// the correct retry posture.
//
// retryAfterRaw is the raw value of the Retry-After response header (seconds
// as a decimal string). It is honoured only for resource_exhausted; pass an
// empty string when there is no header.
//
// The mapping is keyed on the Connect code string; the x-deny-reason header
// value is intentionally not a parameter here — it is informational on authz
// codes only and never changes the fs-error mapping.
func MapConnectError(ce *ConnectError, retryAfterRaw string) error {
	if ce == nil {
		return nil
	}

	switch ce.Code {
	case "permission_denied", "unauthenticated":
		// Both authz-class codes map to the same EACCES sentinel; no retry.
		// The x-deny-reason header (scope_mismatch, intent_denied,
		// not_downloadable, lease_expired) is informational only and does not
		// change the mapping.
		return fmt.Errorf("%w: %s", ErrPermissionDenied, ce.Message)

	case "invalid_argument":
		// Permanent; no retry. Covers policy size_exceeded (declared-vs-broker
		// max) and malformed-request paths.
		return fmt.Errorf("%w: %s", ErrInvalidArgument, ce.Message)

	case "not_found":
		// Permanent; no retry. Treated uniformly including the cross-scope-uuid
		// anti-enumeration degrade (D8) which carries no x-deny-reason header.
		return fmt.Errorf("%w: %s", ErrNotFound, ce.Message)

	case "already_exists":
		// Permanent; no retry (overwrite_existing=false on existing path).
		return fmt.Errorf("%w: %s", ErrAlreadyExists, ce.Message)

	case "resource_exhausted":
		// Backpressure: retry with backoff. Covers per-session throttle and
		// transport frame over the message ceiling (SEC-46, D4).
		// When a Retry-After header is present, produce an ErrorRetryAfter so
		// the upstream pacer (Phase 3) can honour the broker's back-off hint.
		if retryAfterRaw != "" {
			// Bound the parse: reject non-positive, non-finite ("inf"), and
			// absurdly large values ("1e300"). strconv.ParseFloat accepts
			// "inf" with +Inf > 0, and time.Duration(math.Inf(1)*1e9) is an
			// out-of-range float→int conversion yielding a garbage duration.
			// This parse path is the designated malformed-header defense.
			if secs, err := strconv.ParseFloat(retryAfterRaw, 64); err == nil && secs > 0 && secs < maxRetryAfterSeconds {
				d := time.Duration(secs * float64(time.Second))
				base := fmt.Errorf("brokerrpc: resource exhausted: %s", ce.Message)
				// Wrap as RetryAfter so the pacer can inspect the deadline.
				return fserrors.RetryError(
					fmt.Errorf("%w: %w", base, fserrors.NewErrorRetryAfter(d)),
				)
			}
		}
		return fserrors.RetryError(
			fmt.Errorf("brokerrpc: resource exhausted: %s", ce.Message),
		)

	case "unavailable":
		// Audit subsystem down; retryable with backoff (no Retry-After on this
		// code per the locked contract).
		return fserrors.RetryError(
			fmt.Errorf("brokerrpc: unavailable: %s", ce.Message),
		)

	default:
		// Explicit permanent-no-retry default. `aborted` (a conflict-adjacent
		// verdict) falls here; so does any Connect code outside the closed
		// table. A wrong retryable default could loop a write forever (T-02-09,
		// D4). The default MUST stay non-retryable.
		return fmt.Errorf("%w: code=%s: %s", ErrPermanentOther, ce.Code, ce.Message)
	}
}
