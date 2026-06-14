// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
)

// TestErrorMappingNonRetryable checks that the five non-retryable closed codes
// each produce a permanent, non-retryable error.
func TestErrorMappingNonRetryable(t *testing.T) {
	codes := []struct {
		code         string
		wantSentinel error
	}{
		{"permission_denied", ErrPermissionDenied},
		{"unauthenticated", ErrPermissionDenied}, // maps to same EACCES class
		{"invalid_argument", ErrInvalidArgument},
		{"not_found", ErrNotFound},
		{"already_exists", ErrAlreadyExists},
	}

	for _, tc := range codes {
		t.Run(tc.code, func(t *testing.T) {
			ce := &ConnectError{Code: tc.code, Message: "test"}
			mapped := MapConnectError(ce, "")
			if mapped == nil {
				t.Fatal("MapConnectError returned nil")
			}
			if fserrors.IsRetryError(mapped) {
				t.Errorf("code %q: expected non-retryable, got retryable", tc.code)
			}
			if !errors.Is(mapped, tc.wantSentinel) {
				t.Errorf("code %q: errors.Is(%v) false", tc.code, tc.wantSentinel)
			}
		})
	}
}

// TestErrorMappingRetryable checks that resource_exhausted and unavailable
// produce retryable errors via rclone's fserrors machinery.
func TestErrorMappingRetryable(t *testing.T) {
	codes := []string{"resource_exhausted", "unavailable"}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			ce := &ConnectError{Code: code, Message: "backpressure"}
			mapped := MapConnectError(ce, "")
			if mapped == nil {
				t.Fatal("MapConnectError returned nil")
			}
			if !fserrors.IsRetryError(mapped) {
				t.Errorf("code %q: expected retryable, got non-retryable", code)
			}
		})
	}
}

// TestErrorMappingRetryAfter checks that resource_exhausted with a Retry-After
// header produces an IsRetryAfterError.
func TestErrorMappingRetryAfter(t *testing.T) {
	ce := &ConnectError{Code: "resource_exhausted", Message: "throttled"}
	mapped := MapConnectError(ce, "5") // 5-second Retry-After
	if mapped == nil {
		t.Fatal("MapConnectError returned nil")
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

// TestErrorMappingRetryAfterRejectsNonFinite verifies that a non-finite or
// absurdly large Retry-After value is not turned into a garbage deadline
// (LO-03). The error must stay retryable (resource_exhausted) but carry no
// RetryAfter deadline.
func TestErrorMappingRetryAfterRejectsNonFinite(t *testing.T) {
	for _, raw := range []string{"inf", "Inf", "+Inf", "1e300", "-5", "0"} {
		t.Run(raw, func(t *testing.T) {
			ce := &ConnectError{Code: "resource_exhausted", Message: "throttled"}
			mapped := MapConnectError(ce, raw)
			if mapped == nil {
				t.Fatal("MapConnectError returned nil")
			}
			if !fserrors.IsRetryError(mapped) {
				t.Errorf("%q: resource_exhausted must remain retryable", raw)
			}
			if fserrors.IsRetryAfterError(mapped) {
				t.Errorf("%q: malformed Retry-After must not produce a RetryAfter deadline", raw)
			}
		})
	}
}

// TestErrorMappingRetryAfterCapBoundary pins the upper bound of the accepted
// Retry-After window (maxRetryAfterSeconds = 3600). The guard is
// `secs < maxRetryAfterSeconds`, so the boundary is exclusive:
//
//	just under the cap  → retryable WITH a usable deadline
//	exactly at the cap  → retryable WITHOUT a usable deadline
//	over the cap        → retryable WITHOUT a usable deadline
//
// Were the guard `<=` (off-by-one), the at-cap value would wrongly yield a
// deadline; the at-cap case below catches that. All three remain retryable
// because resource_exhausted is always backpressure regardless of the hint.
func TestErrorMappingRetryAfterCapBoundary(t *testing.T) {
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
			ce := &ConnectError{Code: "resource_exhausted", Message: "throttled"}
			mapped := MapConnectError(ce, tc.raw)
			if mapped == nil {
				t.Fatal("MapConnectError returned nil")
			}
			// Always retryable: the hint never changes the retry posture.
			if !fserrors.IsRetryError(mapped) {
				t.Errorf("%s: resource_exhausted must remain retryable", tc.name)
			}
			if got := fserrors.IsRetryAfterError(mapped); got != tc.wantDeadline {
				t.Fatalf("%s (raw=%q): IsRetryAfterError = %t, want %t", tc.name, tc.raw, got, tc.wantDeadline)
			}
			if tc.wantDeadline {
				// The just-under-cap value must produce a usable, near-cap
				// deadline — pinning that an accepted hint actually carries
				// through, not merely that the flag is set.
				d := time.Until(fserrors.RetryAfterErrorTime(mapped))
				if d < 3500*time.Second || d > 3600*time.Second {
					t.Errorf("%s: deadline %v out of expected near-cap range", tc.name, d)
				}
			}
		})
	}
}

// TestErrorMappingUnknownCodeIsPermanent verifies that a code outside the
// closed table maps to a permanent, non-retryable error with NO retryable
// fallthrough. This is the explicit default branch.
func TestErrorMappingUnknownCodeIsPermanent(t *testing.T) {
	unknownCodes := []string{"data_loss", "deadline_exceeded", "cancelled", "out_of_range"}
	for _, code := range unknownCodes {
		t.Run(code, func(t *testing.T) {
			ce := &ConnectError{Code: code, Message: "unexpected"}
			mapped := MapConnectError(ce, "")
			if mapped == nil {
				t.Fatal("MapConnectError returned nil")
			}
			if fserrors.IsRetryError(mapped) {
				t.Errorf("unknown code %q: must NOT be retryable (no retryable fallthrough)", code)
			}
			if !errors.Is(mapped, ErrPermanentOther) {
				t.Errorf("unknown code %q: errors.Is(ErrPermanentOther) false", code)
			}
		})
	}
}

// TestErrorMappingAbortedIsPermanent verifies that `aborted` is permanent and
// non-retryable (falls into the explicit permanent default, not its own row).
func TestErrorMappingAbortedIsPermanent(t *testing.T) {
	ce := &ConnectError{Code: "aborted", Message: "conflict"}
	mapped := MapConnectError(ce, "")
	if mapped == nil {
		t.Fatal("MapConnectError returned nil")
	}
	if fserrors.IsRetryError(mapped) {
		t.Errorf("aborted: must NOT be retryable (permanent default)")
	}
	if !errors.Is(mapped, ErrPermanentOther) {
		t.Errorf("aborted: errors.Is(ErrPermanentOther) false")
	}
}

// callMappedError drives a single unary call against a server that returns the
// given Connect code with the given response headers, and returns the mapped
// error from the production unary path (Client.call → MapConnectError).
func callMappedError(t *testing.T, code string, respHeaders map[string]string) error {
	t.Helper()
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		for k, v := range respHeaders {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		body, _ := json.Marshal(ConnectError{Code: code, Message: "verdict"})
		_, _ = w.Write(body)
	})
	c, _ := New(sock, "fs-deny-01")
	return c.call(context.Background(), OpListDirectory, ListDirectoryRequest{}, nil)
}

// TestDenyReasonDoesNotChangeMappingPermissionDenied drives the real unary path
// end-to-end and asserts that a permission_denied verdict maps to the same
// error whether or not the broker attaches an x-deny-reason header — the
// structural invariant being that the mapping keys on the Connect code and the
// production code reads no deny-reason header at all (MD-05). The prior version
// called MapConnectError twice with identical arguments and could never fail.
func TestDenyReasonDoesNotChangeMappingPermissionDenied(t *testing.T) {
	withHeader := callMappedError(t, "permission_denied", map[string]string{"x-deny-reason": "scope_mismatch"})
	withoutHeader := callMappedError(t, "permission_denied", nil)

	for name, err := range map[string]error{"with-header": withHeader, "without-header": withoutHeader} {
		if err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
		if fserrors.IsRetryError(err) {
			t.Errorf("%s: permission_denied must not be retryable", name)
		}
		if !errors.Is(err, ErrPermissionDenied) {
			t.Errorf("%s: errors.Is(ErrPermissionDenied) false", name)
		}
	}
}

// TestDenyReasonNotReadOnNotFound drives the real unary path and asserts that a
// not_found verdict maps identically whether or not an x-deny-reason header is
// present — confirming the cross-scope-uuid degrade (D8) is treated uniformly
// and the header is never consulted (MD-05).
func TestDenyReasonNotReadOnNotFound(t *testing.T) {
	withHeader := callMappedError(t, "not_found", map[string]string{"x-deny-reason": "scope_mismatch"})
	withoutHeader := callMappedError(t, "not_found", nil)

	for name, err := range map[string]error{"with-header": withHeader, "without-header": withoutHeader} {
		if err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
		if fserrors.IsRetryError(err) {
			t.Errorf("%s: not_found must not be retryable", name)
		}
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: errors.Is(ErrNotFound) false", name)
		}
	}
}

// TestErrorMappingFromUnaryBody verifies the mapper works on errors decoded
// from a unary non-2xx body (same code → same mapping).
func TestErrorMappingFromUnaryBody(t *testing.T) {
	// Simulate what the unary path decodes from a non-2xx body.
	ce := &ConnectError{Code: "already_exists", Message: "path occupied"}
	mapped := MapConnectError(ce, "")
	if mapped == nil {
		t.Fatal("MapConnectError returned nil")
	}
	if fserrors.IsRetryError(mapped) {
		t.Error("already_exists from unary body must not be retryable")
	}
	if !errors.Is(mapped, ErrAlreadyExists) {
		t.Error("already_exists: errors.Is(ErrAlreadyExists) false")
	}
}

// TestErrorMappingFromEndStreamTrailer verifies the mapper works on errors
// decoded from a streaming EndStreamResponse trailer (same code → same mapping).
func TestErrorMappingFromEndStreamTrailer(t *testing.T) {
	ce := &ConnectError{Code: "unavailable", Message: "audit down"}
	mapped := MapConnectError(ce, "")
	if mapped == nil {
		t.Fatal("MapConnectError returned nil")
	}
	if !fserrors.IsRetryError(mapped) {
		t.Error("unavailable from EndStreamResponse trailer must be retryable")
	}
}
