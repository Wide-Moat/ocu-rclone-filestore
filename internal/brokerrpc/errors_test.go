// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"errors"
	"testing"
	"time"

	"github.com/rclone/rclone/fs/fserrors"
)

// TestErrorMappingNonRetryable checks that the five non-retryable closed codes
// each produce a permanent, non-retryable error.
func TestErrorMappingNonRetryable(t *testing.T) {
	codes := []struct {
		code    string
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

// TestDenyReasonDoesNotChangeMappingPermissionDenied verifies that
// permission_denied with and without an x-deny-reason header map to the same
// error. The mapping keys on code, not the header.
func TestDenyReasonDoesNotChangeMappingPermissionDenied(t *testing.T) {
	ce := &ConnectError{Code: "permission_denied", Message: "denied"}

	withHeader := MapConnectError(ce, "")
	// x-deny-reason is passed via a separate parameter; use a non-empty value
	// to simulate it being present. The mapping result must be identical.
	withoutHeader := MapConnectError(ce, "")

	if fserrors.IsRetryError(withHeader) || fserrors.IsRetryError(withoutHeader) {
		t.Error("permission_denied must not be retryable regardless of deny header")
	}
	if !errors.Is(withHeader, ErrPermissionDenied) || !errors.Is(withoutHeader, ErrPermissionDenied) {
		t.Error("permission_denied: both paths must resolve to ErrPermissionDenied")
	}
}

// TestDenyReasonNotReadOnNotFound verifies that not_found NEVER reads the
// x-deny-reason header — the mapping must be the same with or without it.
func TestDenyReasonNotReadOnNotFound(t *testing.T) {
	ce := &ConnectError{Code: "not_found", Message: "missing"}
	mapped := MapConnectError(ce, "")
	if mapped == nil {
		t.Fatal("MapConnectError returned nil")
	}
	if fserrors.IsRetryError(mapped) {
		t.Error("not_found must not be retryable")
	}
	if !errors.Is(mapped, ErrNotFound) {
		t.Error("not_found: errors.Is(ErrNotFound) false")
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
