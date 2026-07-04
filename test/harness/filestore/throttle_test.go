// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// listReq builds a listDirectory request body for the scope root, which always
// exists, so a non-throttled op returns 200 and a throttled op is refused at
// stage 0 before the op runs.
func listReq(t *testing.T, srv *Server, fsID string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"filesystem_id":          fsID,
		"authorization_metadata": map[string]any{"intent": "read"},
		"path":                   ".",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, restBase+string(opListDirectory), bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+fsID) // StaticCredentialValidator maps cred->fsID below
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// TestPerOpThrottle_RefusesOverBudgetBurstAndRecovers proves the per-op token
// bucket refuses an over-budget metadata burst on the throttled scope with the
// unmapped throttle status and admits it again after the bucket refills, while a
// non-throttled scope is never charged.
func TestPerOpThrottle_RefusesOverBudgetBurstAndRecovers(t *testing.T) {
	const throttleFSID, rwFSID = "fsthrottle", "fsrw"
	throttleDir := t.TempDir()
	rwDir := t.TempDir()

	// A controllable clock so the test is deterministic: no real sleeps.
	var nowNanos atomic.Int64
	nowNanos.Store(time.Unix(1_700_000_000, 0).UnixNano())
	clock := func() time.Time { return time.Unix(0, nowNanos.Load()) }

	srv := MustNewServer(Options{
		Scopes: []Scope{
			{FilesystemID: throttleFSID, Root: throttleDir, ReadOnly: false},
			{FilesystemID: rwFSID, Root: rwDir, ReadOnly: false},
		},
		// The credential value equals the fsID so listReq's bearer authorises it.
		Credentials: StaticCredentialValidator{Credentials: map[string]string{
			throttleFSID: throttleFSID,
			rwFSID:       rwFSID,
		}},
		PerOpThrottle: &PerOpThrottle{
			FilesystemID: throttleFSID,
			Rate:         2,
			Burst:        2,
			Now:          clock,
		},
	})

	// Burst of 6 back-to-back ops with no clock advance: the first 2 fit the
	// burst budget, the remaining 4 are refused with the throttle status.
	admitted, refused := 0, 0
	for i := 0; i < 6; i++ {
		w := listReq(t, srv, throttleFSID)
		switch w.Code {
		case http.StatusOK:
			admitted++
		case throttleRefusalStatus:
			refused++
		default:
			t.Fatalf("burst op %d: unexpected status %d", i, w.Code)
		}
	}
	if admitted != 2 {
		t.Fatalf("burst admitted %d ops, want 2 (the burst budget)", admitted)
	}
	if refused != 4 {
		t.Fatalf("burst refused %d ops, want 4 (the over-budget remainder)", refused)
	}

	// The rw scope is never charged even while the throttle scope is exhausted.
	for i := 0; i < 5; i++ {
		if w := listReq(t, srv, rwFSID); w.Code != http.StatusOK {
			t.Fatalf("rw op %d throttled (status %d); the per-op ceiling must apply only to the named scope", i, w.Code)
		}
	}

	// Advance the clock one second: at rate 2/s the bucket refills 2 tokens, so
	// the throttled scope admits again — the recover-after-backoff property.
	nowNanos.Add(int64(time.Second))
	if w := listReq(t, srv, throttleFSID); w.Code != http.StatusOK {
		t.Fatalf("after refill the throttled scope returned %d, want 200 (recover-after-backoff)", w.Code)
	}
}

// TestThrottleRefusalStatusIsUnmapped guards the load-bearing choice that the
// refusal status is NOT one the guest maps to a retryable or permission/notfound
// error: it must be an unmapped status so the guest surfaces it as EIO.
func TestThrottleRefusalStatusIsUnmapped(t *testing.T) {
	for _, mapped := range []int{
		http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusConflict, http.StatusBadRequest, http.StatusUnprocessableEntity,
		http.StatusTooManyRequests, http.StatusServiceUnavailable,
	} {
		if throttleRefusalStatus == mapped {
			t.Fatalf("throttle refusal status %d collides with a mapped status; it must be unmapped so it surfaces as EIO", throttleRefusalStatus)
		}
	}
}
