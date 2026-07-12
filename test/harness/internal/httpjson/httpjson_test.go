// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package httpjson

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestErrorWritesAnErrorEnvelope checks Error emits the status, the JSON content
// type, and an {"error": msg} body.
func TestErrorWritesAnErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, http.StatusBadRequest, "malformed request body")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusBadRequest)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q; want application/json", ct)
	}
	var got errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Error != "malformed request body" {
		t.Fatalf("error = %q; want %q", got.Error, "malformed request body")
	}
}

// TestOKWritesA200Envelope checks OK emits a 200, the JSON content type, and the
// encoded value.
func TestOKWritesA200Envelope(t *testing.T) {
	rec := httptest.NewRecorder()
	OK(rec, map[string]string{"token": "abc"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q; want application/json", ct)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["token"] != "abc" {
		t.Fatalf("token = %q; want abc", got["token"])
	}
}
