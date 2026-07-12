// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package httpjson holds the two JSON response writers the harness peers share:
// a non-2xx error responder that emits {"error": msg}, and a 200 responder that
// encodes an arbitrary value. Both set the JSON content type before writing the
// status so the header is not stranded after WriteHeader.
package httpjson

import (
	"encoding/json"
	"net/http"
)

// errorBody is the JSON shape returned for a non-2xx outcome.
type errorBody struct {
	Error string `json:"error"`
}

// Error writes a non-2xx JSON error response of the form {"error": msg}.
func Error(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg})
}

// OK writes a 200 JSON response encoding v.
func OK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}
