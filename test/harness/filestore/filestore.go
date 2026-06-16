// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package filestore is a self-contained test-harness peer that speaks the REST
// file-operations surface the guest mount calls: POST routes under
// v1/filestore/fs/<operation> with JSON bodies carrying filesystem_id and an
// authorization_metadata object, plus a multipart upload path and a chunked
// octet-stream download path.
//
// Each scope is a local-volume directory keyed by filesystem_id, with a
// read-only or read-write posture. The peer validates the post-exchange
// credential the inspecting edge injects on the Authorization header — it never
// sees or validates the weak session JWT directly. Missing or unknown
// credentials draw 401; a credential bound to a different filesystem_id than the
// request body draws 403; writes to a read-only scope are refused with 403.
//
// The request and response bodies mirror the guest's own message structs. The
// two are paired ends we control; the shapes are kept private to the harness and
// are not canonised here.
package filestore

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// restBase mirrors the guest client's REST path prefix. Each op routes to
// /v1/filestore/fs/<operation>.
const restBase = "/v1/filestore/fs/"

// op is a file-operation name; the values mirror the guest's op constants.
type op string

const (
	opCreateFile      op = "createFile"
	opReadFile        op = "readFile"
	opReadMetadata    op = "readMetadata"
	opListDirectory   op = "listDirectory"
	opCopyFile        op = "copyFile"
	opMoveFile        op = "moveFile"
	opRemoveFile      op = "removeFile"
	opMakeDirectory   op = "makeDirectory"
	opMoveDirectory   op = "moveDirectory"
	opRemoveDirectory op = "removeDirectory"
	opFileUpload      op = "fileUpload"
	opFileDownload    op = "fileDownload"
)

// writeIntentOps is the set of ops that mutate the filesystem. A request for any
// of these against a read-only scope is refused before the filesystem is
// touched. The classification mirrors the guest's op-to-intent table.
var writeIntentOps = map[op]bool{
	opCreateFile:      true,
	opCopyFile:        true,
	opMoveFile:        true,
	opRemoveFile:      true,
	opMakeDirectory:   true,
	opMoveDirectory:   true,
	opRemoveDirectory: true,
	opFileUpload:      true,
}

// Scope is a local-volume directory keyed by filesystem_id with a read-only or
// read-write posture.
type Scope struct {
	FilesystemID string
	Root         string
	ReadOnly     bool
}

// CredentialValidator resolves the Authorization header the edge injected to the
// filesystem_id it is bound to. A non-nil error means the credential is
// missing, unknown, or expired (the peer maps that to 401).
type CredentialValidator interface {
	Validate(authzHeader string) (subjectFilesystemID string, err error)
}

// StaticCredentialValidator is a primitive validator backed by a fixed map from
// the bearer credential value to its bound filesystem_id. The exchange peer
// issues credentials into this map in the e2e pairing.
type StaticCredentialValidator struct {
	// Credentials maps a bare credential value (the token after "Bearer ") to
	// the filesystem_id it authorises.
	Credentials map[string]string
}

// errNoCredential is returned by the validator when no usable credential is
// present; the server maps it (and any validator error) to 401.
var errNoCredential = fmt.Errorf("filestore: missing or unknown credential")

// Validate resolves the bearer credential to its bound filesystem_id.
func (v StaticCredentialValidator) Validate(authzHeader string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authzHeader, prefix) {
		return "", errNoCredential
	}
	cred := strings.TrimSpace(strings.TrimPrefix(authzHeader, prefix))
	if cred == "" {
		return "", errNoCredential
	}
	fsID, ok := v.Credentials[cred]
	if !ok {
		return "", errNoCredential
	}
	return fsID, nil
}

// Options carries Server construction parameters.
type Options struct {
	Scopes      []Scope
	Credentials CredentialValidator
	// ThrottleEvery, when > 0, makes every Nth write/upload return 429 with a
	// Retry-After header so the guest's pacer/backoff path can be exercised. A
	// value of 0 (the default) never throttles.
	ThrottleEvery int
}

// Server is the REST filestore peer.
type Server struct {
	scopes      map[string]Scope
	credentials CredentialValidator
	mux         *http.ServeMux

	throttleEvery int
	mu            sync.Mutex
	writeCount    int
}

// NewServer constructs a Server from the given options. It panics on a missing
// credential validator: a peer that accepts unvalidated requests would defeat
// the test's entire point.
func NewServer(opts Options) *Server {
	if opts.Credentials == nil {
		panic("filestore.NewServer: a CredentialValidator is required")
	}
	s := &Server{
		scopes:        make(map[string]Scope, len(opts.Scopes)),
		credentials:   opts.Credentials,
		throttleEvery: opts.ThrottleEvery,
	}
	for _, sc := range opts.Scopes {
		s.scopes[sc.FilesystemID] = sc
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc(restBase, s.route)
	return s
}

// Handler returns the peer's HTTP handler so callers can serve it under TLS or
// drive it with httptest.
func (s *Server) Handler() http.Handler { return s.mux }

// DefaultE2EScopes wires the two scopes the e2e uses: a read-only uploads scope
// and a read-write outputs scope, each keyed by its filesystem_id and backed by
// a local directory.
func DefaultE2EScopes(uploadsDir, outputsDir, uploadsFSID, outputsFSID string) []Scope {
	return []Scope{
		{FilesystemID: uploadsFSID, Root: uploadsDir, ReadOnly: true},
		{FilesystemID: outputsFSID, Root: outputsDir, ReadOnly: false},
	}
}

// TLSServer wraps the peer's handler in an httptest TLS server and returns the
// server plus its CA certificate PEM, so a caller (or a later phase) can feed
// that PEM as the trust anchor. The caller must Close the returned server.
func (s *Server) TLSServer() (*httptest.Server, []byte) {
	ts := httptest.NewTLSServer(s.Handler())
	certPEM := pemEncodeCert(ts.Certificate().Raw)
	return ts, certPEM
}

// route is the single mux handler: it authenticates, authorises against the
// scope, then dispatches to the per-op handler.
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}
	opName := op(strings.TrimPrefix(r.URL.Path, restBase))

	// fileUpload carries its body as multipart; all other ops carry JSON. The
	// upload handler parses its own body and runs auth itself because the
	// filesystem_id lives in the multipart "params" field, so route only
	// dispatches it here.
	if opName == opFileUpload {
		s.handleFileUpload(w, r)
		return
	}

	// Authenticate the injected credential.
	subjectFSID, err := s.credentials.Validate(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing or unknown credential")
		return
	}

	// Decode the JSON body far enough to read the filesystem_id and intent.
	body, err := decodeCommon(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	scope, status, msg := s.authorize(opName, subjectFSID, body.FilesystemID)
	if status != 0 {
		writeError(w, status, msg)
		return
	}

	s.dispatch(w, r, opName, scope, body)
}

// commonBody is the shared prefix of every JSON request body: the scope handle
// and the authorization metadata. Op-specific fields are decoded by each
// handler from the raw body.
type commonBody struct {
	FilesystemID          string                `json:"filesystem_id"`
	AuthorizationMetadata authorizationMetadata `json:"authorization_metadata"`
	raw                   []byte
}

// authorizationMetadata mirrors the guest's stamped metadata.
type authorizationMetadata struct {
	Intent       string `json:"intent"`
	Downloadable bool   `json:"downloadable"`
}

// decodeCommon reads the request body and decodes the shared prefix, retaining
// the raw bytes so the per-op handler can decode its own fields.
func decodeCommon(r *http.Request) (commonBody, error) {
	raw, err := readAllLimited(r.Body)
	if err != nil {
		return commonBody{}, err
	}
	var cb commonBody
	if err := json.Unmarshal(raw, &cb); err != nil {
		return commonBody{}, err
	}
	cb.raw = raw
	return cb, nil
}

// authorize applies the scope rules for a JSON-bodied op: it resolves the
// requested scope, enforces that the credential's bound filesystem_id matches
// the requested one, and refuses writes to a read-only scope. A zero status
// means authorised; otherwise it returns the HTTP status and message to send.
func (s *Server) authorize(opName op, subjectFSID, requestedFSID string) (Scope, int, string) {
	if requestedFSID == "" {
		return Scope{}, http.StatusBadRequest, "filesystem_id is required"
	}
	if subjectFSID != requestedFSID {
		// The credential is bound to a different scope than the request targets.
		return Scope{}, http.StatusForbidden, "credential is not bound to the requested filesystem_id"
	}
	scope, ok := s.scopes[requestedFSID]
	if !ok {
		return Scope{}, http.StatusForbidden, "unknown filesystem_id"
	}
	if scope.ReadOnly && writeIntentOps[opName] {
		return Scope{}, http.StatusForbidden, "scope is read-only; write refused"
	}
	return scope, 0, ""
}

// dispatch routes an authorised JSON op to its handler.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, opName op, scope Scope, body commonBody) {
	switch opName {
	case opCreateFile:
		s.handleCreateFile(w, scope, body)
	case opReadFile:
		s.handleReadFile(w, scope, body)
	case opReadMetadata:
		s.handleReadMetadata(w, scope, body)
	case opListDirectory:
		s.handleListDirectory(w, scope, body)
	case opCopyFile:
		s.handleCopyFile(w, scope, body)
	case opMoveFile:
		s.handleMoveFile(w, scope, body)
	case opRemoveFile:
		s.handleRemoveFile(w, scope, body)
	case opMakeDirectory:
		s.handleMakeDirectory(w, scope, body)
	case opMoveDirectory:
		s.handleMoveDirectory(w, scope, body)
	case opRemoveDirectory:
		s.handleRemoveDirectory(w, scope, body)
	case opFileDownload:
		s.handleFileDownload(w, scope, body)
	default:
		writeError(w, http.StatusNotFound, "unimplemented operation")
	}
}

// writeJSON writes a 200 JSON response.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// errorBody is the JSON shape returned for a non-2xx outcome.
type errorBody struct {
	Error string `json:"error"`
}

// writeError writes a non-2xx JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg})
}
