// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	fsUploads = "fs-uploads" // read-only scope
	fsOutputs = "fs-outputs" // read-write scope
)

// testEnv wires a filestore peer over two scopes with a static credential map,
// returning the running server and helpers bound to the issued credentials.
type testEnv struct {
	ts          *httptest.Server
	uploadsCred string
	outputsCred string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	uploadsDir := t.TempDir()
	outputsDir := t.TempDir()
	creds := map[string]string{
		"cred-uploads": fsUploads,
		"cred-outputs": fsOutputs,
	}
	srv := NewServer(Options{
		Scopes:      DefaultE2EScopes(uploadsDir, outputsDir, fsUploads, fsOutputs),
		Credentials: StaticCredentialValidator{Credentials: creds},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, uploadsCred: "cred-uploads", outputsCred: "cred-outputs"}
}

// post issues a JSON op against the peer with the given bearer credential.
func (e *testEnv) post(t *testing.T, cred, opName string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+restBase+opName, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// newRunning starts an httptest server for srv and registers its cleanup.
func newRunning(t *testing.T, srv *Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// uploadRaw posts a multipart upload with caller-controlled params and an
// optional file part, for exercising malformed-request arms. When withFile is
// true a "file" part is written with content (which may be empty).
func (e *testEnv) uploadRaw(t *testing.T, cred, params string, content []byte, withFile bool) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if params != "" {
		if err := mw.WriteField("params", params); err != nil {
			t.Fatalf("write params: %v", err)
		}
	}
	if withFile {
		fp, err := mw.CreateFormFile("file", "upload")
		if err != nil {
			t.Fatalf("create file part: %v", err)
		}
		if _, err := fp.Write(content); err != nil {
			t.Fatalf("write file part: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close mw: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+restBase+string(opFileUpload), &buf)
	if err != nil {
		t.Fatalf("new upload request: %v", err)
	}
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do upload: %v", err)
	}
	return resp
}

func jsonBody(fsID, intent string, extra map[string]any) map[string]any {
	body := map[string]any{
		"filesystem_id":          fsID,
		"authorization_metadata": map[string]any{"intent": intent, "downloadable": false},
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func TestForeignScopeForbidden(t *testing.T) {
	e := newTestEnv(t)
	// Credential bound to outputs, request targets uploads: 403.
	resp := e.post(t, e.outputsCred, string(opReadMetadata), jsonBody(fsUploads, "read", map[string]any{"path": "/x"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign scope: got %d want 403", resp.StatusCode)
	}
}

func TestMissingCredentialUnauthorized(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, "", string(opReadMetadata), jsonBody(fsOutputs, "read", map[string]any{"path": "/x"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing credential: got %d want 401", resp.StatusCode)
	}
}

func TestUnknownCredentialUnauthorized(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, "bogus-credential", string(opReadMetadata), jsonBody(fsOutputs, "read", map[string]any{"path": "/x"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown credential: got %d want 401", resp.StatusCode)
	}
}

func TestWriteOnReadOnlyForbidden(t *testing.T) {
	e := newTestEnv(t)
	// createFile is a write intent; the uploads scope is read-only: 403.
	resp := e.post(t, e.uploadsCred, string(opCreateFile), jsonBody(fsUploads, "write", map[string]any{"path": "/new.txt"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write on read-only: got %d want 403", resp.StatusCode)
	}
}

func TestCreateReadListRoundTrip(t *testing.T) {
	e := newTestEnv(t)

	// Create a file in the read-write outputs scope.
	resp := e.post(t, e.outputsCred, string(opCreateFile), jsonBody(fsOutputs, "write", map[string]any{"path": "/dir/a.txt"}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: got %d want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// readMetadata sees it.
	resp = e.post(t, e.outputsCred, string(opReadMetadata), jsonBody(fsOutputs, "read", map[string]any{"path": "/dir/a.txt"}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readMetadata: got %d want 200", resp.StatusCode)
	}
	var meta struct {
		File wireFile `json:"file"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	_ = resp.Body.Close()
	if meta.File.Path != "/dir/a.txt" {
		t.Fatalf("metadata path: got %q", meta.File.Path)
	}

	// listDirectory shows the entry.
	resp = e.post(t, e.outputsCred, string(opListDirectory), jsonBody(fsOutputs, "read", map[string]any{"path": "/dir"}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listDirectory: got %d want 200", resp.StatusCode)
	}
	var list struct {
		Entries []listDirEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	_ = resp.Body.Close()
	if len(list.Entries) != 1 || list.Entries[0].File == nil {
		t.Fatalf("list entries: got %+v", list.Entries)
	}
}

// upload streams a small file part with the matching params field.
func (e *testEnv) upload(t *testing.T, cred, fsID, path string, content []byte, overwrite bool) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	params := map[string]any{
		"filesystem_id":          fsID,
		"path":                   path,
		"declared_size_bytes":    len(content),
		"authorization_metadata": map[string]any{"intent": "write", "downloadable": false},
	}
	if overwrite {
		params["overwrite_existing"] = true
	}
	raw, _ := json.Marshal(params)
	if err := mw.WriteField("params", string(raw)); err != nil {
		t.Fatalf("write params: %v", err)
	}
	fp, err := mw.CreateFormFile("file", "upload")
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fp.Write(content); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close mw: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+restBase+string(opFileUpload), &buf)
	if err != nil {
		t.Fatalf("new upload request: %v", err)
	}
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do upload: %v", err)
	}
	return resp
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	content := []byte("hello round-trip body")

	resp := e.upload(t, e.outputsCred, fsOutputs, "/out/file.bin", content, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: got %d want 200", resp.StatusCode)
	}
	var up struct {
		File wireFile `json:"file"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&up); err != nil {
		t.Fatalf("decode upload resp: %v", err)
	}
	_ = resp.Body.Close()
	if up.File.UUID == "" {
		t.Fatalf("upload returned no uuid")
	}

	// Download by uuid and compare bytes.
	dl := e.post(t, e.outputsCred, string(opFileDownload), map[string]any{
		"filesystem_id":          fsOutputs,
		"uuid":                   up.File.UUID,
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": false},
	})
	if dl.StatusCode != http.StatusOK {
		t.Fatalf("download: got %d want 200", dl.StatusCode)
	}
	got, err := io.ReadAll(dl.Body)
	_ = dl.Body.Close()
	if err != nil {
		t.Fatalf("read download body: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("download mismatch: got %q want %q", got, content)
	}
	if ct := dl.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("download content-type: got %q", ct)
	}
}

func TestDownloadRangeWindow(t *testing.T) {
	e := newTestEnv(t)
	content := []byte("0123456789")
	resp := e.upload(t, e.outputsCred, fsOutputs, "/ranged.bin", content, false)
	var up struct {
		File wireFile `json:"file"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&up)
	_ = resp.Body.Close()

	dl := e.post(t, e.outputsCred, string(opFileDownload), map[string]any{
		"filesystem_id":          fsOutputs,
		"uuid":                   up.File.UUID,
		"range":                  map[string]any{"offset": 2, "length": 3},
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": false},
	})
	got, _ := io.ReadAll(dl.Body)
	_ = dl.Body.Close()
	if string(got) != "234" {
		t.Fatalf("range window: got %q want %q", got, "234")
	}
}

func TestDownloadUnknownUUIDNotFound(t *testing.T) {
	e := newTestEnv(t)
	dl := e.post(t, e.outputsCred, string(opFileDownload), map[string]any{
		"filesystem_id":          fsOutputs,
		"uuid":                   "deadbeefdeadbeefdeadbeefdeadbeef",
		"authorization_metadata": map[string]any{"intent": "read", "downloadable": false},
	})
	defer func() { _ = dl.Body.Close() }()
	if dl.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown uuid: got %d want 404", dl.StatusCode)
	}
}

func TestUploadMissingCredentialUnauthorized(t *testing.T) {
	e := newTestEnv(t)
	resp := e.upload(t, "", fsOutputs, "/x.bin", []byte("x"), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("upload without credential: got %d want 401", resp.StatusCode)
	}
}

func TestUploadOnReadOnlyForbidden(t *testing.T) {
	e := newTestEnv(t)
	resp := e.upload(t, e.uploadsCred, fsUploads, "/x.bin", []byte("x"), false)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("upload on read-only: got %d want 403", resp.StatusCode)
	}
}

func TestUploadDeclaredSizeMismatch(t *testing.T) {
	e := newTestEnv(t)
	// Hand-build a params with a wrong declared_size_bytes.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	params := map[string]any{
		"filesystem_id":          fsOutputs,
		"path":                   "/mismatch.bin",
		"declared_size_bytes":    999,
		"authorization_metadata": map[string]any{"intent": "write", "downloadable": false},
	}
	raw, _ := json.Marshal(params)
	_ = mw.WriteField("params", string(raw))
	fp, _ := mw.CreateFormFile("file", "upload")
	_, _ = fp.Write([]byte("short"))
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+restBase+string(opFileUpload), &buf)
	req.Header.Set("Authorization", "Bearer "+e.outputsCred)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("size mismatch: got %d want 422", resp.StatusCode)
	}
}

// TestUploadZeroDeclaredSizeRejectsNonEmptyBody pins the size-match fix: a body
// streamed against declared_size_bytes=0 must be rejected, not silently
// accepted. Before the fix the size check was skipped whenever the declared size
// was 0, so a non-empty stream slipped through against a 0 declaration.
func TestUploadZeroDeclaredSizeRejectsNonEmptyBody(t *testing.T) {
	e := newTestEnv(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	params := map[string]any{
		"filesystem_id":          fsOutputs,
		"path":                   "/zero-decl.bin",
		"declared_size_bytes":    0,
		"authorization_metadata": map[string]any{"intent": "write", "downloadable": false},
	}
	raw, _ := json.Marshal(params)
	_ = mw.WriteField("params", string(raw))
	fp, _ := mw.CreateFormFile("file", "upload")
	_, _ = fp.Write([]byte("not empty")) // 9 bytes against a declared 0
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+restBase+string(opFileUpload), &buf)
	req.Header.Set("Authorization", "Bearer "+e.outputsCred)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("non-empty body against declared 0: got %d want 422", resp.StatusCode)
	}
}

func TestUploadThrottle(t *testing.T) {
	uploadsDir := t.TempDir()
	outputsDir := t.TempDir()
	srv := NewServer(Options{
		Scopes:        DefaultE2EScopes(uploadsDir, outputsDir, fsUploads, fsOutputs),
		Credentials:   StaticCredentialValidator{Credentials: map[string]string{"c": fsOutputs}},
		ThrottleEvery: 2,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	env := &testEnv{ts: ts, outputsCred: "c"}

	// First upload succeeds; the second is throttled (429 + Retry-After).
	r1 := env.upload(t, "c", fsOutputs, "/a.bin", []byte("a"), false)
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first upload: got %d want 200", r1.StatusCode)
	}
	_ = r1.Body.Close()
	r2 := env.upload(t, "c", fsOutputs, "/b.bin", []byte("b"), false)
	defer func() { _ = r2.Body.Close() }()
	if r2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second upload: got %d want 429", r2.StatusCode)
	}
	if ra := r2.Header.Get("Retry-After"); ra == "" {
		t.Fatalf("throttled response missing Retry-After")
	}
}

func TestNewServerPanicsWithoutValidator(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for nil validator")
		}
	}()
	_ = NewServer(Options{})
}

func TestRouteRejectsNonPost(t *testing.T) {
	e := newTestEnv(t)
	resp, err := http.Get(e.ts.URL + restBase + string(opReadMetadata))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET op: got %d want 405", resp.StatusCode)
	}
}

func TestTraversalGuard(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, e.outputsCred, string(opReadMetadata), jsonBody(fsOutputs, "read", map[string]any{"path": "/../../etc/passwd"}))
	defer func() { _ = resp.Body.Close() }()
	// The traversal is cleaned to a path under the scope root, which does not
	// exist, so the peer returns 404 rather than escaping the volume.
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("traversal guard: got %d want 404", resp.StatusCode)
	}
}

func TestTLSServerExposesCert(t *testing.T) {
	srv := NewServer(Options{
		Scopes:      []Scope{{FilesystemID: fsOutputs, Root: t.TempDir(), ReadOnly: false}},
		Credentials: StaticCredentialValidator{Credentials: map[string]string{"c": fsOutputs}},
	})
	ts, certPEM := srv.TLSServer()
	defer ts.Close()
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("TLSServer returned no PEM cert")
	}
}

func TestCopyMoveRemove(t *testing.T) {
	e := newTestEnv(t)
	mk := func(op, path string, body map[string]any) int {
		resp := e.post(t, e.outputsCred, op, jsonBody(fsOutputs, "write", body))
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	if s := mk(string(opCreateFile), "", map[string]any{"path": "/src.txt"}); s != http.StatusOK {
		t.Fatalf("create src: %d", s)
	}
	if s := mk(string(opCopyFile), "", map[string]any{"source": "/src.txt", "destination": "/copy.txt"}); s != http.StatusOK {
		t.Fatalf("copy: %d", s)
	}
	if s := mk(string(opMoveFile), "", map[string]any{"source": "/copy.txt", "destination": "/moved.txt"}); s != http.StatusOK {
		t.Fatalf("move: %d", s)
	}
	if s := mk(string(opMakeDirectory), "", map[string]any{"path": "/d"}); s != http.StatusOK {
		t.Fatalf("mkdir: %d", s)
	}
	if s := mk(string(opMoveDirectory), "", map[string]any{"source": "/d", "destination": "/d2"}); s != http.StatusOK {
		t.Fatalf("movedir: %d", s)
	}
	if s := mk(string(opRemoveFile), "", map[string]any{"path": "/moved.txt"}); s != http.StatusOK {
		t.Fatalf("rm file: %d", s)
	}
	if s := mk(string(opRemoveDirectory), "", map[string]any{"path": "/d2"}); s != http.StatusOK {
		t.Fatalf("rmdir: %d", s)
	}
}

func TestReadFileMetadataOnly(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, e.outputsCred, string(opCreateFile), jsonBody(fsOutputs, "write", map[string]any{"path": "/rf.txt"}))
	_ = resp.Body.Close()
	resp = e.post(t, e.outputsCred, string(opReadFile), jsonBody(fsOutputs, "read", map[string]any{"path": "/rf.txt"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readFile: got %d want 200", resp.StatusCode)
	}
}

func TestUnknownOpNotFound(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, e.outputsCred, "importFiles", jsonBody(fsOutputs, "read", map[string]any{"path": "/"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown op: got %d want 404", resp.StatusCode)
	}
}

func TestMalformedJSONBadRequest(t *testing.T) {
	e := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+restBase+string(opReadMetadata), strings.NewReader("{not json"))
	req.Header.Set("Authorization", "Bearer "+e.outputsCred)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed json: got %d want 400", resp.StatusCode)
	}
}
