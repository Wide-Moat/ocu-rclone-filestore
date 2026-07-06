// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

// uploadAndDownload covers the multipart fileUpload and the chunked fileDownload
// happy paths plus a couple of error arms, against the real server.
func TestUploadAndDownloadArms(t *testing.T) {
	root := t.TempDir()
	srv := MustNewServer(Options{
		Scopes:      []Scope{{FilesystemID: "fsrw", Root: root, ReadOnly: false}},
		Credentials: StaticCredentialValidator{Credentials: map[string]string{"rw-cred": "fsrw"}},
	})

	payload := []byte("the quick brown fox jumps over the lazy dog")

	// --- fileUpload (multipart) ---
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	params, _ := json.Marshal(map[string]any{
		"filesystem_id":          "fsrw",
		"path":                   "up.txt",
		"declared_size_bytes":    len(payload),
		"authorization_metadata": map[string]any{"intent": "write"},
	})
	_ = mw.WriteField("params", string(params))
	fw, _ := mw.CreateFormFile("file", "up.txt")
	_, _ = fw.Write(payload)
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, restBase+string(opFileUpload), &buf)
	r.Header.Set("Authorization", "Bearer rw-cred")
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("fileUpload returned %d, want 200: %s", w.Code, w.Body.String())
	}
	var up struct {
		File struct {
			UUID string `json:"uuid"`
		} `json:"file"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &up); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if up.File.UUID == "" {
		t.Fatal("fileUpload returned no uuid")
	}

	// --- fileDownload (whole object) ---
	dl := download(t, srv, up.File.UUID, nil)
	if dl.Code != http.StatusOK {
		t.Fatalf("fileDownload returned %d, want 200", dl.Code)
	}
	if !bytes.Equal(dl.Body.Bytes(), payload) {
		t.Fatalf("downloaded bytes mismatch")
	}

	// --- fileDownload with a range window ---
	rng := download(t, srv, up.File.UUID, map[string]any{"offset": 4, "length": 5})
	if rng.Code != http.StatusOK {
		t.Fatalf("ranged fileDownload returned %d, want 200", rng.Code)
	}
	if got := rng.Body.String(); got != "quick" {
		t.Fatalf("ranged download = %q, want %q", got, "quick")
	}

	// --- fileDownload error arms: missing uuid (400), unknown uuid (404),
	// negative range (400). ---
	if w := download(t, srv, "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("download with no uuid returned %d, want 400", w.Code)
	}
	if w := download(t, srv, "deadbeef", nil); w.Code != http.StatusNotFound {
		t.Fatalf("download of an unknown uuid returned %d, want 404", w.Code)
	}
	if w := download(t, srv, up.File.UUID, map[string]any{"offset": -1, "length": 1}); w.Code != http.StatusBadRequest {
		t.Fatalf("download with a negative range returned %d, want 400", w.Code)
	}

	// --- fileUpload error arms: a declared-size mismatch is a 422; an upload to
	// an existing path without overwrite is a 409. ---
	if w := upload(t, srv, "mismatch.txt", []byte("abc"), 999, false); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("upload with a declared-size mismatch returned %d, want 422", w.Code)
	}
	if w := upload(t, srv, "up.txt", payload, len(payload), false); w.Code != http.StatusConflict {
		t.Fatalf("upload over an existing path without overwrite returned %d, want 409", w.Code)
	}
	// Overwrite allowed -> 200.
	if w := upload(t, srv, "up.txt", payload, len(payload), true); w.Code != http.StatusOK {
		t.Fatalf("upload with overwrite returned %d, want 200", w.Code)
	}
}

// upload posts a multipart fileUpload and returns the recorder.
func upload(t *testing.T, srv *Server, path string, data []byte, declared int, overwrite bool) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	params, _ := json.Marshal(map[string]any{
		"filesystem_id":          "fsrw",
		"path":                   path,
		"declared_size_bytes":    declared,
		"overwrite_existing":     overwrite,
		"authorization_metadata": map[string]any{"intent": "write"},
	})
	_ = mw.WriteField("params", string(params))
	fw, _ := mw.CreateFormFile("file", path)
	_, _ = fw.Write(data)
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, restBase+string(opFileUpload), &buf)
	r.Header.Set("Authorization", "Bearer rw-cred")
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// download posts a fileDownload request and returns the recorder.
func download(t *testing.T, srv *Server, uuid string, rng map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{
		"filesystem_id":          "fsrw",
		"authorization_metadata": map[string]any{"intent": "read"},
	}
	if uuid != "" {
		body["uuid"] = uuid
	}
	if rng != nil {
		body["range"] = rng
	}
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, restBase+string(opFileDownload), bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer rw-cred")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}
