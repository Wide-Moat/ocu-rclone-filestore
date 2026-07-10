// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

// fakebroker_test.go — an in-process httptest TLS server speaking the REST wire
// shapes the guest now uses:
//
//   - Unary ops: POST /v1/filestore/fs/<op> with a JSON body; JSON response.
//     The listDirectory response serves the pinned union entries array
//     [{file:{…mtime…}},{directory:{…mtime…}}].
//
//   - fileUpload: multipart/form-data (a "params" JSON field plus a file part).
//
//   - fileDownload: a chunked application/octet-stream body carrying the object
//     bytes directly.
//
// Every request must carry Authorization: Bearer <fakeBrokerAuthToken>; a
// missing/wrong credential draws 401. The fake lets a real *Fs be constructed
// via registry → NewFs → brokerrpc.New over TLS with no production test-hook.

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBrokerContentBytes are the canned bytes served for a Download request.
var fakeBrokerContentBytes = []byte("fake-content-data")

// fakeBrokerAuthToken is the static credential every fake-broker request must
// carry as Authorization: Bearer.
const fakeBrokerAuthToken = "fake-broker-jwt"

// fakeBrokerFileMtime is the RFC3339 mtime used in all file entries.
var fakeBrokerFileMtime = time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)

// fakeBrokerDirMtime is the RFC3339 mtime used in all directory entries.
var fakeBrokerDirMtime = time.Date(2026, 5, 18, 8, 0, 0, 0, time.UTC).Format(time.RFC3339)

// fakeBroker bundles the running TLS server's URL and its leaf certificate PEM
// so tests can construct a Client/configmap that trusts it.
type fakeBroker struct {
	url     string
	certPEM []byte
}

// startFakeBroker starts an in-process httptest TLS server speaking the REST
// wire shapes and registers a t.Cleanup to stop it.
func startFakeBroker(t *testing.T) fakeBroker {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(fakeBrokerHandler))
	t.Cleanup(srv.Close)
	return fakeBroker{url: srv.URL, certPEM: certPEMOf(srv)}
}

// requireAuth enforces the Bearer credential; it returns false (and writes 401)
// when the credential is missing or wrong.
func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+fakeBrokerAuthToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("missing or invalid credential"))
		return false
	}
	return true
}

// fakeBrokerHandler dispatches by the REST op extracted from the URL path.
func fakeBrokerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !requireAuth(w, r) {
		return
	}

	const prefix = "/v1/filestore/fs/"
	op := strings.TrimPrefix(r.URL.Path, prefix)

	switch op {
	case "listDirectory":
		serveListDirectory(w, r)
	case "readMetadata":
		serveReadMetadata(w, r)
	case "makeDirectory", "removeDirectory", "moveDirectory", "copyFile", "moveFile", "removeFile":
		serveAck(w, r)
	case "fileUpload":
		serveFileUpload(w, r)
	case "fileDownload":
		serveFileDownload(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("unknown op " + op))
	}
}

// writeJSON writes v as an application/json 200 response.
func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// serveListDirectory serves the pinned listDirectory union page (one file arm +
// one directory arm). The child paths derive from the request body's path.
func serveListDirectory(w http.ResponseWriter, r *http.Request) {
	dirPath := requestPath(r)
	if dirPath == "" {
		dirPath = "/testdir"
	}
	body := `{"entries":[` +
		`{"file":{"path":"` + dirPath + `/fakefile.txt","size":17,"uuid":"fake-file-uuid-001","mime":"text/plain","mtime":"` + fakeBrokerFileMtime + `"}},` +
		`{"directory":{"path":"` + dirPath + `/fakesub","mtime":"` + fakeBrokerDirMtime + `"}}` +
		`],"cursor":""}`
	writeJSON(w, body)
}

// serveReadMetadata serves a canned file-arm ReadMetadata response for the
// requested path.
func serveReadMetadata(w http.ResponseWriter, r *http.Request) {
	p := requestPath(r)
	if p == "" {
		p = "/fake/path"
	}
	body := `{"file":{"path":"` + p + `","size":17,"uuid":"fake-meta-uuid-002","mime":"text/plain","mtime":"` + fakeBrokerFileMtime + `"}}`
	writeJSON(w, body)
}

// serveAck serves the bare-ack {} response for mutating ops.
func serveAck(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, `{}`)
}

// serveFileDownload streams the canned content as a chunked octet-stream body,
// honouring an optional {offset, length} request window clamped to the content
// size. The client fails ranged over-delivery closed, so the fake must serve
// exactly the requested window, as the real south face does.
func serveFileDownload(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Range *struct {
			Offset int64 `json:"offset"`
			Length int64 `json:"length"`
		} `json:"range"`
	}
	_ = json.Unmarshal(body, &req)
	out := fakeBrokerContentBytes
	if req.Range != nil {
		start, end := req.Range.Offset, req.Range.Offset+req.Range.Length
		if start > int64(len(out)) {
			start = int64(len(out))
		}
		if end > int64(len(out)) {
			end = int64(len(out))
		}
		out = out[start:end]
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// serveFileUpload drains the multipart body and replies 200.
func serveFileUpload(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	w.WriteHeader(http.StatusOK)
}

// requestPath decodes the `path` field from a unary JSON request body.
func requestPath(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	return jsonStringField(body, "path")
}

// ---------------------------------------------------------------------------
// Capturing fake broker — records the decoded two-path bodies (copyFile,
// moveFile, moveDirectory) so a test can assert source/destination land in the
// correct wire slots.
// ---------------------------------------------------------------------------

// twoPathBody is the decoded shape of the two-path mutating ops.
type twoPathBody struct {
	Source      string
	Destination string
}

// capturingBroker records the most recent two-path body per op.
type capturingBroker struct {
	mu      sync.Mutex
	byOp    map[string]twoPathBody
	seenOps map[string]int
}

func (b *capturingBroker) lastTwoPath(op string) (twoPathBody, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.byOp[op]
	return v, ok
}

func (b *capturingBroker) callCount(op string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seenOps[op]
}

// startCapturingFakeBroker behaves like startFakeBroker but captures the decoded
// request body of the two-path ops.
func startCapturingFakeBroker(t *testing.T) (fakeBroker, *capturingBroker) {
	t.Helper()
	cap := &capturingBroker{
		byOp:    make(map[string]twoPathBody),
		seenOps: make(map[string]int),
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !requireAuth(w, r) {
			return
		}
		const prefix = "/v1/filestore/fs/"
		op := strings.TrimPrefix(r.URL.Path, prefix)
		switch op {
		case "copyFile", "moveFile", "moveDirectory":
			body, _ := io.ReadAll(r.Body)
			cap.mu.Lock()
			cap.byOp[op] = twoPathBody{
				Source:      jsonStringField(body, "source"),
				Destination: jsonStringField(body, "destination"),
			}
			cap.seenOps[op]++
			cap.mu.Unlock()
			serveAck(w, r)
		default:
			// Re-dispatch without the body-capture; auth already checked.
			dispatchNoAuth(w, r, op)
		}
	}))
	t.Cleanup(srv.Close)
	return fakeBroker{url: srv.URL, certPEM: certPEMOf(srv)}, cap
}

// dispatchNoAuth routes an already-authenticated request to the canned servers.
func dispatchNoAuth(w http.ResponseWriter, r *http.Request, op string) {
	switch op {
	case "listDirectory":
		serveListDirectory(w, r)
	case "readMetadata":
		serveReadMetadata(w, r)
	case "makeDirectory", "removeDirectory", "removeFile":
		serveAck(w, r)
	case "fileUpload":
		serveFileUpload(w, r)
	case "fileDownload":
		serveFileDownload(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// jsonStringField extracts a top-level string field from a JSON object body
// without a struct dependency, so the fake is an independent observer of the
// wire. It is a deliberately small decoder: only top-level string values.
func jsonStringField(body []byte, field string) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}

// certPEMOf returns the PEM-encoded leaf certificate of a TLS test server.
func certPEMOf(srv *httptest.Server) []byte {
	cert := srv.Certificate()
	if cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
