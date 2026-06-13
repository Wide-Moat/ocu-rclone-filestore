// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

// fakebroker_test.go — an in-process net/http fake broker bound to a temp unix
// socket. It serves the LOCKED wire shapes from CANON-DIVERGENCE-INDEX.md:
//
//   - Unary ops: POST /ocu.filestore.v1alpha.FilesystemService/<op>
//     Content-Type: application/json response.
//     The listDirectory response serves the pinned union entries array
//     [{file:{…mtime…}},{directory:{…mtime…}}] keyed on the `mtime` wire key
//     that the tolerant structs currently decode (design decision 5 from 03-02).
//
//   - Streaming ops (fileUpload, fileDownload): 5-byte frame envelope
//     (1 flag byte + 4-byte big-endian length); end-stream flag 0x02 on the
//     final frame carrying EndStreamResponse.
//
// The fake allows a real *Fs to be constructed via
//   registry → NewFs → brokerrpc.New → the temp unix socket
// with no production test-hook.
//
// This fake is NOT the real broker. It can faithfully satisfy:
//   registration, NewFs construction, listDirectory union classification,
//   request shape assertions, and basic read round-trips.
// Real persistence (write→read-back, list-after-write) requires a live broker
// and is gated behind RCLONE_OCUFS_LIVE for Phase 5.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBrokerContentBytes are the canned bytes served for a Download request.
// This allows a basic read round-trip to succeed for tests that need it.
var fakeBrokerContentBytes = []byte("fake-content-data")

// fakeBrokerFileMtime is the RFC3339 mtime used in all file entries served by
// the fake broker. It uses the `mtime` wire key (the struct's current tag).
var fakeBrokerFileMtime = time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC).
	Format(time.RFC3339)

// fakeBrokerDirMtime is the RFC3339 mtime used in all directory entries.
var fakeBrokerDirMtime = time.Date(2026, 5, 18, 8, 0, 0, 0, time.UTC).
	Format(time.RFC3339)

// startFakeBroker starts an in-process HTTP server on a temp unix socket and
// registers a t.Cleanup to stop it. It returns the socket path and the HTTP
// server instance.
//
// The server routes every POST to /ocu.filestore.v1alpha.FilesystemService/<op>
// and serves canned locked-wire-shape responses so brokerrpc.Client can parse
// them correctly.
func startFakeBroker(t *testing.T) string {
	t.Helper()

	// Use os.CreateTemp to get a short path in /tmp, then remove the file and
	// use the path for the unix socket. The macOS unix socket path limit is 104
	// bytes; t.TempDir() paths are often >104 chars and bind would fail.
	f, err := os.CreateTemp("", "ocufs-test-*.sock")
	if err != nil {
		t.Fatalf("startFakeBroker: create temp socket file: %v", err)
	}
	sockPath := f.Name()
	f.Close()
	// Remove the placeholder file so net.Listen can create the socket there.
	os.Remove(sockPath) //nolint:errcheck

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("startFakeBroker: listen unix %s: %v", sockPath, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", fakeBrokerHandler)

	srv := &http.Server{Handler: mux}
	go func() {
		// Serve returns when the listener is closed; that is expected.
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	return sockPath
}

// fakeBrokerHandler dispatches incoming requests to the appropriate canned
// response builder based on the op extracted from the URL path.
func fakeBrokerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"code":"not_found","message":"method not allowed"}`, http.StatusNotFound)
		return
	}

	// Extract the op name from the URL path:
	//   /ocu.filestore.v1alpha.FilesystemService/<op>
	const prefix = "/ocu.filestore.v1alpha.FilesystemService/"
	op := strings.TrimPrefix(r.URL.Path, prefix)

	switch op {
	case "listDirectory":
		serveListDirectory(w, r)
	case "readMetadata":
		serveReadMetadata(w, r)
	case "makeDirectory":
		serveAck(w, r)
	case "removeDirectory":
		serveAck(w, r)
	case "moveDirectory":
		serveAck(w, r)
	case "copyFile":
		serveAck(w, r)
	case "moveFile":
		serveAck(w, r)
	case "removeFile":
		serveAck(w, r)
	case "fileUpload":
		serveFileUpload(w, r)
	case "fileDownload":
		serveFileDownload(w, r)
	default:
		// Unknown op: return a connect-style not_found error.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"code":"not_found","message":"unknown op %q"}`, op)
	}
}

// ---------------------------------------------------------------------------
// Unary op response helpers
// ---------------------------------------------------------------------------

// writeJSON marshals v to JSON and writes it as an application/json response
// with HTTP 200.
func writeJSON(w http.ResponseWriter, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"code":"internal","message":"marshal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// fakeBrokerFileEntry is the file arm of the listDirectory union entry as the
// tolerant struct currently decodes it. Uses the `mtime` wire key (design
// decision 5 from 03-02) so parseMtime returns a non-zero time.
type fakeBrokerFileEntry struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	UUID  string `json:"uuid"`
	MIME  string `json:"mime"`
	Mtime string `json:"mtime"`
}

// fakeBrokerDirEntry is the directory arm. Uses the `mtime` wire key.
type fakeBrokerDirEntry struct {
	Path  string `json:"path"`
	Mtime string `json:"mtime"`
}

// fakeBrokerListDirEntry represents one entry in the entries array.
// One of File or Directory will be non-nil; the other is omitted (JSON
// omitempty) — the discriminator used by ListDirEntry decoder.
type fakeBrokerListDirEntry struct {
	File      *fakeBrokerFileEntry `json:"file,omitempty"`
	Directory *fakeBrokerDirEntry  `json:"directory,omitempty"`
}

// serveListDirectory serves the pinned listDirectory union page. The page
// contains one file arm and one directory arm so both arms of the union
// decoder and the direct List classification are exercised.
//
// The broker path is extracted from the request body's `path` field so the
// fake can build sensible child paths; falls back to "/testdir" on any parse
// error (tolerant, keeps the test from crashing on unexpected requests).
func serveListDirectory(w http.ResponseWriter, r *http.Request) {
	// Decode the request body to extract the path for child construction.
	var req struct {
		Path string `json:"path"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)
	dirPath := req.Path
	if dirPath == "" {
		dirPath = "/testdir"
	}

	entries := []fakeBrokerListDirEntry{
		{File: &fakeBrokerFileEntry{
			Path:  dirPath + "/fakefile.txt",
			Size:  int64(len(fakeBrokerContentBytes)),
			UUID:  "fake-file-uuid-001",
			MIME:  "text/plain",
			Mtime: fakeBrokerFileMtime,
		}},
		{Directory: &fakeBrokerDirEntry{
			Path:  dirPath + "/fakesub",
			Mtime: fakeBrokerDirMtime,
		}},
	}

	writeJSON(w, map[string]interface{}{
		"entries": entries,
		"cursor":  "",
	})
}

// serveReadMetadata serves a canned ReadMetadata response. It returns a
// file entry matching the requested path so that resolve() and NewObject
// succeed.
func serveReadMetadata(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)
	p := req.Path
	if p == "" {
		p = "/fake/path"
	}

	// Return a file entry so the caller gets a fully-populated Object back.
	writeJSON(w, map[string]interface{}{
		"file": map[string]interface{}{
			"path":  p,
			"size":  int64(len(fakeBrokerContentBytes)),
			"uuid":  "fake-meta-uuid-002",
			"mime":  "text/plain",
			"mtime": fakeBrokerFileMtime,
		},
	})
}

// serveAck serves the bare-ack response ({}) for mutating ops that return no
// body (makeDirectory, removeDirectory, moveDirectory, copyFile, moveFile,
// removeFile).
func serveAck(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]interface{}{})
}

// ---------------------------------------------------------------------------
// Streaming op helpers — 5-byte frame envelope
// ---------------------------------------------------------------------------

// writeStreamFrame writes a single Connect streaming frame to w:
//
//	Byte 0:     flag (0x00 = data, 0x02 = end-stream)
//	Bytes 1–4:  payload length as big-endian uint32
//	Bytes 5+:   payload
func writeStreamFrame(w io.Writer, flag byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = flag
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// serveFileDownload serves a canned fileDownload server-streaming response.
// It writes one data frame carrying the canned content bytes as base64 (the
// downloadContentFrame shape: {"data": <base64 bytes>}), followed by an
// end-stream frame ({}).
func serveFileDownload(w http.ResponseWriter, r *http.Request) {
	// Drain the request frame (the client sends one params frame).
	_, _ = io.ReadAll(r.Body)

	w.Header().Set("Content-Type", "application/connect+json")
	w.WriteHeader(http.StatusOK)

	// Data frame: {"data": <raw bytes>}. brokerrpc decodes []byte as base64
	// via Go's standard json.Unmarshal for []byte fields.
	dataFrame := map[string]interface{}{
		"data": fakeBrokerContentBytes,
	}
	payload, err := json.Marshal(dataFrame)
	if err != nil {
		return
	}
	// flag 0x00 = data frame
	_ = writeStreamFrame(w, 0x00, payload)

	// End-stream frame: {} = success.
	endPayload, _ := json.Marshal(map[string]interface{}{})
	// flag 0x02 = end-stream
	_ = writeStreamFrame(w, 0x02, endPayload)

	// Flush if the ResponseWriter supports it (http.ResponseWriter in test
	// context does; this call is best-effort so tests see the response).
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// serveFileUpload accepts a client-streaming fileUpload request. It drains the
// request body (all frames) and responds with an end-stream trailer ({}) so
// Upload returns success.
func serveFileUpload(w http.ResponseWriter, r *http.Request) {
	// Drain all incoming frames from the client.
	_, _ = io.ReadAll(r.Body)

	w.Header().Set("Content-Type", "application/connect+json")
	w.WriteHeader(http.StatusOK)

	// End-stream trailer: {} = success (no optional response message frame).
	endPayload, _ := json.Marshal(map[string]interface{}{})
	_ = writeStreamFrame(w, 0x02, endPayload)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// ---------------------------------------------------------------------------
// Capturing fake broker — records the decoded request body for the two-path
// ops (copyFile, moveFile, moveDirectory) so a test can assert that source and
// destination land in the correct wire slots, not just that the call succeeded.
// The plain serveAck used by startFakeBroker discards the body, so a slot
// transposition on the wire would go undetected; this variant closes that gap.
// ---------------------------------------------------------------------------

// twoPathBody is the decoded shape of the two-path mutating ops. The wire field
// names (`source`, `destination`) match the request structs the client marshals
// for copyFile / moveFile / moveDirectory. Capturing them as raw JSON keys (no
// dependency on the client's request types) keeps the fake an independent
// observer of the wire, so a transposition in the client-to-wire mapping is
// genuinely caught rather than mirrored.
type twoPathBody struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// capturingBroker records the most recent decoded two-path body per op. It is
// safe for concurrent handler goroutines (httptest serves each request in its
// own goroutine; the race detector is on).
type capturingBroker struct {
	mu      sync.Mutex
	byOp    map[string]twoPathBody
	seenOps map[string]int
}

// lastTwoPath returns the most recently captured source/destination for op and
// whether any request for that op was seen.
func (b *capturingBroker) lastTwoPath(op string) (twoPathBody, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.byOp[op]
	return v, ok
}

// callCount returns how many requests for op the broker observed.
func (b *capturingBroker) callCount(op string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seenOps[op]
}

// startCapturingFakeBroker starts a fake broker that behaves exactly like
// startFakeBroker for response shaping but additionally captures the decoded
// request body of the two-path ops. It returns the socket path and the capture
// handle. A t.Cleanup stops the server.
func startCapturingFakeBroker(t *testing.T) (string, *capturingBroker) {
	t.Helper()

	f, err := os.CreateTemp("", "ocufs-cap-*.sock")
	if err != nil {
		t.Fatalf("startCapturingFakeBroker: create temp socket file: %v", err)
	}
	sockPath := f.Name()
	f.Close()
	os.Remove(sockPath) //nolint:errcheck

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("startCapturingFakeBroker: listen unix %s: %v", sockPath, err)
	}

	cap := &capturingBroker{
		byOp:    make(map[string]twoPathBody),
		seenOps: make(map[string]int),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Capture the two-path ops, then fall through to the canned responses
		// the production decoders expect.
		const prefix = "/ocu.filestore.v1alpha.FilesystemService/"
		op := strings.TrimPrefix(r.URL.Path, prefix)
		switch op {
		case "copyFile", "moveFile", "moveDirectory":
			body, _ := io.ReadAll(r.Body)
			var decoded twoPathBody
			_ = json.Unmarshal(body, &decoded)
			cap.mu.Lock()
			cap.byOp[op] = decoded
			cap.seenOps[op]++
			cap.mu.Unlock()
			// Replace the drained body so any downstream read still works; the
			// ack helper ignores it, but keep the contract clean.
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			serveAck(w, r)
		default:
			fakeBrokerHandler(w, r)
		}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	return sockPath, cap
}
