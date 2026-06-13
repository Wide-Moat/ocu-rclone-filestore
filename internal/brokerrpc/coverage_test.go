// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// White-box error-path coverage for the broker RPC client. These tests reach
// the failure branches that the happy-path tests do not: construction guards,
// the unary call helper's marshal/read/non-2xx branches, the streaming frame
// helpers' wrong-flag and malformed-payload branches, the unknown-op intent
// path, and the upload/download dial and write-fault paths. Every assertion
// pins an observable behaviour (returned error identity, wrapped sentinel, or
// decoded bytes), never just touches a line.

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rclone/rclone/fs/fserrors"
)

// errWriter is an io.Writer that fails after allowing the first n successful
// writes through. It is used to drive writeFrame / writeUploadFrames /
// writeEndStream into their write-error branches.
type errWriter struct {
	allow int // number of writes to let succeed before failing
	n     int
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.n >= e.allow {
		return 0, errors.New("errWriter: forced write failure")
	}
	e.n++
	return len(p), nil
}

// errReader is an io.Reader that returns a forced error on the first read,
// driving the upload source-read branch.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("errReader: forced read failure")
}

// unmarshalable is a value json.Marshal cannot encode (a function field),
// used to drive the marshal-error branch in call().
type unmarshalable struct {
	Fn func() `json:"fn"`
}

// ---------------------------------------------------------------------------
// NewWithOptions construction guards
// ---------------------------------------------------------------------------

func TestNewWithOptionsRejectsEmptyInputs(t *testing.T) {
	if _, err := NewWithOptions("", "fs", ClientOptions{}); err == nil {
		t.Error("empty socketPath: expected error, got nil")
	}
	if _, err := NewWithOptions("/tmp/x.sock", "", ClientOptions{}); err == nil {
		t.Error("empty fsID: expected error, got nil")
	}
	// Both valid: no error and the default ceiling applies.
	c, err := NewWithOptions("/tmp/x.sock", "fs", ClientOptions{})
	if err != nil {
		t.Fatalf("valid construction: %v", err)
	}
	if c.messageCeiling != defaultMessageCeiling {
		t.Errorf("default ceiling: got %d, want %d", c.messageCeiling, defaultMessageCeiling)
	}
	// An explicit positive ceiling overrides the default.
	c2, err := NewWithOptions("/tmp/x.sock", "fs", ClientOptions{MessageCeiling: 4096})
	if err != nil {
		t.Fatalf("valid construction with ceiling: %v", err)
	}
	if c2.messageCeiling != 4096 {
		t.Errorf("explicit ceiling: got %d, want 4096", c2.messageCeiling)
	}
}

// ---------------------------------------------------------------------------
// call() error branches
// ---------------------------------------------------------------------------

// TestCallMarshalErrorReturnsWrapped drives the request-marshal failure branch:
// a request value json.Marshal cannot encode must surface as an error before
// any network I/O, naming the op.
func TestCallMarshalErrorReturnsWrapped(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("call must fail at marshal before reaching the server")
	})
	c, _ := New(sock, "fs-call-01")
	err := c.call(context.Background(), OpListDirectory, unmarshalable{}, nil)
	if err == nil {
		t.Fatal("expected marshal error, got nil")
	}
	if !strings.Contains(err.Error(), "marshal") {
		t.Errorf("error %q does not mention marshal", err.Error())
	}
}

// TestCallNonParseableBodyFallsBackToPermanent drives the non-2xx branch where
// the error body is not a parseable Connect error: it must fall back to the
// ErrPermanentOther sentinel and carry the raw body and status.
func TestCallNonParseableBodyFallsBackToPermanent(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway) // 502
		_, _ = w.Write([]byte("upstream blew up, not json"))
	})
	c, _ := New(sock, "fs-call-02")
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected error on non-2xx body, got nil")
	}
	if !errors.Is(err, ErrPermanentOther) {
		t.Errorf("unparseable non-2xx body must map to ErrPermanentOther; got %v", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should carry the status code 502; got %q", err.Error())
	}
}

// TestCallNonParseableEmptyCodeFallsBack drives the second half of the fallback
// guard: a JSON body that parses but has an empty code is treated as
// non-parseable (the `ce.Code == ""` arm), not as a Connect error.
func TestCallNonParseableEmptyCodeFallsBack(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"no code field present"}`))
	})
	c, _ := New(sock, "fs-call-03")
	_, err := c.MakeDirectory(context.Background(), "/d")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPermanentOther) {
		t.Errorf("empty-code body must fall back to ErrPermanentOther; got %v", err)
	}
	// The empty-code arm must route through the raw-body fallback (which stamps
	// the HTTP status into the message), NOT through MapConnectError. Asserting
	// the status code 500 is present pins that routing: the code mapper produces
	// "code=: ..." with no HTTP status, so a body wrongly sent through it would
	// drop the 500 and fail here. Mirrors the sibling non-parseable-body test's
	// 502 check.
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("empty-code fallback must carry the status code 500; got %q", err.Error())
	}
}

// TestCallParseableConnectErrorMaps drives the non-2xx branch where the body IS
// a parseable Connect error: it must run through MapConnectError and surface the
// right typed sentinel and retry posture.
func TestCallParseableConnectErrorMaps(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"permission_denied","message":"scope_mismatch"}`))
	})
	c, _ := New(sock, "fs-call-04")
	_, err := c.RemoveFile(context.Background(), "/secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("parseable permission_denied must map to ErrPermissionDenied; got %v", err)
	}
}

// TestCallResourceExhaustedHonoursRetryAfter drives the Retry-After header path:
// a resource_exhausted body with a Retry-After header must be retryable.
func TestCallResourceExhaustedHonoursRetryAfter(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":"resource_exhausted","message":"throttled"}`))
	})
	c, _ := New(sock, "fs-call-05")
	_, err := c.CreateFile(context.Background(), "/new.txt")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !fserrors.IsRetryError(err) {
		t.Errorf("resource_exhausted must be retryable; got %v", err)
	}
}

// TestCallResponseUnmarshalError drives the 2xx-but-bad-JSON branch: a 200 with
// a body that does not decode into the response type must surface an unmarshal
// error naming the op.
func TestCallResponseUnmarshalError(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// listDirectory's response is an object; an array fails to decode.
		_, _ = w.Write([]byte(`["this","is","an","array"]`))
	})
	c, _ := New(sock, "fs-call-06")
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("error %q does not mention unmarshal", err.Error())
	}
}

// TestCallDialErrorSurfaces drives the transport (Do) error branch: a client
// pointed at a non-existent socket fails on dial.
func TestCallDialErrorSurfaces(t *testing.T) {
	c, _ := New("/nonexistent/dir/no.sock", "fs-call-07")
	_, err := c.ReadMetadata(context.Background(), "/x")
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// ---------------------------------------------------------------------------
// stamp() — happy path returns the bound fsID; the error path is reachable only
// through StampAuthMeta with an unknown op (covered below).
// ---------------------------------------------------------------------------

func TestStampReturnsBoundFSID(t *testing.T) {
	c, _ := New("/tmp/x.sock", "fs-bound-99")
	fsID, am, err := c.stamp(OpReadFile)
	if err != nil {
		t.Fatalf("stamp known op: %v", err)
	}
	if fsID != "fs-bound-99" {
		t.Errorf("stamp fsID: got %q, want fs-bound-99", fsID)
	}
	if am.Intent != "read" || am.Downloadable {
		t.Errorf("stamp am: got %+v, want {read false}", am)
	}
}

// TestStampUnknownOpErrors drives the stamp error branch directly: an op not in
// the intent table must fail.
func TestStampUnknownOpErrors(t *testing.T) {
	c, _ := New("/tmp/x.sock", "fs-bound-99")
	_, _, err := c.stamp(Op("notARealOp"))
	if err == nil {
		t.Fatal("expected stamp error for unknown op, got nil")
	}
}

// ---------------------------------------------------------------------------
// intent.go unknown-op error branches
// ---------------------------------------------------------------------------

func TestIntentForUnknownOpErrors(t *testing.T) {
	intent, err := IntentFor(Op("phantomOp"))
	if err == nil {
		t.Fatal("IntentFor(unknown): expected error, got nil")
	}
	if intent != "" {
		t.Errorf("IntentFor(unknown) intent: got %q, want empty", intent)
	}
	if !strings.Contains(err.Error(), "phantomOp") {
		t.Errorf("error should name the unknown op; got %q", err.Error())
	}
}

func TestStampAuthMetaUnknownOpErrors(t *testing.T) {
	am, err := StampAuthMeta(Op("phantomOp"))
	if err == nil {
		t.Fatal("StampAuthMeta(unknown): expected error, got nil")
	}
	if am != (AuthorizationMetadata{}) {
		t.Errorf("StampAuthMeta(unknown) am: got %+v, want zero value", am)
	}
}

// ---------------------------------------------------------------------------
// MapConnectError nil input
// ---------------------------------------------------------------------------

func TestMapConnectErrorNilReturnsNil(t *testing.T) {
	if err := MapConnectError(nil, ""); err != nil {
		t.Errorf("MapConnectError(nil): got %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// ConnectError.Error() formatter
// ---------------------------------------------------------------------------

func TestConnectErrorFormatsCodeAndMessage(t *testing.T) {
	ce := &ConnectError{Code: "not_found", Message: "object gone"}
	got := ce.Error()
	want := "brokerrpc: connect error not_found: object gone"
	if got != want {
		t.Errorf("ConnectError.Error(): got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// stream.go frame helper error branches
// ---------------------------------------------------------------------------

// TestWriteFrameHeaderWriteError drives the header-write failure branch.
func TestWriteFrameHeaderWriteError(t *testing.T) {
	err := writeFrame(&errWriter{allow: 0}, 0x00, []byte("payload"))
	if err == nil {
		t.Fatal("expected header write error, got nil")
	}
	if !strings.Contains(err.Error(), "header") {
		t.Errorf("error %q does not mention header", err.Error())
	}
}

// TestWriteFramePayloadWriteError drives the payload-write failure branch: the
// header write succeeds, the payload write fails.
func TestWriteFramePayloadWriteError(t *testing.T) {
	err := writeFrame(&errWriter{allow: 1}, 0x00, []byte("payload"))
	if err == nil {
		t.Fatal("expected payload write error, got nil")
	}
	if !strings.Contains(err.Error(), "payload") {
		t.Errorf("error %q does not mention payload", err.Error())
	}
}

// TestWriteEndStreamWriteError drives writeEndStream's underlying write-error
// propagation (the marshal of EndStreamResponse always succeeds, so the error
// comes from writeFrame).
func TestWriteEndStreamWriteError(t *testing.T) {
	err := writeEndStream(&errWriter{allow: 0}, nil)
	if err == nil {
		t.Fatal("expected write error from writeEndStream, got nil")
	}
}

// TestReadEndStreamReadFrameError drives the readFrame-failure branch: an empty
// reader fails to read the frame header.
func TestReadEndStreamReadFrameError(t *testing.T) {
	_, err := readEndStream(bytes.NewReader(nil))
	if err == nil {
		t.Fatal("expected read error on empty stream, got nil")
	}
}

// TestReadEndStreamWrongFlagError drives the not-0x02 branch: a data frame is
// not an end-stream frame.
func TestReadEndStreamWrongFlagError(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, 0x00, []byte(`{}`)); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	_, err := readEndStream(&buf)
	if err == nil {
		t.Fatal("expected wrong-flag error, got nil")
	}
	if !strings.Contains(err.Error(), "end-stream") {
		t.Errorf("error %q does not mention end-stream", err.Error())
	}
}

// TestReadEndStreamBadJSONError drives the JSON-parse-failure branch: a proper
// end-stream frame (flag 0x02) carrying a non-JSON payload.
func TestReadEndStreamBadJSONError(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, endStreamFlag, []byte("not json at all")); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	_, err := readEndStream(&buf)
	if err == nil {
		t.Fatal("expected JSON parse error, got nil")
	}
	if !strings.Contains(err.Error(), "EndStreamResponse") {
		t.Errorf("error %q does not mention EndStreamResponse", err.Error())
	}
}

// TestReadUploadResultReadFrameError drives the readFrame-failure branch in
// readUploadResult.
func TestReadUploadResultReadFrameError(t *testing.T) {
	_, err := readUploadResult(bytes.NewReader(nil))
	if err == nil {
		t.Fatal("expected read error, got nil")
	}
}

// TestReadUploadResultLeadingMessageBadJSON drives the leading-data-frame branch
// where the response message frame is present but not valid FileUploadResponse
// JSON.
func TestReadUploadResultLeadingMessageBadJSON(t *testing.T) {
	var buf bytes.Buffer
	// A leading data frame (flag 0x00) with an undecodable response message.
	if err := writeFrame(&buf, 0x00, []byte("definitely not json")); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	_, err := readUploadResult(&buf)
	if err == nil {
		t.Fatal("expected parse error on bad response message frame, got nil")
	}
	if !strings.Contains(err.Error(), "fileUpload response message") {
		t.Errorf("error %q does not mention the response message frame", err.Error())
	}
}

// TestReadUploadResultLeadingMessageThenTrailer drives the standard
// client-streaming success shape: a valid response message frame (flag 0x00)
// followed by a success trailer (flag 0x02). The trailer verdict is returned.
func TestReadUploadResultLeadingMessageThenTrailer(t *testing.T) {
	var buf bytes.Buffer
	msg := []byte(`{"file":{"path":"/done.txt","size":3}}`)
	if err := writeFrame(&buf, 0x00, msg); err != nil {
		t.Fatalf("writeFrame msg: %v", err)
	}
	if err := writeEndStream(&buf, nil); err != nil {
		t.Fatalf("writeEndStream: %v", err)
	}
	esr, err := readUploadResult(&buf)
	if err != nil {
		t.Fatalf("readUploadResult: %v", err)
	}
	if esr.Error != nil {
		t.Errorf("expected success trailer, got error %+v", esr.Error)
	}
}

// TestReadUploadResultTrailerBadJSON drives the no-message-frame branch where
// the trailer frame (flag 0x02) carries a non-JSON payload.
func TestReadUploadResultTrailerBadJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, endStreamFlag, []byte("garbage trailer")); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	_, err := readUploadResult(&buf)
	if err == nil {
		t.Fatal("expected trailer parse error, got nil")
	}
	if !strings.Contains(err.Error(), "EndStreamResponse") {
		t.Errorf("error %q does not mention EndStreamResponse", err.Error())
	}
}

// ---------------------------------------------------------------------------
// sourceChunkSize floor
// ---------------------------------------------------------------------------

// TestSourceChunkSizeFloorIsThree drives the n<3 floor: a ceiling so small the
// budget is below 4 must still yield a chunk size of at least 3 so progress is
// guaranteed.
func TestSourceChunkSizeFloorIsThree(t *testing.T) {
	// jsonEnvelopeOverhead is 13; any ceiling at/below 13+3 leaves budget<4.
	if got := sourceChunkSize(1); got != 3 {
		t.Errorf("sourceChunkSize(1): got %d, want 3 (floor)", got)
	}
	if got := sourceChunkSize(jsonEnvelopeOverhead); got != 3 {
		t.Errorf("sourceChunkSize(overhead): got %d, want 3 (floor)", got)
	}
	// A generous ceiling yields a multiple of 3 strictly above the floor.
	big := sourceChunkSize(64 * 1024)
	if big%3 != 0 {
		t.Errorf("sourceChunkSize must be a multiple of 3; got %d", big)
	}
	if big <= 3 {
		t.Errorf("a large ceiling should give a chunk well above the floor; got %d", big)
	}
}

// ---------------------------------------------------------------------------
// writeUploadFrames write-fault branches (driven with a failing writer)
// ---------------------------------------------------------------------------

// TestWriteUploadFramesParamsFrameWriteError drives the params-frame write
// failure: the very first writeFrame fails.
func TestWriteUploadFramesParamsFrameWriteError(t *testing.T) {
	am := AuthorizationMetadata{Intent: "write"}
	err := writeUploadFrames(&errWriter{allow: 0}, "fs", "/p", 3, false, am,
		bytes.NewReader([]byte("abc")), defaultMessageCeiling)
	if err == nil {
		t.Fatal("expected params frame write error, got nil")
	}
}

// TestWriteUploadFramesChunkFrameWriteError drives a chunk-frame write failure:
// the params frame (2 writes: header+payload) succeeds, then the first chunk
// frame's header write fails.
func TestWriteUploadFramesChunkFrameWriteError(t *testing.T) {
	am := AuthorizationMetadata{Intent: "write"}
	err := writeUploadFrames(&errWriter{allow: 2}, "fs", "/p", 3, false, am,
		bytes.NewReader([]byte("abc")), defaultMessageCeiling)
	if err == nil {
		t.Fatal("expected chunk frame write error, got nil")
	}
}

// TestWriteUploadFramesSourceReadError drives the source-read failure branch:
// the source reader returns an error mid-stream.
func TestWriteUploadFramesSourceReadError(t *testing.T) {
	am := AuthorizationMetadata{Intent: "write"}
	// A discard writer never fails, so the only error comes from the source.
	err := writeUploadFrames(io.Discard, "fs", "/p", 3, false, am,
		errReader{}, defaultMessageCeiling)
	if err == nil {
		t.Fatal("expected source read error, got nil")
	}
	if !strings.Contains(err.Error(), "read source") {
		t.Errorf("error %q does not mention read source", err.Error())
	}
}

// TestWriteUploadFramesEndStreamWriteError drives the terminating end-stream
// write failure: an empty source means zero chunk frames, so after the params
// frame (2 writes) the end-stream write is next; fail it.
func TestWriteUploadFramesEndStreamWriteError(t *testing.T) {
	am := AuthorizationMetadata{Intent: "write"}
	err := writeUploadFrames(&errWriter{allow: 2}, "fs", "/p", 0, false, am,
		bytes.NewReader(nil), defaultMessageCeiling)
	if err == nil {
		t.Fatal("expected end-stream write error, got nil")
	}
}

// TestWriteUploadFramesHappyPath confirms the full frame sequence is written and
// reassembles: params frame, one chunk frame, end-stream trailer.
func TestWriteUploadFramesHappyPath(t *testing.T) {
	am := AuthorizationMetadata{Intent: "write", Downloadable: false}
	var buf bytes.Buffer
	content := []byte("hello")
	if err := writeUploadFrames(&buf, "fs-x", "/h.txt", int64(len(content)), true, am,
		bytes.NewReader(content), defaultMessageCeiling); err != nil {
		t.Fatalf("writeUploadFrames: %v", err)
	}
	// Frame 1: params.
	flag, payload, err := readFrame(&buf)
	if err != nil || flag != 0x00 {
		t.Fatalf("params frame: flag=0x%02x err=%v", flag, err)
	}
	if !bytes.Contains(payload, []byte(`"path":"/h.txt"`)) {
		t.Errorf("params frame missing path: %s", payload)
	}
	if !bytes.Contains(payload, []byte(`"overwrite_existing":true`)) {
		t.Errorf("params frame missing overwrite_existing:true: %s", payload)
	}
	// Frame 2: chunk.
	flag, payload, err = readFrame(&buf)
	if err != nil || flag != 0x00 {
		t.Fatalf("chunk frame: flag=0x%02x err=%v", flag, err)
	}
	// Frame 3: end-stream.
	flag, _, err = readFrame(&buf)
	if err != nil || flag != endStreamFlag {
		t.Fatalf("end-stream frame: flag=0x%02x err=%v", flag, err)
	}
}

// ---------------------------------------------------------------------------
// Upload transport error branches (dial, write-fault without trailer, bad trailer)
// ---------------------------------------------------------------------------

// TestUploadDialErrorSurfaces drives the Do-error branch: a non-existent socket
// fails the upload at the transport.
func TestUploadDialErrorSurfaces(t *testing.T) {
	c, _ := New("/nonexistent/dir/no.sock", "fs-up-dial")
	err := c.Upload(context.Background(), "/a.txt", bytes.NewReader([]byte("x")), 1, false)
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// TestUploadWriteFaultSurfacesWhenNoTrailerError drives the writeErr branch: a
// source-read failure with a server that returns a clean success trailer means
// there is no authoritative error trailer, so the genuine write fault surfaces.
func TestUploadWriteFaultSurfacesWhenNoTrailerError(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		_ = writeEndStream(&buf, nil) // clean success trailer
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
	c, _ := New(sock, "fs-up-wf")
	// errReader fails on first read, so writeUploadFrames returns a non-pipe
	// error; the server drains and replies {}, so trailerErr==nil and
	// esr.Error==nil — the write fault must surface.
	err := c.Upload(context.Background(), "/a.txt", errReader{}, 3, false)
	if err == nil {
		t.Fatal("expected write-fault error to surface, got nil")
	}
	if !strings.Contains(err.Error(), "write frames") {
		t.Errorf("error %q does not mention write frames", err.Error())
	}
}

// TestUploadBadTrailerSurfaces drives the trailerErr branch: the server replies
// with an unparseable trailer frame, so the read fails and there is no clear
// write fault, surfacing the trailer-read error.
func TestUploadBadTrailerSurfaces(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		// An end-stream frame (flag 0x02) with a non-JSON payload.
		_ = writeFrame(&buf, endStreamFlag, []byte("not a valid trailer"))
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
	c, _ := New(sock, "fs-up-bt")
	err := c.Upload(context.Background(), "/a.txt", bytes.NewReader([]byte("x")), 1, false)
	if err == nil {
		t.Fatal("expected trailer-read error, got nil")
	}
	if !strings.Contains(err.Error(), "EndStreamResponse") {
		t.Errorf("error %q does not mention EndStreamResponse", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Download transport error branches (stamp via DownloadRange guards, dial, read frame)
// ---------------------------------------------------------------------------

// TestDownloadRangeNegativeOffsetErrors drives the negative-offset guard.
func TestDownloadRangeNegativeOffsetErrors(t *testing.T) {
	c, _ := New("/tmp/x.sock", "fs-dl-neg")
	_, err := c.DownloadRange(context.Background(), "uuid", -1, 4)
	if err == nil {
		t.Fatal("expected error on negative offset, got nil")
	}
	if !strings.Contains(err.Error(), "negative offset") {
		t.Errorf("error %q does not mention negative offset", err.Error())
	}
}

// TestDownloadDialErrorSurfaces drives the doDownloadRequest Do-error branch.
func TestDownloadDialErrorSurfaces(t *testing.T) {
	c, _ := New("/nonexistent/dir/no.sock", "fs-dl-dial")
	_, err := c.Download(context.Background(), "uuid")
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// TestDownloadRangeDialErrorSurfaces drives the same Do-error branch through the
// ranged helper (so its post-request reassembly error path is also exercised).
func TestDownloadRangeDialErrorSurfaces(t *testing.T) {
	c, _ := New("/nonexistent/dir/no.sock", "fs-dl-dial2")
	_, err := c.DownloadRange(context.Background(), "uuid", 0, 4)
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

// TestDownloadRangeReassembleErrorSurfaces drives DownloadRange's
// post-request reassembly error branch: the request succeeds (HTTP 200) but the
// stream's trailer carries an error, which must surface from DownloadRange (not
// just Download).
func TestDownloadRangeReassembleErrorSurfaces(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		var buf bytes.Buffer
		_ = writeEndStream(&buf, &ConnectError{Code: "not_found", Message: "gone"})
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
	c, _ := New(sock, "fs-dl-range-err")
	_, err := c.DownloadRange(context.Background(), "uuid", 0, 4)
	if err == nil {
		t.Fatal("expected error trailer to surface from DownloadRange, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("not_found trailer must map to ErrNotFound; got %v", err)
	}
}

// TestListDirectoryAllCallErrorSurfaces drives the call-error branch inside the
// ListDirectoryAll paging loop: a non-2xx first page must surface wrapped.
func TestListDirectoryAllCallErrorSurfaces(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"permission_denied","message":"no"}`))
	})
	c, _ := New(sock, "fs-lda-err")
	_, err := c.ListDirectoryAll(context.Background(), "/")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ListDirectoryAll") {
		t.Errorf("error %q does not name ListDirectoryAll", err.Error())
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("underlying permission_denied must be preserved; got %v", err)
	}
}

// TestListFilesAllCallErrorSurfaces drives the call-error branch inside the
// ListFilesAll paging loop.
func TestListFilesAllCallErrorSurfaces(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"not_found","message":"missing"}`))
	})
	c, _ := New(sock, "fs-lfa-err")
	_, err := c.ListFilesAll(context.Background(), "root-uuid")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ListFilesAll") {
		t.Errorf("error %q does not name ListFilesAll", err.Error())
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("underlying not_found must be preserved; got %v", err)
	}
}

// TestCallResponseBodyReadError drives the io.ReadAll-failure branch in call():
// a server that declares a larger Content-Length than it writes, then abruptly
// closes the connection, makes the body read fail with an unexpected EOF.
func TestCallResponseBodyReadError(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		// Promise 200 bytes but only write a few, then hijack and close the
		// underlying connection so the client's body read hits unexpected EOF.
		w.Header().Set("Content-Length", "200")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partial":`))
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	})
	c, _ := New(sock, "fs-read-err")
	_, err := c.ListDirectory(context.Background(), "/")
	if err == nil {
		t.Fatal("expected body-read error, got nil")
	}
}

// TestDownloadOversizedFrameIsNonEOFError drives the non-EOF read-frame error
// branch in reassembleDownloadStream: a frame declaring a length over the
// inbound cap is a read error that is NOT EOF, so it takes the generic
// read-frame error path rather than the truncated-stream path.
func TestDownloadOversizedFrameIsNonEOFError(t *testing.T) {
	sock := uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		// A frame header declaring a payload over maxInboundFrame.
		header := make([]byte, frameHeaderLen)
		header[0] = 0x00
		binary.BigEndian.PutUint32(header[1:5], maxInboundFrame+1)
		w.Header().Set("Content-Type", "application/connect+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(header)
	})
	c, _ := New(sock, "fs-dl-big")
	_, err := c.Download(context.Background(), "uuid")
	if err == nil {
		t.Fatal("expected oversized-frame error, got nil")
	}
	// It must be the generic read-frame error path, not the truncated-stream
	// path: the message names the read-frame failure.
	if !strings.Contains(err.Error(), "read frame") {
		t.Errorf("error %q does not mention read frame", err.Error())
	}
}
