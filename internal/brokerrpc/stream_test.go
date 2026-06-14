// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// TestFrameRoundTrip verifies that writing a message through the frame writer
// and reading it back yields the original payload.
func TestFrameRoundTrip(t *testing.T) {
	payload := []byte(`{"hello":"world"}`)
	var buf bytes.Buffer
	if err := writeFrame(&buf, 0x00, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	flag, got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if flag != 0x00 {
		t.Errorf("flag: got %02x, want 00", flag)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %q, want %q", got, payload)
	}
}

// TestFramePrefixBytes asserts the exact 5-byte prefix layout: 1 flag byte
// followed by 4-byte big-endian length.
func TestFramePrefixBytes(t *testing.T) {
	payload := []byte(`{"x":1}`) // 7 bytes
	var buf bytes.Buffer
	if err := writeFrame(&buf, 0x00, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	data := buf.Bytes()
	if len(data) < 5 {
		t.Fatalf("too short: %d bytes", len(data))
	}
	// Byte 0: flag
	if data[0] != 0x00 {
		t.Errorf("byte[0] flag: got %02x, want 00", data[0])
	}
	// Bytes 1-4: big-endian uint32 length
	wantLen := uint32(len(payload))
	gotLen := binary.BigEndian.Uint32(data[1:5])
	if gotLen != wantLen {
		t.Errorf("length field: got %d, want %d", gotLen, wantLen)
	}
	// The rest is the payload
	if !bytes.Equal(data[5:], payload) {
		t.Errorf("payload bytes mismatch")
	}
}

// TestEndStreamFlagIsZeroX02 asserts that the end-stream flag value is 0x02.
func TestEndStreamFlagIsZeroX02(t *testing.T) {
	if endStreamFlag != 0x02 {
		t.Errorf("endStreamFlag: got %02x, want 02", endStreamFlag)
	}
}

// TestReadFrameRejectsOversizedLength verifies that readFrame refuses a wire
// length above maxInboundFrame instead of allocating it (MD-01: a 4-byte field
// must not size an unbounded allocation and OOM the guest).
func TestReadFrameRejectsOversizedLength(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, frameHeaderLen)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], maxInboundFrame+1)
	buf.Write(header)
	// No payload bytes follow; readFrame must reject before trying to read.

	_, _, err := readFrame(&buf)
	if err == nil {
		t.Fatal("expected error for oversized frame length, got nil")
	}
}

// TestReadFrameAcceptsLengthAtCap pins the inclusive upper boundary of the
// inbound-frame size guard: a frame whose declared length is exactly
// maxInboundFrame (4 MiB) must be ACCEPTED, while a declared length of
// maxInboundFrame+1 must be REJECTED. The guard is `length > maxInboundFrame`,
// so the cap value itself passes; were it `>=` (off-by-one) the at-cap frame
// would be wrongly rejected. The test supplies the full at-cap payload so the
// guard is exercised against a real read, not a short body that would mask a
// `>=` regression behind an EOF.
func TestReadFrameAcceptsLengthAtCap(t *testing.T) {
	// Exactly at the cap: must be accepted and round-trip byte-for-byte.
	atCap := bytes.Repeat([]byte{0xAB}, maxInboundFrame)
	if uint32(len(atCap)) != maxInboundFrame {
		t.Fatalf("fixture size %d != maxInboundFrame %d", len(atCap), maxInboundFrame)
	}
	var buf bytes.Buffer
	header := make([]byte, frameHeaderLen)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], maxInboundFrame)
	buf.Write(header)
	buf.Write(atCap)

	flag, got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("frame declaring length == maxInboundFrame must be accepted, got: %v", err)
	}
	if flag != 0x00 {
		t.Errorf("flag: got %02x, want 00", flag)
	}
	if uint32(len(got)) != maxInboundFrame {
		t.Fatalf("payload length: got %d, want %d", len(got), maxInboundFrame)
	}
	if !bytes.Equal(got, atCap) {
		t.Error("at-cap payload did not round-trip byte-for-byte")
	}

	// One byte over the cap: must be rejected by the size guard before any
	// payload read. This is the negative half of the boundary; together with the
	// accept case above it pins `>` (correct) against `>=` (off-by-one).
	var overBuf bytes.Buffer
	overHeader := make([]byte, frameHeaderLen)
	overHeader[0] = 0x00
	binary.BigEndian.PutUint32(overHeader[1:5], maxInboundFrame+1)
	overBuf.Write(overHeader)
	// No payload bytes follow; the guard must trip before the payload read.

	if _, _, err := readFrame(&overBuf); err == nil {
		t.Fatal("frame declaring length == maxInboundFrame+1 must be rejected, got nil error")
	}
}

// TestPayloadFitsFrameBoundary pins the outbound length-field bound: a payload
// at or below math.MaxUint32 fits the 4-byte prefix; one byte more does not.
// The over-limit case is checked through the predicate rather than by
// allocating a >4 GiB slice (the guard's reason for existing is that such a
// payload cannot be length-prefixed without truncation and stream desync).
func TestPayloadFitsFrameBoundary(t *testing.T) {
	if !payloadFitsFrame(0) {
		t.Error("empty payload should fit")
	}
	// The boundary values exceed a 32-bit int, so this assertion is meaningful
	// only where int is 64-bit. On a 32-bit int every length already fits the
	// uint32 field, so the over-limit case cannot arise and the test is skipped.
	const maxInt = uint64(^uint(0) >> 1) // largest int value on the build platform
	if maxFramePayload > maxInt {
		t.Skip("int is 32-bit here; the frame-length bound cannot be exceeded by a slice length")
	}
	atCap := int(maxFramePayload)
	if !payloadFitsFrame(atCap) {
		t.Error("a payload exactly at maxFramePayload should fit (the field holds it)")
	}
	if payloadFitsFrame(atCap + 1) {
		t.Error("a payload one byte above maxFramePayload must not fit")
	}
}

// TestWriteFrameWritesExactBytes asserts writeFrame emits exactly the 5-byte
// prefix plus the payload and reports no error on a representable payload.
func TestWriteFrameWritesExactBytes(t *testing.T) {
	payload := []byte("payload-bytes")
	var buf bytes.Buffer
	if err := writeFrame(&buf, endStreamFlag, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if got, want := buf.Len(), frameHeaderLen+len(payload); got != want {
		t.Fatalf("framed length: got %d, want %d", got, want)
	}
	if buf.Bytes()[0] != endStreamFlag {
		t.Errorf("flag byte: got %02x, want %02x", buf.Bytes()[0], endStreamFlag)
	}
}

// TestEndStreamSuccessRoundTrip writes a success end-stream frame and reads
// it back; success/failure comes from the parsed EndStreamResponse, not the
// HTTP status (always 200 for streams).
func TestEndStreamSuccessRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeEndStream(&buf, nil); err != nil {
		t.Fatalf("writeEndStream: %v", err)
	}

	esr, err := readEndStream(&buf)
	if err != nil {
		t.Fatalf("readEndStream: %v", err)
	}
	if esr.Error != nil {
		t.Errorf("expected success, got error: %v", esr.Error)
	}
}

// TestEndStreamErrorRoundTrip writes an error end-stream frame and reads it
// back; the code and message are preserved.
func TestEndStreamErrorRoundTrip(t *testing.T) {
	connErr := &ConnectError{Code: "not_found", Message: "object missing"}
	var buf bytes.Buffer
	if err := writeEndStream(&buf, connErr); err != nil {
		t.Fatalf("writeEndStream: %v", err)
	}

	esr, err := readEndStream(&buf)
	if err != nil {
		t.Fatalf("readEndStream: %v", err)
	}
	if esr.Error == nil {
		t.Fatal("expected error in EndStreamResponse, got nil")
	}
	if esr.Error.Code != "not_found" {
		t.Errorf("code: got %q, want %q", esr.Error.Code, "not_found")
	}
	if esr.Error.Message != "object missing" {
		t.Errorf("message: got %q, want %q", esr.Error.Message, "object missing")
	}
}

// TestEndStreamFlagMarksBoundary checks that a regular data frame (flag 0x00)
// is not mistaken for an end-stream frame, and vice versa.
func TestEndStreamFlagMarksBoundary(t *testing.T) {
	payload := []byte(`{"chunk":"aGVsbG8="}`)
	var buf bytes.Buffer
	if err := writeFrame(&buf, 0x00, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	flag, _, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if flag&endStreamFlag != 0 {
		t.Errorf("data frame flag %02x has end-stream bit set", flag)
	}
}

// TestEndStreamBodyIsJSON verifies that a written end-stream frame carries a
// valid JSON body (either {} for success or {"error":{...}} for error).
func TestEndStreamBodyIsJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := writeEndStream(&buf, nil); err != nil {
		t.Fatalf("writeEndStream: %v", err)
	}

	flag, payload, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if flag != endStreamFlag {
		t.Errorf("expected end-stream flag %02x, got %02x", endStreamFlag, flag)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Errorf("end-stream payload is not valid JSON: %v", err)
	}
}
