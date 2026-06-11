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
