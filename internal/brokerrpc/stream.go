// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc — streaming frame helpers.
//
// This file implements the Connect streaming frame envelope used for the
// two streaming ops (fileUpload, fileDownload). The envelope is a 5-byte
// prefix followed by the JSON-encoded message payload.
//
// Frame layout (per the locked transport contract):
//
//	Byte 0:   flag (0x00 = data frame, 0x02 = end-stream frame)
//	Bytes 1–4: payload length as a big-endian uint32
//	Bytes 5+:  JSON-encoded payload

package brokerrpc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// endStreamFlag is the Connect streaming end-of-stream flag value.
// A frame carrying this flag in byte 0 is the final frame and its payload
// is an EndStreamResponse. Streams always return HTTP 200; the error (if any)
// lives exclusively in this trailer.
const endStreamFlag byte = 0x02

// frameHeaderLen is the fixed size of the Connect streaming frame prefix.
const frameHeaderLen = 5

// maxInboundFrame caps the payload size readFrame will allocate from the 4-byte
// wire length field. Without a bound, a broker bug, a desynced stream, or a
// corrupted length turns a 4-byte field into a multi-gigabyte allocation and
// guest OOM. The guest is the least-provisioned party in this architecture and
// must never let a wire field size its allocations unboundedly. The cap is set
// well above the 256 KiB message ceiling to leave headroom for any legitimate
// trailer or metadata frame while still rejecting absurd lengths.
const maxInboundFrame = 4 * 1024 * 1024 // 4 MiB

// ConnectError is the on-wire error shape shared by both unary non-2xx bodies
// and EndStreamResponse error trailers.
type ConnectError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details []any  `json:"details,omitempty"`
}

func (e *ConnectError) Error() string {
	return fmt.Sprintf("brokerrpc: connect error %s: %s", e.Code, e.Message)
}

// EndStreamResponse is the payload of the final frame (flag 0x02) in a
// server-streaming or client-streaming response. On success the payload is
// the JSON object {}; on error it carries {"error":{code,message,details?}}.
// The HTTP status for streaming responses is always 200 — the caller must
// read this trailer to determine success or failure.
type EndStreamResponse struct {
	Error    *ConnectError      `json:"error,omitempty"`
	Metadata map[string]any     `json:"metadata,omitempty"`
}

// writeFrame writes a single Connect streaming frame to w. The flag byte and
// the JSON payload are separated by a 4-byte big-endian length prefix.
func writeFrame(w io.Writer, flag byte, payload []byte) error {
	header := make([]byte, frameHeaderLen)
	header[0] = flag
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("brokerrpc: write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("brokerrpc: write frame payload: %w", err)
	}
	return nil
}

// readFrame reads one Connect streaming frame from r and returns the flag byte
// and payload. The caller must check the flag to determine whether it is a
// data frame (0x00) or an end-stream frame (0x02).
func readFrame(r io.Reader) (flag byte, payload []byte, err error) {
	header := make([]byte, frameHeaderLen)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, nil, fmt.Errorf("brokerrpc: read frame header: %w", err)
	}
	flag = header[0]
	length := binary.BigEndian.Uint32(header[1:5])
	if length > maxInboundFrame {
		return 0, nil, fmt.Errorf("brokerrpc: inbound frame length %d exceeds max %d", length, maxInboundFrame)
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("brokerrpc: read frame payload: %w", err)
		}
	}
	return flag, payload, nil
}

// writeEndStream writes the final end-stream frame (flag 0x02). If connErr is
// nil the payload is {}; otherwise it is {"error":{...}}.
func writeEndStream(w io.Writer, connErr *ConnectError) error {
	esr := EndStreamResponse{Error: connErr}
	payload, err := json.Marshal(esr)
	if err != nil {
		return fmt.Errorf("brokerrpc: marshal EndStreamResponse: %w", err)
	}
	return writeFrame(w, endStreamFlag, payload)
}

// readEndStream reads and parses the next frame as an EndStreamResponse. It
// returns an error if the frame flag is not 0x02 or if the JSON body cannot be
// parsed.
func readEndStream(r io.Reader) (*EndStreamResponse, error) {
	flag, payload, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	if flag != endStreamFlag {
		return nil, fmt.Errorf("brokerrpc: expected end-stream frame (flag 0x02), got 0x%02x", flag)
	}
	var esr EndStreamResponse
	if err := json.Unmarshal(payload, &esr); err != nil {
		return nil, fmt.Errorf("brokerrpc: parse EndStreamResponse: %w", err)
	}
	return &esr, nil
}

// readUploadResult reads the response of a client-streaming op. Standard
// Connect client-streaming success is an optional single response message frame
// (data flag 0x00) followed by the end-stream frame (flag 0x02). The broker may
// or may not emit the response message frame; this reader tolerates either
// shape. When a message frame is present it is decoded into a FileUploadResponse
// (and currently otherwise unused — the trailer carries the success verdict).
// The returned EndStreamResponse trailer is authoritative for success/failure.
func readUploadResult(r io.Reader) (*EndStreamResponse, error) {
	flag, payload, err := readFrame(r)
	if err != nil {
		return nil, err
	}

	if flag != endStreamFlag {
		// A leading data frame: the optional response message. Decode it into
		// the declared response type so the shape is consumed, then read the
		// trailer that must follow.
		var msg FileUploadResponse
		if jsonErr := json.Unmarshal(payload, &msg); jsonErr != nil {
			return nil, fmt.Errorf("brokerrpc: parse fileUpload response message: %w", jsonErr)
		}
		return readEndStream(r)
	}

	// No response message frame: this frame is already the trailer.
	var esr EndStreamResponse
	if err := json.Unmarshal(payload, &esr); err != nil {
		return nil, fmt.Errorf("brokerrpc: parse EndStreamResponse: %w", err)
	}
	return &esr, nil
}

// streamingURL constructs the POST URL for a streaming op.
// Both fileUpload and fileDownload follow the same URL scheme as unary ops.
func streamingURL(op Op) string {
	return "http://broker" + serviceBase + string(op)
}
