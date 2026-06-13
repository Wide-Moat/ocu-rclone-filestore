// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// White-box fuzz targets for the Connect streaming frame envelope reader.
//
// readFrame is the single most security-sensitive parser on the broker wire:
// a 4-byte, broker-influenced length field drives a make([]byte, length)
// allocation. The guest is the least-provisioned party in the architecture, so
// an unbounded length must error BEFORE any allocation. These targets live in
// package brokerrpc because readFrame/writeFrame are unexported.

package brokerrpc

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// frame builds a raw Connect frame: flag byte + big-endian uint32 length + body.
// The declared length is len(body) so the frame is self-consistent.
func frame(flag byte, body []byte) []byte {
	hdr := make([]byte, frameHeaderLen)
	hdr[0] = flag
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(body)))
	return append(hdr, body...)
}

// frameWithDeclaredLen builds a frame whose declared length need NOT equal the
// real body length, so the corpus can express oversize/truncated headers.
func frameWithDeclaredLen(flag byte, declared uint32, body []byte) []byte {
	hdr := make([]byte, frameHeaderLen)
	hdr[0] = flag
	binary.BigEndian.PutUint32(hdr[1:5], declared)
	return append(hdr, body...)
}

// FuzzReadFrame drives readFrame with an arbitrary raw byte stream.
//
// Invariants asserted (no panic on any input is the implicit baseline):
//   - On success, len(payload) == the declared header length field. A frame is
//     never reported as read with a payload shorter or longer than its header
//     claimed (no partial-as-success).
//   - readFrame NEVER allocates/returns a payload larger than maxInboundFrame.
//     A length field above the cap must be a hard error, proving the size guard
//     fires before the make([]byte, length).
//   - A truncated body (header claims N, fewer than N bytes follow) is an error,
//     never a short success.
func FuzzReadFrame(f *testing.F) {
	// Valid frames.
	f.Add(frame(0x00, []byte(`{"data":"AAAA"}`)))
	f.Add(frame(endStreamFlag, []byte(`{}`)))
	f.Add(frame(0x00, []byte{}))                        // length 0, empty payload
	f.Add(frame(0x00, bytes.Repeat([]byte("x"), 1024))) // moderate payload

	// Adversarial frames.
	f.Add(frameWithDeclaredLen(0x00, maxInboundFrame, []byte{}))   // at cap, truncated body
	f.Add(frameWithDeclaredLen(0x00, maxInboundFrame+1, []byte{})) // just over cap
	f.Add(frameWithDeclaredLen(0x00, 0xFFFFFFFF, []byte{}))        // max uint32
	f.Add(frameWithDeclaredLen(0x00, 4096, []byte("short")))       // claims 4096, body 5
	f.Add([]byte{0x00, 0x00, 0x00})                                // truncated header
	f.Add([]byte{})                                                // empty stream
	f.Add([]byte{0x07, 0x00, 0x00, 0x00, 0x00})                    // unknown flag, len 0

	f.Fuzz(func(t *testing.T, data []byte) {
		flag, payload, err := readFrame(bytes.NewReader(data))
		if err != nil {
			// Error path: nothing more to assert beyond "did not panic". A
			// truncated/oversize/empty stream is correctly an error.
			return
		}

		// Success path: the declared length must be recoverable from the input
		// and must match what we got back.
		if len(data) < frameHeaderLen {
			t.Fatalf("success on a sub-header stream of %d bytes", len(data))
		}
		declared := binary.BigEndian.Uint32(data[1:5])

		if uint32(len(payload)) != declared {
			t.Fatalf("payload length %d != declared header length %d", len(payload), declared)
		}
		if uint64(len(payload)) > uint64(maxInboundFrame) {
			t.Fatalf("payload length %d exceeds maxInboundFrame %d on a success", len(payload), maxInboundFrame)
		}
		if declared > maxInboundFrame {
			t.Fatalf("declared length %d above cap %d returned success instead of erroring", declared, maxInboundFrame)
		}
		// The flag is whatever byte 0 was; it is opaque to readFrame.
		if flag != data[0] {
			t.Fatalf("returned flag 0x%02x != input byte0 0x%02x", flag, data[0])
		}
	})
}

// FuzzReadFrameRoundTrip asserts the writeFrame -> readFrame round-trip is
// lossless for any flag/payload that fits under the cap: what writeFrame
// serialised, readFrame recovers byte-for-byte. This pins the envelope codec
// against silent corruption (a flipped length-endianness or off-by-one prefix
// would corrupt every download in a FUSE mount).
func FuzzReadFrameRoundTrip(f *testing.F) {
	f.Add(byte(0x00), []byte(`{"data":"AAAA"}`))
	f.Add(endStreamFlag, []byte(`{}`))
	f.Add(byte(0x00), []byte{})
	f.Add(byte(0xFF), bytes.Repeat([]byte("z"), 4096))

	f.Fuzz(func(t *testing.T, flag byte, payload []byte) {
		// Only round-trip payloads the reader is allowed to accept; an oversize
		// payload is a writer-side contract the reader deliberately rejects.
		if uint64(len(payload)) > uint64(maxInboundFrame) {
			return
		}

		var buf bytes.Buffer
		if err := writeFrame(&buf, flag, payload); err != nil {
			t.Fatalf("writeFrame failed for an in-bounds payload: %v", err)
		}

		gotFlag, gotPayload, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame failed to read a frame writeFrame produced: %v", err)
		}
		if gotFlag != flag {
			t.Fatalf("flag round-trip mismatch: wrote 0x%02x read 0x%02x", flag, gotFlag)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("payload round-trip mismatch: wrote %d bytes, read %d bytes", len(payload), len(gotPayload))
		}
		// Reader must have consumed exactly the frame: nothing trails.
		if rest, _ := io.ReadAll(&buf); len(rest) != 0 {
			t.Fatalf("readFrame left %d trailing bytes after a single frame", len(rest))
		}
	})
}
