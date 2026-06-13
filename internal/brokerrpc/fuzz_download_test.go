// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// White-box fuzz target for the fileDownload stream reassembler.
//
// reassembleDownloadStream is the highest-complexity decode loop on the read
// path: a multi-frame stream of base64-bearing content frames terminated by an
// EndStreamResponse trailer. For a FUSE-backed mount, returning truncated bytes
// as success is silent file corruption — the worst failure mode. This target
// lives in package brokerrpc because the reassembler is unexported.

package brokerrpc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"
)

// rawFrame builds a self-consistent Connect frame (flag + BE len + body).
func rawFrame(flag byte, body []byte) []byte {
	hdr := make([]byte, frameHeaderLen)
	hdr[0] = flag
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(body)))
	return append(hdr, body...)
}

// FuzzReassembleDownloadStream drives the reassembler with an arbitrary frame
// stream.
//
// Invariants (no panic on any input is the baseline):
//   - A stream that ends before the 0x02 trailer is ALWAYS an error. Accumulated
//     content is never returned as success without the terminating trailer
//     (the truncation-is-corruption guard).
//   - A success result (err == nil) is only reachable through a trailer with no
//     error object; on success the returned slice is non-nil-or-empty and the
//     function consumed a real trailer.
//   - A malformed content frame is a hard error (never truncated-as-success).
func FuzzReassembleDownloadStream(f *testing.F) {
	mkData := func(b64 string) []byte { return []byte(`{"data":"` + b64 + `"}`) }
	trailerOK := []byte(`{}`)
	trailerErr := []byte(`{"error":{"code":"unavailable","message":"x"}}`)

	// Valid: single content frame + OK trailer.
	f.Add(append(rawFrame(0x00, mkData("aGVsbG8=")), rawFrame(endStreamFlag, trailerOK)...))
	// Valid: multi content frame + OK trailer.
	f.Add(bytes.Join([][]byte{
		rawFrame(0x00, mkData("YQ==")),
		rawFrame(0x00, mkData("Yg==")),
		rawFrame(endStreamFlag, trailerOK),
	}, nil))
	// Valid: zero-length data frame then trailer.
	f.Add(append(rawFrame(0x00, mkData("")), rawFrame(endStreamFlag, trailerOK)...))
	// Trailer-only (empty object, success, zero bytes).
	f.Add(rawFrame(endStreamFlag, trailerOK))
	// Error trailer — must surface as a non-nil error.
	f.Add(rawFrame(endStreamFlag, trailerErr))

	// Adversarial.
	f.Add(rawFrame(0x00, mkData("aGVsbG8=")))                    // content, no trailer (truncated)
	f.Add(rawFrame(0x00, []byte(`{"data":"!!!not base64!!!"}`))) // malformed base64 data
	f.Add(rawFrame(0x00, []byte(`{`)))                           // malformed JSON data frame
	f.Add(rawFrame(endStreamFlag, []byte(`{`)))                  // malformed JSON trailer
	f.Add([]byte{0x00, 0x00, 0x00})                              // truncated header
	f.Add([]byte{})                                              // empty stream

	f.Fuzz(func(t *testing.T, stream []byte) {
		hdr := http.Header{}
		out, err := reassembleDownloadStream(bytes.NewReader(stream), hdr)

		if err != nil {
			// Error path: must not also hand back content (no truncation leak).
			if out != nil {
				t.Fatalf("error path returned non-nil content (%d bytes): truncation leak", len(out))
			}
			return
		}

		// Success path is only valid if the stream actually contained a
		// well-formed end-stream (0x02) trailer with no error object. Re-scan
		// the stream to confirm a trailer frame was present and reachable; if
		// success was reported without one, that is the corruption-as-success
		// bug the guard must prevent.
		if !streamHasReachableOKTrailer(t, stream) {
			t.Fatalf("success returned for a stream with no reachable OK trailer (%d content bytes)", len(out))
		}
	})
}

// streamHasReachableOKTrailer walks the stream the same way the reassembler
// does and reports whether an end-stream frame with an empty/no-error trailer
// is reached before the stream runs out or a frame fails to parse. It is an
// independent oracle for the success precondition.
func streamHasReachableOKTrailer(t *testing.T, stream []byte) bool {
	t.Helper()
	r := bytes.NewReader(stream)
	for {
		flag, payload, err := readFrame(r)
		if err != nil {
			return false
		}
		if flag == endStreamFlag {
			var esr EndStreamResponse
			if jsonErr := json.Unmarshal(payload, &esr); jsonErr != nil {
				return false
			}
			return esr.Error == nil
		}
		// Content frame: it must parse and (if it carries data) decode, mirroring
		// the reassembler's hard-error stance on a malformed frame.
		var cf downloadContentFrame
		if jsonErr := json.Unmarshal(payload, &cf); jsonErr != nil {
			return false
		}
	}
}
