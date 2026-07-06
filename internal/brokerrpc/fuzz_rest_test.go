// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// White-box fuzz targets for the REST response decode paths.
//
// On the read path the client decodes two broker-controlled shapes: the unary
// 2xx JSON body (into a response struct) and the fileDownload octet-stream body
// (read as raw bytes, bounded by the download cap). Neither must panic on
// arbitrary input, and the download cap must never be exceeded by a success.

package brokerrpc

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

// FuzzUnaryResponseDecode drives the unary 2xx JSON decode with arbitrary bytes.
// The tolerant decoder must never panic; on success the listing slice is
// range-safe.
func FuzzUnaryResponseDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"entries":[{"file":{"path":"/a","uuid":"u","size":1}}],"cursor":"c"}`))
	f.Add([]byte(`{"entries":[{"directory":{"path":"/d"}}]}`))
	f.Add([]byte(`{"entries":null}`))
	f.Add([]byte(`["not","an","object"]`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Add([]byte(`{"entries":[{}]}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		var resp ListDirectoryResponse
		// Mirror call()'s decode: an error is fine, a panic is not.
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		// Success: ranging the entries must be safe.
		for range resp.Entries {
		}
	})
}

// FuzzDownloadBodyRead drives the bounded octet-stream read used by doDownload.
// Arbitrary bytes under the cap must read back exactly; the read must never
// panic or exceed the cap.
func FuzzDownloadBodyRead(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte("x"), 4096))
	f.Add([]byte{0x00, 0xFF, 0x7F, 0x80})

	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := io.ReadAll(io.LimitReader(bytes.NewReader(body), defaultMaxDownloadBytes+1))
		if err != nil {
			t.Fatalf("bounded read of an in-memory body must not error: %v", err)
		}
		if int64(len(got)) > defaultMaxDownloadBytes {
			t.Fatalf("read %d bytes exceeds the cap %d", len(got), defaultMaxDownloadBytes)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("bounded read did not round-trip: %d vs %d bytes", len(got), len(body))
		}
	})
}
