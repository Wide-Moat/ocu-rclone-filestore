// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sync/errgroup"
)

// mixedOpServer routes by request path so a single socket serves all three
// data-path ops (fileDownload, listDirectory, fileUpload) from one handler.
// The handler holds no shared mutable state beyond the atomic request counter,
// so it is itself safe under the many connection goroutines the stdlib HTTP
// server spawns for concurrent clients. Each op replies with a deterministic,
// self-contained success body derived only from the request, so correctness
// does not depend on handler-side ordering.
func mixedOpServer(t *testing.T, requestCount *int64) string {
	t.Helper()
	return uploadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(requestCount, 1)

		switch {
		case r.URL.Path == serviceBase+string(OpFileDownload):
			// Server-streaming: one content frame + success trailer. Echo a
			// fixed payload so the caller can assert exact bytes.
			drainDownloadRequest(r.Body)
			var buf bytes.Buffer
			frame, _ := json.Marshal(map[string][]byte{"data": []byte("DL-payload")})
			_ = writeFrame(&buf, 0x00, frame)
			_ = writeEndStream(&buf, nil)
			w.Header().Set("Content-Type", "application/connect+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(buf.Bytes())

		case r.URL.Path == serviceBase+string(OpFileUpload):
			// Client-streaming: drain every request frame, then reply with a
			// success end-stream trailer.
			for {
				_, _, err := readFrame(r.Body)
				if err != nil {
					break
				}
			}
			var buf bytes.Buffer
			_ = writeEndStream(&buf, nil)
			w.Header().Set("Content-Type", "application/connect+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(buf.Bytes())

		case r.URL.Path == serviceBase+string(OpListDirectory):
			// Unary: a single page of one directory entry, empty cursor (last
			// and only page). The union shape carries a `directory` arm.
			_, _ = io.ReadAll(r.Body)
			respBody := []byte(`{"entries":[{"directory":{"path":"/d","mtime":"2026-01-01T00:00:00Z"}}]}`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBody)

		default:
			t.Errorf("unexpected route %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// drainDownloadRequest reads the single request params frame and any trailing
// bytes so the connection can be reused, ignoring errors (the params frame is
// not under test here).
func drainDownloadRequest(body io.Reader) {
	_, _, _ = readFrame(body)
	_, _ = io.ReadAll(body)
}

// TestConcurrentOpsOneSharedClient is the load-bearing concurrency proof.
// Production fans parallel FUSE operations through a SINGLE *Client; this test
// issues many concurrent operations — a mix of Download, ListDirectoryAll and
// Upload — against ONE shared *Client bound to one in-process server, and
// asserts every operation succeeds with the expected result. The -race run is
// the point: a data race on the shared Client's fields, its http.Client, or the
// per-op stamping/framing would be flagged by the detector. (Run with -race.)
func TestConcurrentOpsOneSharedClient(t *testing.T) {
	var requestCount int64
	sock := mixedOpServer(t, &requestCount)

	// ONE Client, shared across every goroutine.
	c, err := New(sock, "fs-conc-01")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const total = 30 // > the 20 floor; multiple of 3 so each op runs 10 times.
	g, ctx := errgroup.WithContext(context.Background())

	for i := 0; i < total; i++ {
		i := i
		g.Go(func() error {
			switch i % 3 {
			case 0:
				got, err := c.Download(ctx, fmt.Sprintf("uuid-%d", i))
				if err != nil {
					return fmt.Errorf("Download #%d: %w", i, err)
				}
				if !bytes.Equal(got, []byte("DL-payload")) {
					return fmt.Errorf("Download #%d: got %q, want %q", i, got, "DL-payload")
				}
			case 1:
				entries, err := c.ListDirectoryAll(ctx, fmt.Sprintf("/dir-%d", i))
				if err != nil {
					return fmt.Errorf("ListDirectoryAll #%d: %w", i, err)
				}
				if len(entries) != 1 {
					return fmt.Errorf("ListDirectoryAll #%d: got %d entries, want 1", i, len(entries))
				}
				if entries[0].Directory == nil {
					return fmt.Errorf("ListDirectoryAll #%d: directory arm nil", i)
				}
			default:
				payload := bytes.Repeat([]byte("u"), 64)
				if err := c.Upload(ctx, fmt.Sprintf("/up-%d.bin", i), bytes.NewReader(payload), int64(len(payload)), false); err != nil {
					return fmt.Errorf("Upload #%d: %w", i, err)
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		t.Fatalf("concurrent ops against shared Client: %v", err)
	}

	// Every operation reached the server. ListDirectoryAll terminates in a
	// single call here (empty cursor), so the request count equals the op
	// count exactly.
	if got := atomic.LoadInt64(&requestCount); got != total {
		t.Errorf("server saw %d requests, want %d (one per op)", got, total)
	}
}

// TestConcurrentUploadsStressPipeOrdering runs several overlapping Upload()
// calls against one shared *Client under -race, including a large multi-chunk
// upload. Upload() spawns a frame-writer goroutine that feeds an io.Pipe while
// http.Do consumes the read end and the result is collected over errCh before
// the trailer is read; concurrent uploads multiply that per-call goroutine
// choreography. A race in the writer-goroutine/http.Do/errCh/trailer ordering
// — or shared state leaking across the per-call pipes — would surface under the
// detector. (Run with -race.)
func TestConcurrentUploadsStressPipeOrdering(t *testing.T) {
	var requestCount int64
	sock := mixedOpServer(t, &requestCount)

	c, err := New(sock, "fs-conc-up-01")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Sizes include at least one large (>4 MiB) multi-chunk upload that is
	// still mid-stream while smaller uploads complete, stressing the ordering.
	sizes := []int{
		1,
		64,
		200 * 1024,
		5 * 1024 * 1024, // > 4 MiB: many chunk frames at the default ceiling.
		300 * 1024,
		1024,
	}

	var wg sync.WaitGroup
	errs := make([]error, len(sizes))
	for idx, n := range sizes {
		wg.Add(1)
		go func(idx, n int) {
			defer wg.Done()
			payload := bytes.Repeat([]byte("Z"), n)
			errs[idx] = c.Upload(
				context.Background(),
				fmt.Sprintf("/stress-%d.bin", idx),
				bytes.NewReader(payload),
				int64(n),
				false,
			)
		}(idx, n)
	}
	wg.Wait()

	for idx, err := range errs {
		if err != nil {
			t.Errorf("overlapping Upload #%d (%d bytes): %v", idx, sizes[idx], err)
		}
	}
	if got := atomic.LoadInt64(&requestCount); got != int64(len(sizes)) {
		t.Errorf("server saw %d upload requests, want %d", got, len(sizes))
	}
}
