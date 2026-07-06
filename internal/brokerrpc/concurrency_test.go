// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sync/errgroup"
)

// mixedOpHandler routes by REST path so one TLS server serves all three
// data-path ops (fileDownload, listDirectory, fileUpload) from one handler. It
// holds no shared mutable state beyond the atomic request counter, so it is safe
// under the many connection goroutines the stdlib HTTP server spawns.
func mixedOpHandler(t *testing.T, requestCount *int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(requestCount, 1)
		switch r.URL.Path {
		case "/" + restBase + string(OpFileDownload):
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("DL-payload"))

		case "/" + restBase + string(OpFileUpload):
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)

		case "/" + restBase + string(OpListDirectory):
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"entries":[{"directory":{"path":"/d","mtime":"2026-01-01T00:00:00Z"}}]}`))

		default:
			t.Errorf("unexpected route %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// TestConcurrentOpsOneSharedClient is the load-bearing concurrency proof.
// Production fans parallel FUSE operations through a SINGLE *Client; this test
// issues many concurrent operations against ONE shared *Client and asserts every
// operation succeeds. The -race run is the point: a data race on the shared
// Client's fields, its http.Client, or per-op stamping would be flagged.
func TestConcurrentOpsOneSharedClient(t *testing.T) {
	var requestCount int64
	c, _ := newTLSTestClient(t, "fs-conc-01", mixedOpHandler(t, &requestCount))

	const total = 30
	g, ctx := errgroup.WithContext(context.Background())

	for i := 0; i < total; i++ {
		g.Go(func() error {
			switch i % 3 {
			case 0:
				rc, err := c.Download(ctx, fmt.Sprintf("uuid-%d", i))
				if err != nil {
					return fmt.Errorf("Download #%d: %w", i, err)
				}
				got, rErr := io.ReadAll(rc)
				_ = rc.Close()
				if rErr != nil {
					return fmt.Errorf("Download #%d read: %w", i, rErr)
				}
				if !bytes.Equal(got, []byte("DL-payload")) {
					return fmt.Errorf("Download #%d: got %q", i, got)
				}
			case 1:
				entries, err := c.ListDirectoryAll(ctx, fmt.Sprintf("/dir-%d", i))
				if err != nil {
					return fmt.Errorf("ListDirectoryAll #%d: %w", i, err)
				}
				if len(entries) != 1 || entries[0].Directory == nil {
					return fmt.Errorf("ListDirectoryAll #%d: unexpected entries %v", i, entries)
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
	if got := atomic.LoadInt64(&requestCount); got != total {
		t.Errorf("server saw %d requests, want %d", got, total)
	}
}

// TestConcurrentUploadsStressOrdering runs several overlapping Upload() calls
// against one shared *Client under -race, including a large multi-chunk upload.
// Each Upload spawns a body-writer goroutine feeding an io.Pipe while http.Do
// consumes the read end; concurrent uploads multiply that choreography. A race
// in the writer/Do/errCh ordering would surface under the detector.
func TestConcurrentUploadsStressOrdering(t *testing.T) {
	var requestCount int64
	c, _ := newTLSTestClient(t, "fs-conc-up-01", mixedOpHandler(t, &requestCount))

	sizes := []int{1, 64, 200 * 1024, 5 * 1024 * 1024, 300 * 1024, 1024}

	var wg sync.WaitGroup
	errs := make([]error, len(sizes))
	for idx, n := range sizes {
		wg.Add(1)
		go func(idx, n int) {
			defer wg.Done()
			payload := bytes.Repeat([]byte("Z"), n)
			errs[idx] = c.Upload(context.Background(), fmt.Sprintf("/stress-%d.bin", idx),
				bytes.NewReader(payload), int64(n), false)
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
