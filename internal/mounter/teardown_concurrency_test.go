// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// barrierWaitBound is the bounded fallback for the barrier seam below. Under a
// sequential unmountAll the barrier can never release (the next unmount does
// not start until the current one returns), so instead of hanging, the fake
// records that no overlap was observed and lets the test fail deterministically.
const barrierWaitBound = 2 * time.Second

// barrierSeamFake is a pointMounter whose unmount blocks until EVERY expected
// unmount has started. It is the pin for F-61: teardown must drain points
// CONCURRENTLY, because each real drain can hold writebackDrainTimeout +
// unmountDetachGrace and a sequential walk stacks those budgets past the
// compose stop_grace_period. The barrier makes concurrency the pass condition
// without timing races: concurrent unmounts all reach the barrier and release
// each other immediately; a sequential walk strands the first unmount at the
// barrier (the second cannot start), the bounded fallback fires, and
// noOverlap records the failure.
type barrierSeamFake struct {
	mu sync.Mutex

	expectedUnmounts int
	unmountsStarted  int
	allStarted       chan struct{}
	noOverlap        bool // set when an unmount timed out waiting for the others

	// holdAfterBarrier optionally holds each unmount after the barrier
	// releases, standing in for a per-point drain of known length so the
	// secondary wall-clock sanity check has something to measure.
	holdAfterBarrier time.Duration

	mountCalls   int
	unmountCalls []string // destinations passed to unmount (order is nondeterministic under the fan-out)
	failNth      int      // 1-based index of the mountAndWaitReady to fail; 0 = never
}

func newBarrierSeamFake(expected int) *barrierSeamFake {
	return &barrierSeamFake{expectedUnmounts: expected, allStarted: make(chan struct{})}
}

func (f *barrierSeamFake) mountAndWaitReady(_ context.Context, spec mountSpec) (point, error) {
	f.mu.Lock()
	f.mountCalls++
	n := f.mountCalls
	f.mu.Unlock()
	if f.failNth != 0 && n == f.failNth {
		return nil, errFakeStart
	}
	return &fakePoint{dest: spec.mount.Destination, waitErr: make(chan error, 1)}, nil
}

func (f *barrierSeamFake) unmount(p point) error {
	f.mu.Lock()
	f.unmountCalls = append(f.unmountCalls, p.destination())
	f.unmountsStarted++
	if f.unmountsStarted == f.expectedUnmounts {
		close(f.allStarted)
	}
	f.mu.Unlock()

	select {
	case <-f.allStarted:
	case <-time.After(barrierWaitBound):
		f.mu.Lock()
		f.noOverlap = true
		f.mu.Unlock()
	}
	if f.holdAfterBarrier > 0 {
		time.Sleep(f.holdAfterBarrier)
	}
	return nil
}

func (f *barrierSeamFake) overlapMissed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.noOverlap
}

func (f *barrierSeamFake) unmountCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.unmountCalls)
}

// errFakeStart is the injected mountAndWaitReady failure; the orchestrator
// only wraps it, so any sentinel serves.
var errFakeStart = errors.New("fake start failure")

// TestUnmountAllDrainsPointsConcurrentlyOnSignal pins F-61 on the signal
// teardown path: with two live points, SIGTERM-driven teardown must start both
// unmounts concurrently, so whole-teardown cost is the MAX over points, not
// the sum. The test synchronizes on the readiness signal (the ready-file)
// BEFORE delivering SIGTERM: once the ready-file exists, signalReady has run
// and the only remaining signal consumer is blockUntilTeardown's select, so
// the signal-teardown path is exercised deterministically.
func TestUnmountAllDrainsPointsConcurrentlyOnSignal(t *testing.T) {
	fake := newBarrierSeamFake(2)
	fake.holdAfterBarrier = 250 * time.Millisecond
	sig := make(chan os.Signal, 1)
	readyFile := filepath.Join(t.TempDir(), "ready")

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/a"), writableEntry("/mnt/b")},
	}
	o := &orchestrator{
		seam:       fake,
		readiness:  ReadinessConfig{ReadyFilePath: readyFile},
		signals:    sig,
		serviceURL: "https://broker.example",
		caCertPEM:  "pem",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	waitForFile(t, readyFile)
	teardownStart := time.Now()
	sig <- syscall.SIGTERM

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v; want nil on clean signal teardown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after signal")
	}
	elapsed := time.Since(teardownStart)

	// Load-bearing assertion: both unmounts overlapped in time. A sequential
	// unmountAll strands the first unmount at the barrier until the bounded
	// fallback fires, so this fails deterministically, not by timing.
	if fake.overlapMissed() {
		t.Fatal("unmounts did not overlap: teardown drained points sequentially, stacking per-point drain budgets (N x 123s) past the compose stop_grace_period")
	}
	if fake.unmountCount() != 2 {
		t.Errorf("unmountCount = %d; want 2 (all points torn down)", fake.unmountCount())
	}
	// Secondary sanity only (>=4x margin): two unmounts each holding 250ms
	// after the barrier must finish well under 4x the hold when concurrent.
	// The barrier above is the load-bearing proof; drop this bound before ever
	// tightening it if it flakes on a loaded runner.
	if elapsed > time.Second {
		t.Errorf("teardown of 2 concurrent 250ms unmounts took %v; want < 1s (secondary sanity bound)", elapsed)
	}
}

// TestUnmountAllDrainsPointsConcurrentlyOnFailFast pins F-61 on the fail-fast
// startup path: when the third mountAndWaitReady fails, the two
// already-started points must drain concurrently during the best-effort
// cleanup, and the aggregated error still names the failed destination.
func TestUnmountAllDrainsPointsConcurrentlyOnFailFast(t *testing.T) {
	fake := newBarrierSeamFake(2)
	fake.failNth = 3
	sig := make(chan os.Signal, 1)

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/a"), writableEntry("/mnt/b"), writableEntry("/mnt/c")},
	}
	o := &orchestrator{
		seam:       fake,
		signals:    sig,
		serviceURL: "https://broker.example",
		caCertPEM:  "pem",
	}

	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil; want the aggregated fail-fast error")
	}
	if !strings.Contains(err.Error(), "/mnt/c") {
		t.Errorf("error %q does not name the failed destination /mnt/c", err.Error())
	}
	if fake.overlapMissed() {
		t.Fatal("fail-fast cleanup did not overlap unmounts: the started points drained sequentially")
	}
	if fake.unmountCount() != 2 {
		t.Errorf("unmountCount = %d; want 2 (both started points torn down)", fake.unmountCount())
	}
}
