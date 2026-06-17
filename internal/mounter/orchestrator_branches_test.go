// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// unmountErrFake wraps the recording fake's behaviour but lets every unmount
// fail with a fixed error, so the unmountAll error-collecting branch and run's
// aggregation of cleanup errors are exercised. It records the same way as the
// shared fake so the existing assertions translate.
type unmountErrFake struct {
	mu           sync.Mutex
	mountCalls   []string
	unmountCalls []string
	points       []*fakePoint
	unmountErr   error
}

func (f *unmountErrFake) mountAndWaitReady(_ context.Context, spec mountSpec) (point, error) {
	f.mu.Lock()
	f.mountCalls = append(f.mountCalls, spec.mount.Destination)
	p := &fakePoint{dest: spec.mount.Destination, waitErr: make(chan error, 1)}
	f.points = append(f.points, p)
	f.mu.Unlock()
	return p, nil
}

func (f *unmountErrFake) unmount(p point) error {
	f.mu.Lock()
	f.unmountCalls = append(f.unmountCalls, p.destination())
	f.mu.Unlock()
	return f.unmountErr
}

func (f *unmountErrFake) mountCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mountCalls)
}

func (f *unmountErrFake) unmountCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.unmountCalls)
}

// TestRunNoSeamConfigured covers the run branch where neither a seam nor a
// newSeam constructor is wired: run must return the "no mount seam configured"
// hard error after the socket check passes, before any mount is attempted.
func TestRunNoSeamConfigured(t *testing.T) {
	o := &orchestrator{
		signals:    make(chan os.Signal, 1),
		serviceURL: "https://broker.example",
		caCertPEM:  "pem",
		// seam and newSeam both nil
	}
	err := o.run(context.Background(), &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/w")},
	})
	if err == nil {
		t.Fatal("run = nil; want the no-mount-seam-configured hard error")
	}
	if !strings.Contains(err.Error(), "no mount seam configured") {
		t.Fatalf("run error = %q; want the no-mount-seam-configured error", err.Error())
	}
}

// TestRunInstallsDefaultSignalChannel covers the run branch that installs a
// default SIGTERM/SIGINT channel when the entrypoint injected none. The
// zero-mount config returns cleanly after the default channel is installed, so
// the branch runs without depending on delivering a real OS signal.
func TestRunInstallsDefaultSignalChannel(t *testing.T) {
	o := &orchestrator{
		seam:       newFake(),
		serviceURL: "https://broker.example",
		caCertPEM:  "pem",
		// signals nil -> run installs the default channel
	}
	if err := o.run(context.Background(), &mountcfg.Config{Mounts: []mountcfg.Mount{}}); err != nil {
		t.Fatalf("run = %v; want nil for zero mounts with a default signal channel", err)
	}
	if o.signals == nil {
		t.Error("run left o.signals nil; want the default channel installed")
	}
}

// TestUnmountAllCollectsErrors covers the unmountAll error-collecting branch and
// run's aggregation of cleanup errors: every unmount fails, so the clean signal
// teardown still surfaces the per-point unmount errors (best-effort cleanup that
// reports what it could not tear down). Each error names its destination.
func TestUnmountAllCollectsErrors(t *testing.T) {
	fake := &unmountErrFake{unmountErr: errors.New("device busy")}
	sig := make(chan os.Signal, 1)

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/a"), writableEntry("/mnt/b")},
	}
	o := &orchestrator{
		seam:       fake,
		signals:    sig,
		serviceURL: "https://broker.example",
		caCertPEM:  "pem",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for fake.mountCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("mounts never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	sig <- syscall.SIGTERM
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run = nil; want the aggregated unmount errors surfaced from teardown")
		}
		if !strings.Contains(err.Error(), "/mnt/a") || !strings.Contains(err.Error(), "/mnt/b") {
			t.Fatalf("run error = %q; want both failed destinations named", err.Error())
		}
		if !strings.Contains(err.Error(), "device busy") {
			t.Fatalf("run error = %q; want the underlying unmount error wrapped", err.Error())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after signal")
	}
	if fake.unmountCount() != 2 {
		t.Errorf("unmountCount = %d; want 2 (best-effort tried every point despite errors)", fake.unmountCount())
	}
}

// TestRunCleanSpontaneousExit covers blockUntilTeardown's clean-spontaneous-exit
// branch: a point's wait() returns nil (a clean self-exit). run still ends the
// process, unmounts the remaining points, and returns nil because there is no
// point error to surface.
func TestRunCleanSpontaneousExit(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/x"), writableEntry("/mnt/y")},
	}
	o := &orchestrator{
		seam:       fake,
		signals:    sig,
		serviceURL: "https://broker.example",
		caCertPEM:  "pem",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for fake.mountCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("points never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A clean (nil) spontaneous exit of the first point.
	fake.points[0].waitErr <- nil

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v; want nil on a clean spontaneous point exit", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after a clean spontaneous exit")
	}
	// The exited point is already down; only the remaining point is unmounted.
	if fake.unmountCount() != 1 {
		t.Errorf("unmountCount = %d; want 1 (the remaining point; the exited one is already down)", fake.unmountCount())
	}
}

// TestRunSignalAfterLastMount covers the second signalPending check in run: a
// termination signal that arrives after every mount completed but before
// readiness is signalled must still suppress the ready-file and tear down
// cleanly. The fake holds the last mount until we release it; we plant the
// signal in the buffered channel first, then release, so the post-fan-out
// recheck observes it.
func TestRunSignalAfterLastMount(t *testing.T) {
	fake := newFake()
	fake.delayReadyLast = true
	fake.totalSpecs = 2
	sig := make(chan os.Signal, 2)
	readyFile := tmpReadyPath(t)

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

	// Wait until the first mount is up and the orchestrator is blocked on the
	// last mount (delayReadyLast). The per-iteration signalPending check for the
	// last spec already ran (no signal yet), so place the signal now and release
	// the last mount: the only remaining check that can observe it is the
	// post-fan-out recheck immediately before signalReady.
	deadline := time.Now().Add(2 * time.Second)
	for fake.mountCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("orchestrator never reached the delayed last mount")
		}
		time.Sleep(5 * time.Millisecond)
	}
	sig <- syscall.SIGTERM
	close(fake.releaseReady)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v; want nil on a clean signal-driven shutdown after the last mount", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after the post-fan-out signal")
	}
	if _, statErr := os.Stat(readyFile); !os.IsNotExist(statErr) {
		t.Error("ready-file created despite a signal arriving before signalReady; readiness must never appear after termination requested")
	}
}
