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

// fakePoint is a test handle the fake seam hands back to the orchestrator. Its
// wait() blocks until the test (or the seam's failNth path) makes it return.
type fakePoint struct {
	dest    string
	waitErr chan error
}

func (p *fakePoint) destination() string { return p.dest }
func (p *fakePoint) wait() error         { return <-p.waitErr }

// fakePointMounter records the mount/unmount calls so the orchestration policy
// is provable without a real mount. failNth makes the Nth mountAndWaitReady
// return an error; delayReadyLast holds the last mount until released.
type fakePointMounter struct {
	mu sync.Mutex

	mountCalls   []string // destinations passed to mountAndWaitReady, in order
	unmountCalls []string // destinations passed to unmount, in order
	points       []*fakePoint

	failNth        int // 1-based index of the start to fail; 0 = never fail
	releaseReady   chan struct{}
	delayReadyLast bool // hold the last mountAndWaitReady until releaseReady closes
	totalSpecs     int  // number of specs the orchestrator will start
}

func newFake() *fakePointMounter {
	return &fakePointMounter{releaseReady: make(chan struct{})}
}

func (f *fakePointMounter) mountAndWaitReady(_ context.Context, spec mountSpec) (point, error) {
	f.mu.Lock()
	n := len(f.mountCalls) + 1
	f.mountCalls = append(f.mountCalls, spec.mount.Destination)
	f.mu.Unlock()

	if f.failNth != 0 && n == f.failNth {
		return nil, errors.New("fake start failure")
	}

	if f.delayReadyLast && n == f.totalSpecs {
		<-f.releaseReady
	}

	p := &fakePoint{dest: spec.mount.Destination, waitErr: make(chan error, 1)}
	f.mu.Lock()
	f.points = append(f.points, p)
	f.mu.Unlock()
	return p, nil
}

func (f *fakePointMounter) unmount(p point) error {
	f.mu.Lock()
	f.unmountCalls = append(f.unmountCalls, p.destination())
	f.mu.Unlock()
	return nil
}

func (f *fakePointMounter) unmountCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.unmountCalls)
}

func (f *fakePointMounter) mountCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mountCalls)
}

// writableEntry / readonlyEntry build minimal valid config mounts for the
// orchestrator tests (the scope split is enforced by the loader; here we only
// need fields the orchestrator threads through).
func writableEntry(dest string) mountcfg.Mount {
	return mountcfg.Mount{
		Destination:     dest,
		FilesystemID:    ptrStr("fs-" + dest),
		VfsCacheMode:    "writes",
		CacheDurationS:  ptrInt(60),
		VfsCacheMaxSize: "0",
		DirPerms:        "0755",
		FilePerms:       "0644",
	}
}

func readonlyEntry(dest string) mountcfg.Mount {
	m := writableEntry(dest)
	return m
}

func TestOrchestratorFanOutAndSignalTeardown(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)
	readyFile := filepath.Join(t.TempDir(), "ready")

	cfg := &mountcfg.Config{
		Mounts:         []mountcfg.Mount{writableEntry("/mnt/w")},
		ReadonlyMounts: []mountcfg.Mount{readonlyEntry("/mnt/r")},
	}

	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyFile},
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	// Wait for readiness to be signaled (ready-file created).
	waitForFile(t, readyFile)

	if fake.mountCount() != 2 {
		t.Fatalf("mountCount = %d; want 2", fake.mountCount())
	}

	sig <- syscall.SIGTERM

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v; want nil on clean signal teardown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after signal")
	}

	if fake.unmountCount() != 2 {
		t.Errorf("unmountCount = %d; want 2 (all points torn down)", fake.unmountCount())
	}
}

func TestOrchestratorFailFastSecondPoint(t *testing.T) {
	fake := newFake()
	fake.failNth = 2
	sig := make(chan os.Signal, 1)
	readyFile := filepath.Join(t.TempDir(), "ready")

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/first"), writableEntry("/mnt/second")},
	}

	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyFile},
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil error; want a non-nil aggregated error on fail-fast")
	}
	if !strings.Contains(err.Error(), "/mnt/second") {
		t.Errorf("error %q does not name the failed destination /mnt/second", err.Error())
	}
	if fake.unmountCount() != 1 {
		t.Errorf("unmountCount = %d; want 1 (the already-started first point)", fake.unmountCount())
	}
	if _, statErr := os.Stat(readyFile); !os.IsNotExist(statErr) {
		t.Errorf("ready-file exists after fail-fast; want it never created")
	}
}

func TestOrchestratorReadinessOrdering(t *testing.T) {
	fake := newFake()
	fake.delayReadyLast = true
	fake.totalSpecs = 2
	sig := make(chan os.Signal, 1)
	readyFile := filepath.Join(t.TempDir(), "ready")

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/a"), writableEntry("/mnt/b")},
	}

	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyFile},
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	// Give the orchestrator time to start the first point and block on the
	// second; the ready-file must NOT exist while the last point is pending.
	time.Sleep(100 * time.Millisecond)
	if _, statErr := os.Stat(readyFile); !os.IsNotExist(statErr) {
		t.Fatalf("ready-file exists before the last point is ready; want absent")
	}

	close(fake.releaseReady)
	waitForFile(t, readyFile)

	sig <- syscall.SIGINT
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after signal")
	}
}

func TestOrchestratorSpontaneousPointError(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/x"), writableEntry("/mnt/y")},
	}

	o := &orchestrator{
		seam:             fake,
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	// Wait until both points are started, then make one wait() return an error.
	deadline := time.Now().Add(2 * time.Second)
	for fake.mountCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("points never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	wantErr := errors.New("point died")
	fake.points[0].waitErr <- wantErr

	select {
	case err := <-done:
		if !errors.Is(err, wantErr) {
			t.Fatalf("run = %v; want the spontaneous point error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after a spontaneous point error")
	}
	// The point that exited on its own is already down; the orchestrator
	// unmounts only the remaining point (decision 7).
	if fake.unmountCount() != 1 {
		t.Errorf("unmountCount = %d; want 1 (the remaining point; the exited one is already down)", fake.unmountCount())
	}
}

// TestOrchestratorSignalDuringFanOut is the HI-01 regression: a termination
// signal already pending when run starts the fan-out must abort startup BEFORE
// readiness is advertised. The orchestrator polls the signal channel before each
// mountAndWaitReady; with a signal buffered up front it should start no point
// (or unmount whatever it started), create NO ready-file, and return cleanly.
func TestOrchestratorSignalDuringFanOut(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)
	sig <- syscall.SIGTERM // pending before run polls
	readyFile := filepath.Join(t.TempDir(), "ready")

	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{writableEntry("/mnt/a"), writableEntry("/mnt/b")},
	}

	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyFile},
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	err := o.run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run = %v; want nil on a clean signal-driven shutdown during fan-out", err)
	}
	// The signal was observed before the first mount, so no point starts and the
	// fan-out aborts. Every started point (here zero) must be unmounted.
	if fake.mountCount() > fake.unmountCount() {
		t.Errorf("started %d points but unmounted only %d; started points must be torn down on signal",
			fake.mountCount(), fake.unmountCount())
	}
	if _, statErr := os.Stat(readyFile); !os.IsNotExist(statErr) {
		t.Error("ready-file created after a termination signal during fan-out; readiness must never appear after termination requested")
	}
}

func TestOrchestratorMemoryStoreHardError(t *testing.T) {
	fake := newFake()
	cfg := &mountcfg.Config{
		Mounts: []mountcfg.Mount{},
		ReadonlyMounts: []mountcfg.Mount{{
			Destination:   "/mnt/mem",
			MemoryStoreID: ptrStr("mem-1"),
		}},
	}
	o := &orchestrator{
		seam:             fake,
		signals:          make(chan os.Signal, 1),
		brokerSocketPath: "/run/x.sock",
	}
	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil; want a hard error for a memory_store_id mount")
	}
	if fake.mountCount() != 0 {
		t.Errorf("mountCount = %d; want 0 (no point started)", fake.mountCount())
	}
}

func TestOrchestratorZeroMounts(t *testing.T) {
	fake := newFake()
	readyFile := filepath.Join(t.TempDir(), "ready")
	cfg := &mountcfg.Config{Mounts: []mountcfg.Mount{}}
	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyFile},
		signals:          make(chan os.Signal, 1),
		brokerSocketPath: "/run/x.sock",
	}
	if err := o.run(context.Background(), cfg); err != nil {
		t.Fatalf("run = %v; want nil for zero mounts", err)
	}
	if fake.mountCount() != 0 {
		t.Errorf("mountCount = %d; want 0", fake.mountCount())
	}
	if _, statErr := os.Stat(readyFile); !os.IsNotExist(statErr) {
		t.Errorf("ready-file created for zero mounts; want absent")
	}
}

func TestOrchestratorEmptyBrokerSocketIsHardError(t *testing.T) {
	fake := newFake()
	cfg := &mountcfg.Config{Mounts: []mountcfg.Mount{writableEntry("/mnt/w")}}
	o := &orchestrator{
		seam:             fake,
		signals:          make(chan os.Signal, 1),
		brokerSocketPath: "",
	}
	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil; want a hard error for an empty broker socket path")
	}
	if fake.mountCount() != 0 {
		t.Errorf("mountCount = %d; want 0 (no spec started)", fake.mountCount())
	}
}

// TestNewMountEmptyBrokerSocketHardErrorWinsOverSeam asserts that New() with no
// WithBrokerSocket option reaches the orchestrator's empty-broker-socket hard
// error BEFORE the production seam is constructed (W6 error precedence). This
// holds on every platform: on a mount2-supported host the real seam would
// construct fine but is never reached; on an unsupported host the fail-closed
// seam error is likewise pre-empted by the socket check. Either way the error
// names the broker-socket gap, not a mount-method error — proving the check
// runs first and no /dev/fuse is touched.
func TestNewMountEmptyBrokerSocketHardErrorWinsOverSeam(t *testing.T) {
	err := New().Mount(&mountcfg.Config{
		ServiceURL: "https://broker.example",
		Mounts:     []mountcfg.Mount{writableEntry("/mnt/w")},
	})
	if err == nil {
		t.Fatal("New().Mount with no broker socket = nil; want the empty-broker-socket hard error")
	}
	if !strings.Contains(err.Error(), "broker socket path not provided") {
		t.Fatalf("New().Mount error = %q; want the empty-broker-socket hard error to win over the seam", err.Error())
	}
}

// TestOrchestratorStaleReadyFileRemovedAndRetracted is the ME-01 regression: a
// pre-existing ready-file must be removed at start (it could advertise readiness
// for a dead process), and the ready-file must not outlive the process — it is
// retracted on the clean signal-teardown exit.
func TestOrchestratorStaleReadyFileRemovedAndRetracted(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)
	readyFile := filepath.Join(t.TempDir(), "ready")

	// Plant a stale ready-file from a notional previous run.
	if err := os.WriteFile(readyFile, []byte("stale"), 0o644); err != nil {
		t.Fatalf("plant stale ready-file: %v", err)
	}

	cfg := &mountcfg.Config{Mounts: []mountcfg.Mount{writableEntry("/mnt/w")}}
	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyFile},
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	// run removes the stale file at start and recreates an EMPTY one only after
	// the mount is up. Poll until the file holds the fresh (empty) content rather
	// than the planted "stale" bytes — proving the stale file was removed, not
	// merely reopened.
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, err := os.ReadFile(readyFile)
		if err == nil && string(b) != "stale" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ready-file never lost its stale content (last=%q, err %v); want it removed and freshly created", string(b), err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	sig <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v; want nil on clean signal teardown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after signal")
	}

	// The process is shutting down: the ready-file must be retracted, never left
	// advertising readiness for a dead process.
	if _, statErr := os.Stat(readyFile); !os.IsNotExist(statErr) {
		t.Errorf("ready-file survives teardown; want it retracted on exit")
	}
}

// TestOrchestratorDuplicateDestinationHardError is the ME-02 regression: a
// destination repeated across mounts/readonly_mounts must be a hard error before
// any point starts, not a silent shadow.
func TestOrchestratorDuplicateDestinationHardError(t *testing.T) {
	fake := newFake()
	cfg := &mountcfg.Config{
		Mounts:         []mountcfg.Mount{writableEntry("/mnt/dup")},
		ReadonlyMounts: []mountcfg.Mount{readonlyEntry("/mnt/dup")},
	}
	o := &orchestrator{
		seam:             fake,
		signals:          make(chan os.Signal, 1),
		brokerSocketPath: "/run/x.sock",
	}
	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil; want a hard error for a duplicate destination")
	}
	if !strings.Contains(err.Error(), "/mnt/dup") {
		t.Errorf("error %q does not name the duplicate destination", err.Error())
	}
	if fake.mountCount() != 0 {
		t.Errorf("mountCount = %d; want 0 (rejected before any point started)", fake.mountCount())
	}
}

// waitForFile polls until path exists or the test times out.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("file %q never appeared", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
