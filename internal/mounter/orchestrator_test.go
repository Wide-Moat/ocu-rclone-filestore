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

	mountCalls   []string    // destinations passed to mountAndWaitReady, in order
	mountSpecs   []mountSpec // full specs passed to mountAndWaitReady, in order
	unmountCalls []string    // destinations passed to unmount, in order
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
	f.mountSpecs = append(f.mountSpecs, spec)
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

// socketPathByDest returns the socket path each started spec carried, keyed by
// destination, so the per-mount socket derivation is assertable.
func (f *fakePointMounter) socketPathByDest() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.mountSpecs))
	for _, s := range f.mountSpecs {
		out[s.mount.Destination] = s.socketPath
	}
	return out
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

// TestOrchestratorSocketDirDerivesPerMountSocket asserts the socket-dir mode:
// with brokerSocketDirPath set, every spec derives its own socket path as
// <dir>/<filesystem_id>.sock — the broker provisions exactly one session socket
// per filesystem scope under that directory, so a multi-filesystem config dials
// one broker instance per scope instead of forcing one per-process socket onto
// every mount.
func TestOrchestratorSocketDirDerivesPerMountSocket(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)

	rw := writableEntry("/mnt/w")
	rw.FilesystemID = ptrStr("fsrw")
	ro := readonlyEntry("/mnt/r")
	ro.FilesystemID = ptrStr("fsro")
	cfg := &mountcfg.Config{
		Mounts:         []mountcfg.Mount{rw},
		ReadonlyMounts: []mountcfg.Mount{ro},
	}

	o := &orchestrator{
		seam:                fake,
		signals:             sig,
		brokerSocketDirPath: "/run/sockets",
	}

	done := make(chan error, 1)
	go func() { done <- o.run(context.Background(), cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for fake.mountCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d mounts started; want 2", fake.mountCount())
		}
		time.Sleep(5 * time.Millisecond)
	}

	want := map[string]string{
		"/mnt/w": filepath.Join("/run/sockets", "fsrw.sock"),
		"/mnt/r": filepath.Join("/run/sockets", "fsro.sock"),
	}
	got := fake.socketPathByDest()
	for dest, wantSock := range want {
		if got[dest] != wantSock {
			t.Errorf("socket for %q = %q; want %q", dest, got[dest], wantSock)
		}
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
}

// TestOrchestratorSocketPathAndDirMutuallyExclusive asserts that supplying BOTH
// the single socket path and the socket directory is a hard error before any
// mount starts: an ambiguous socket input must never silently pick one.
func TestOrchestratorSocketPathAndDirMutuallyExclusive(t *testing.T) {
	fake := newFake()
	cfg := &mountcfg.Config{Mounts: []mountcfg.Mount{writableEntry("/mnt/w")}}
	o := &orchestrator{
		seam:                fake,
		signals:             make(chan os.Signal, 1),
		brokerSocketPath:    "/run/x.sock",
		brokerSocketDirPath: "/run/sockets",
	}
	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil; want a hard error when both socket inputs are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("run error = %q; want the mutual-exclusion hard error", err.Error())
	}
	if fake.mountCount() != 0 {
		t.Errorf("mountCount = %d; want 0 (no spec started)", fake.mountCount())
	}
}

// TestNewMountSocketDirOptionReachesOrchestrator asserts the WithBrokerSocketDir
// option threads through New().Mount: with ONLY the dir set the run proceeds
// past both socket-input checks. The zero-mount config keeps the test off any
// real mount; the only error a platform may surface is the fail-closed seam
// constructor (on an unsupported platform/arch), never a socket-input error.
func TestNewMountSocketDirOptionReachesOrchestrator(t *testing.T) {
	err := New(WithBrokerSocketDir("/run/sockets")).Mount(&mountcfg.Config{
		ServiceURL: "https://broker.example",
		Mounts:     []mountcfg.Mount{},
	})
	if err != nil {
		if strings.Contains(err.Error(), "broker socket path not provided") ||
			strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("New(WithBrokerSocketDir).Mount = %v; the socket check must accept dir-only input", err)
		}
		// Any other error is the platform seam failing closed on an unsupported
		// platform/arch — out of scope for this option-threading assertion.
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

// TestOrchestratorSignalReadyFileError covers the signalReady file-error path:
// when the ready-file path cannot be created, signalReady returns a wrapped
// error and run treats it as terminal — tearing down every started point and
// surfacing the failure. We point ReadyFilePath at a path whose parent directory
// does not exist, so os.OpenFile fails on create. The stale-remove at start
// tolerates the missing path (os.IsNotExist), so the failure surfaces only at
// the signalReady stage, after the single mount is up.
func TestOrchestratorSignalReadyFileError(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)
	// Parent directory does not exist: O_CREATE cannot make the file.
	readyFile := filepath.Join(t.TempDir(), "no-such-dir", "ready")

	cfg := &mountcfg.Config{Mounts: []mountcfg.Mount{writableEntry("/mnt/w")}}
	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyFile},
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil; want a terminal error when the ready-file cannot be created")
	}
	if !strings.Contains(err.Error(), "create ready-file") {
		t.Fatalf("run error = %q; want the wrapped create-ready-file error", err.Error())
	}
	// The mount was started, then torn down when readiness signalling failed.
	if fake.mountCount() != 1 {
		t.Errorf("mountCount = %d; want 1 (the one mount started before signalReady)", fake.mountCount())
	}
	if fake.unmountCount() != 1 {
		t.Errorf("unmountCount = %d; want 1 (the started point torn down on the terminal readiness error)", fake.unmountCount())
	}
}

// TestOrchestratorStaleRemoveError covers the stale-file remove-error path at
// the START of run: when a non-IsNotExist error occurs removing the pre-existing
// ready-file, run returns the wrapped error before any mount starts. We plant a
// NON-EMPTY DIRECTORY at the ready-file path so os.Remove fails with ENOTEMPTY
// (not IsNotExist), driving the error branch.
func TestOrchestratorStaleRemoveError(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)

	// A non-empty directory at the ready-file path: os.Remove returns a
	// non-IsNotExist error (directory not empty), exercising the stale-remove
	// error branch.
	readyDir := filepath.Join(t.TempDir(), "ready")
	if err := os.Mkdir(readyDir, 0o755); err != nil {
		t.Fatalf("plant ready-dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(readyDir, "child"), []byte("x"), 0o644); err != nil {
		t.Fatalf("plant child in ready-dir: %v", err)
	}

	cfg := &mountcfg.Config{Mounts: []mountcfg.Mount{writableEntry("/mnt/w")}}
	o := &orchestrator{
		seam:             fake,
		readiness:        ReadinessConfig{ReadyFilePath: readyDir},
		signals:          sig,
		brokerSocketPath: "/run/x.sock",
	}

	err := o.run(context.Background(), cfg)
	if err == nil {
		t.Fatal("run = nil; want the wrapped stale-remove error")
	}
	if !strings.Contains(err.Error(), "remove stale ready-file") {
		t.Fatalf("run error = %q; want the wrapped remove-stale-ready-file error", err.Error())
	}
	// The stale-remove fails before any mount is attempted.
	if fake.mountCount() != 0 {
		t.Errorf("mountCount = %d; want 0 (stale-remove fails before any mount)", fake.mountCount())
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
