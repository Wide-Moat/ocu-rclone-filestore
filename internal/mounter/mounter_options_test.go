// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// TestNewAppliesFunctionalOptions asserts each functional option threads its
// value onto the constructed mounter. New returns the Mounter interface, so we
// type-assert back to the concrete orchestratorMounter (same-package access) and
// inspect the fields the options set. This proves WithReadiness and WithSignals
// are wired, not merely defined.
func TestNewAppliesFunctionalOptions(t *testing.T) {
	rc := ReadinessConfig{ReadyFilePath: "/run/ocufs.ready"}
	sig := make(chan os.Signal, 1)

	m := New(
		WithReadiness(rc),
		WithSignals(sig),
	)

	om, ok := m.(orchestratorMounter)
	if !ok {
		t.Fatalf("New returned %T; want orchestratorMounter", m)
	}
	if om.readiness != rc {
		t.Errorf("readiness = %+v; want %+v (WithReadiness not applied)", om.readiness, rc)
	}
	if om.signals == nil {
		t.Error("signals = nil; want the injected channel (WithSignals not applied)")
	}
	// The default seam is always wired by New regardless of options.
	if om.newSeam == nil {
		t.Error("newSeam = nil; want the default production seam constructor")
	}
}

// TestNewNoOptionsLeavesZeroValues asserts that with no options the constructed
// mounter carries a nil signal channel, so Mount installs the default signal
// handling, and the zero ReadinessConfig.
func TestNewNoOptionsLeavesZeroValues(t *testing.T) {
	om, ok := New().(orchestratorMounter)
	if !ok {
		t.Fatal("New() did not return orchestratorMounter")
	}
	if om.signals != nil {
		t.Error("signals != nil; want nil so Mount installs the default channel")
	}
	if (om.readiness != ReadinessConfig{}) {
		t.Errorf("readiness = %+v; want the zero ReadinessConfig", om.readiness)
	}
}

// TestWithSignalsChannelDrivesTeardown proves WithSignals is not merely stored
// but is the channel the orchestrator actually selects on for teardown. We
// build a mounter whose seam is a fake, inject our own signal channel via
// WithSignals, run Mount in a goroutine, and confirm sending on THAT channel
// tears the mounts down cleanly. Mount reaches the orchestrator because the
// broker socket is supplied; the fake seam keeps the test off any real mount.
func TestWithSignalsChannelDrivesTeardown(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)

	m := New(
		WithSignals(sig),
	).(orchestratorMounter)
	// Swap the production seam for the recording fake so Mount drives the
	// orchestration policy without touching the kernel mount method.
	m.newSeam = func() (pointMounter, error) { return fake, nil }

	cfg := &mountcfg.Config{
		ServiceURL: "https://broker.example",
		CACertPEM:  "pem",
		Mounts:     []mountcfg.Mount{writableEntry("/mnt/w")},
	}

	done := make(chan error, 1)
	go func() { done <- m.Mount(cfg) }()

	// Wait until the single mount is up, then signal teardown on the injected
	// channel. If WithSignals were ignored the orchestrator would install its
	// own default channel and never observe this send.
	deadline := time.Now().Add(2 * time.Second)
	for fake.mountCount() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("mount never started via New(...).Mount")
		}
		time.Sleep(5 * time.Millisecond)
	}

	sig <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Mount = %v; want nil on clean teardown via the injected signal channel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Mount did not return after a signal on the WithSignals channel")
	}
	if fake.unmountCount() != 1 {
		t.Errorf("unmountCount = %d; want 1 (the one point torn down on signal)", fake.unmountCount())
	}
}

// TestWithReadinessFileCreatedThroughNew proves WithReadiness is honoured by the
// full New(...).Mount path: the configured ready-file appears once every mount
// is up and is retracted on teardown.
func TestWithReadinessFileCreatedThroughNew(t *testing.T) {
	fake := newFake()
	sig := make(chan os.Signal, 1)
	readyFile := tmpReadyPath(t)

	m := New(
		WithReadiness(ReadinessConfig{ReadyFilePath: readyFile}),
		WithSignals(sig),
	).(orchestratorMounter)
	m.newSeam = func() (pointMounter, error) { return fake, nil }

	cfg := &mountcfg.Config{
		ServiceURL: "https://broker.example",
		CACertPEM:  "pem",
		Mounts:     []mountcfg.Mount{writableEntry("/mnt/w")},
	}

	done := make(chan error, 1)
	go func() { done <- m.Mount(cfg) }()

	waitForFile(t, readyFile)

	sig <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Mount = %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Mount did not return after signal")
	}
	if _, statErr := os.Stat(readyFile); !os.IsNotExist(statErr) {
		t.Error("ready-file survived teardown; WithReadiness path must retract it on exit")
	}
}

// TestMountSeamConstructorErrorSurfaces covers the run path where newSeam returns
// an error: with the socket supplied (so the socket check passes) but the seam
// constructor failing, run surfaces the constructor error verbatim. Driving it
// through New(...).Mount exercises the orchestratorMounter.Mount -> run wiring.
func TestMountSeamConstructorErrorSurfaces(t *testing.T) {
	wantErr := errors.New("seam build failed")
	m := New().(orchestratorMounter)
	m.newSeam = func() (pointMounter, error) { return nil, wantErr }

	err := m.Mount(&mountcfg.Config{
		ServiceURL: "https://broker.example",
		CACertPEM:  "pem",
		Mounts:     []mountcfg.Mount{writableEntry("/mnt/w")},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Mount = %v; want the seam constructor error surfaced", err)
	}
}

// tmpReadyPath returns a ready-file path inside a fresh temp dir.
func tmpReadyPath(t *testing.T) string {
	t.Helper()
	return strings.TrimRight(t.TempDir(), "/") + "/ready"
}
