// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// point is an opaque handle to one live mount. The orchestrator treats it as a
// passive reference: it can ask the destination it serves and select on its
// terminal exit. The seam owns the concrete type; the orchestrator never
// constructs one.
type point interface {
	// destination is the mount path this point serves, used for error
	// attribution.
	destination() string
	// wait blocks until the point exits on its own and returns its terminal
	// error (nil on a clean exit). The orchestrator selects on this so a point
	// that dies spontaneously surfaces as a non-nil run error.
	wait() error
}

// mountSpec is one ordered unit of work: the config mount, its read-only
// posture (derived from which array it came from), and the broker socket path
// the seam threads into the ocufs configmap.
type mountSpec struct {
	mount      mountcfg.Mount
	readOnly   bool
	socketPath string
}

// pointMounter is the testability fulcrum. The orchestration depends ONLY on
// these two operations, so fan-out, fail-fast aggregation, readiness ordering,
// and signal teardown are all provable with a fake that records calls and can
// fail the Nth start, with no real kernel mount. The production implementation that builds
// the ocufs Fs, the VFS and the live mount lands in a later wave.
type pointMounter interface {
	// mountAndWaitReady builds the mount for spec, starts it, and confirms this
	// point is ready, returning a handle the orchestrator can later unmount, or
	// a non-nil error if start/ready failed.
	mountAndWaitReady(ctx context.Context, spec mountSpec) (point, error)
	// unmount best-effort unmounts one point.
	unmount(p point) error
}

// ReadinessConfig carries the optional ready-file path. It is populated from a
// flag/env by the entrypoint, NEVER from the frozen config schema. When
// ReadyFilePath is empty the orchestrator logs a single readiness line instead.
type ReadinessConfig struct {
	ReadyFilePath string
}

// orchestrator fans out N mounts over the pointMounter seam, fails fast with
// best-effort cleanup, signals readiness exactly once after all are up, and
// tears down every point on a termination signal.
//
// The broker socket path is an explicit runtime input (a flag/env supplied by
// the entrypoint), NOT derived from the frozen service_url: the loader forbids
// non-https service_urls, so the per-session socket path cannot come from the
// validated config (D2). An empty value is a hard error before any mount.
type orchestrator struct {
	seam             pointMounter
	readiness        ReadinessConfig
	signals          <-chan os.Signal
	brokerSocketPath string
}

// run realizes every mount in cfg and blocks until teardown.
//
// It rejects an empty broker socket path up front, builds the ordered specs
// (writable mounts then read-only mounts), rejects any memory-store spec as a
// hard error before starting anything, starts each spec sequentially for
// deterministic error attribution, best-effort-unmounts already-started points
// on the first start error and returns an aggregated error naming the failed
// destination, signals readiness exactly once after all are up, then blocks on
// the signal channel and the per-point exits. On a signal it unmounts all
// points and returns nil; on a spontaneous point error it unmounts the rest and
// returns that error.
func (o *orchestrator) run(ctx context.Context, cfg *mountcfg.Config) error {
	if o.brokerSocketPath == "" {
		return errors.New("broker socket path not provided: the per-session socket path is a runtime input (D2), not the frozen service_url")
	}

	specs, err := o.buildSpecs(cfg)
	if err != nil {
		return err
	}

	if len(specs) == 0 {
		slog.Info("no mounts configured")
		return nil
	}

	started := make([]point, 0, len(specs))
	for _, spec := range specs {
		p, err := o.seam.mountAndWaitReady(ctx, spec)
		if err != nil {
			// Fail fast: best-effort-unmount everything already started and
			// return a single aggregated error naming the failed destination.
			startErr := fmt.Errorf("mount %q: %w", spec.mount.Destination, err)
			cleanupErrs := o.unmountAll(started)
			return errors.Join(append([]error{startErr}, cleanupErrs...)...)
		}
		started = append(started, p)
	}

	// Every point is ready: signal readiness exactly once, on the all-up path.
	if err := o.signalReady(len(started)); err != nil {
		// A readiness-signal failure is terminal: tear down and surface it.
		cleanupErrs := o.unmountAll(started)
		return errors.Join(append([]error{err}, cleanupErrs...)...)
	}

	return o.blockUntilTeardown(started)
}

// buildSpecs orders the writable mounts before the read-only mounts and stamps
// each with the broker socket path. A memory-store mount is a hard error here,
// before any point is started, so it is never silently skipped.
func (o *orchestrator) buildSpecs(cfg *mountcfg.Config) ([]mountSpec, error) {
	specs := make([]mountSpec, 0, len(cfg.Mounts)+len(cfg.ReadonlyMounts))
	add := func(mounts []mountcfg.Mount, readOnly bool) error {
		for _, m := range mounts {
			if m.MemoryStoreID != nil {
				return fmt.Errorf("mount %q: memory-store mounts are not yet supported (no memory scope axis)", m.Destination)
			}
			specs = append(specs, mountSpec{mount: m, readOnly: readOnly, socketPath: o.brokerSocketPath})
		}
		return nil
	}
	if err := add(cfg.Mounts, false); err != nil {
		return nil, err
	}
	if err := add(cfg.ReadonlyMounts, true); err != nil {
		return nil, err
	}
	return specs, nil
}

// signalReady fires the readiness signal exactly once: it creates the ready-file
// when a path is configured, otherwise logs a single readiness line.
func (o *orchestrator) signalReady(n int) error {
	if o.readiness.ReadyFilePath != "" {
		f, err := os.OpenFile(o.readiness.ReadyFilePath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("create ready-file %q: %w", o.readiness.ReadyFilePath, err)
		}
		return f.Close()
	}
	slog.Info("all mounts ready", "count", n)
	return nil
}

// blockUntilTeardown waits for either a termination signal or a spontaneous
// point exit. On a signal it unmounts all points and returns nil (clean
// shutdown). On a spontaneous point error it unmounts the rest and returns that
// error.
func (o *orchestrator) blockUntilTeardown(started []point) error {
	// Build a reflect.Select over the signal channel plus every point's wait().
	cases := make([]reflect.SelectCase, 0, len(started)+1)
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(o.signals),
	})
	// Each point's wait() is run in a goroutine that feeds a one-shot channel,
	// so the select observes a spontaneous exit.
	waitChans := make([]chan error, len(started))
	for i, p := range started {
		ch := make(chan error, 1)
		waitChans[i] = ch
		go func(pt point, c chan error) { c <- pt.wait() }(p, ch)
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		})
	}

	chosen, recv, _ := reflect.Select(cases)
	if chosen == 0 {
		// Termination signal: best-effort-unmount all, clean return.
		cleanupErrs := o.unmountAll(started)
		return errors.Join(cleanupErrs...)
	}

	// A point exited on its own. Unmount the rest and surface its error.
	exited := started[chosen-1]
	remaining := make([]point, 0, len(started)-1)
	for _, p := range started {
		if p != exited {
			remaining = append(remaining, p)
		}
	}
	cleanupErrs := o.unmountAll(remaining)

	var pointErr error
	if e, ok := recv.Interface().(error); ok {
		pointErr = e
	}
	if pointErr == nil {
		// A clean spontaneous exit still ends the process; aggregate any
		// cleanup errors.
		return errors.Join(cleanupErrs...)
	}
	return errors.Join(append([]error{fmt.Errorf("mount %q exited: %w", exited.destination(), pointErr)}, cleanupErrs...)...)
}

// unmountAll best-effort-unmounts every point and collects the errors.
func (o *orchestrator) unmountAll(points []point) []error {
	var errs []error
	for _, p := range points {
		if err := o.seam.unmount(p); err != nil {
			errs = append(errs, fmt.Errorf("unmount %q: %w", p.destination(), err))
		}
	}
	return errs
}
