// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"

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
// posture (derived from the mount's readonly key), and the top-level transport
// values (service_url + ca_cert_pem) the seam threads into the ocufs configmap.
// The per-mount auth_token rides on mount.AuthToken.
type mountSpec struct {
	mount      mountcfg.Mount
	readOnly   bool
	serviceURL string
	caCertPEM  string
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
// Transport is config-derived: the top-level service_url (loader-checked,
// ^https://) and ca_cert_pem from the validated config thread to each spec; the
// per-mount auth_token comes from the mount. There is no runtime socket input.
type orchestrator struct {
	// seam is the live pointMounter, constructed lazily by run via newSeam.
	seam pointMounter
	// newSeam constructs the production seam. The fake-driven tests set seam
	// directly and leave this nil.
	newSeam   func() (pointMounter, error)
	readiness ReadinessConfig
	signals   <-chan os.Signal
	// serviceURL and caCertPEM are the top-level transport values from the
	// validated config (service_url ^https://, ca_cert_pem non-empty). They are
	// constant across mounts and thread onto each spec so realpoint's configmap
	// build is self-contained.
	serviceURL string
	caCertPEM  string
}

// run realizes every mount in cfg and blocks until teardown.
//
// It builds the ordered specs (one per mount, RW/RO from each mount's readonly
// key), rejects any memory-store spec as a hard error before starting anything,
// starts each spec sequentially for deterministic error attribution,
// best-effort-unmounts already-started points on the first start error and
// returns an aggregated error naming the failed destination, signals readiness
// exactly once after all are up, then blocks on the signal channel and the
// per-point exits. On a signal it unmounts all points and returns nil; on a
// spontaneous point error it unmounts the rest and returns that error.
func (o *orchestrator) run(ctx context.Context, cfg *mountcfg.Config) error {
	// Construct the production seam. The fake-driven tests inject o.seam
	// directly and leave o.newSeam nil.
	if o.seam == nil {
		if o.newSeam == nil {
			return errors.New("orchestrator: no mount seam configured")
		}
		seam, err := o.newSeam()
		if err != nil {
			return err
		}
		o.seam = seam
	}

	// Install a default termination-signal channel when the entrypoint did not
	// inject one. The fake-driven tests always inject their own.
	if o.signals == nil {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(sig)
		o.signals = sig
	}

	// Ready-file hygiene (ME-01): remove any pre-existing file at the START so a
	// stale file from a previous dead process never advertises "ready" for this
	// run, and register a retraction so the file never outlives the process. The
	// retraction runs on EVERY exit from run (error, signal teardown, spontaneous
	// exit); signalReady creates the file only on the all-up path, so the net
	// effect is: the ready-file exists only while every mount is actually up.
	if o.readiness.ReadyFilePath != "" {
		if err := os.Remove(o.readiness.ReadyFilePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale ready-file %q: %w", o.readiness.ReadyFilePath, err)
		}
		defer func() {
			if err := os.Remove(o.readiness.ReadyFilePath); err != nil && !os.IsNotExist(err) {
				slog.Warn("retract ready-file", "path", o.readiness.ReadyFilePath, "err", err)
			}
		}()
	}

	specs, err := o.buildSpecs(cfg)
	if err != nil {
		return err
	}

	if len(specs) == 0 {
		slog.Info("no mounts configured")
		return nil
	}

	// Derive a cancelable context for the fan-out so a termination signal
	// arriving mid-mount aborts an in-flight mountAndWaitReady (its ctx is
	// threaded into NewFs and the readiness poll) rather than letting it block
	// up to readyTimeout. We cancel it on every exit from this scope; the
	// pending-signal path also cancels explicitly before tearing down.
	mountCtx, cancelMount := context.WithCancel(ctx)
	defer cancelMount()

	started := make([]point, 0, len(specs))
	for _, spec := range specs {
		// A SIGTERM/SIGINT arriving during the sequential fan-out (each mount
		// can block up to readyTimeout, serialized over N specs) must not be
		// ignored until the loop finishes. Poll before each mount: on a pending
		// signal, cancel the fan-out, best-effort-unmount what is up, and return
		// cleanly WITHOUT creating the ready-file (no readiness after a
		// termination request — SC3 ordering).
		if o.signalPending() {
			cancelMount()
			return o.shutdownDuringStartup(started)
		}

		p, err := o.seam.mountAndWaitReady(mountCtx, spec)
		if err != nil {
			// Fail fast: best-effort-unmount everything already started and
			// return a single aggregated error naming the failed destination.
			startErr := fmt.Errorf("mount %q: %w", spec.mount.Destination, err)
			cleanupErrs := o.unmountAll(started)
			return errors.Join(append([]error{startErr}, cleanupErrs...)...)
		}
		started = append(started, p)
	}

	// Re-check immediately before signalling readiness: a signal that arrived
	// after the last mount completed but before this point must still suppress
	// the ready-file (readiness must never appear after termination requested).
	if o.signalPending() {
		cancelMount()
		return o.shutdownDuringStartup(started)
	}

	// Every point is ready: signal readiness exactly once, on the all-up path.
	if err := o.signalReady(len(started)); err != nil {
		// A readiness-signal failure is terminal: tear down and surface it.
		cleanupErrs := o.unmountAll(started)
		return errors.Join(append([]error{err}, cleanupErrs...)...)
	}

	return o.blockUntilTeardown(started)
}

// signalPending reports whether a termination signal is already waiting on the
// signal channel, consuming it if so. It never blocks. A consumed signal is the
// orchestrator's cue to abort startup; because the pending-signal path returns
// before blockUntilTeardown, consuming here does not race that later select.
func (o *orchestrator) signalPending() bool {
	select {
	case <-o.signals:
		return true
	default:
		return false
	}
}

// shutdownDuringStartup handles a termination signal observed mid-fan-out: it
// best-effort-unmounts every already-started point and returns a clean (nil on
// success) result, matching blockUntilTeardown's signal path. The ready-file is
// never created on this path, so readiness is never advertised after a
// termination request.
func (o *orchestrator) shutdownDuringStartup(started []point) error {
	cleanupErrs := o.unmountAll(started)
	return errors.Join(cleanupErrs...)
}

// buildSpecs makes one spec per mount, deriving RW/RO from each mount's
// readonly key, and stamps each with the top-level transport values
// (service_url + ca_cert_pem); the per-mount auth_token rides on the mount. A
// memory-store mount is a hard error here, before any point is started, so it is
// never silently skipped. A destination that repeats across the mounts array is
// likewise a hard error (ME-02): two specs targeting the same path would have
// the second silently shadow the first, violating the never-silently-
// mis-mounted discipline.
func (o *orchestrator) buildSpecs(cfg *mountcfg.Config) ([]mountSpec, error) {
	specs := make([]mountSpec, 0, len(cfg.Mounts))
	seen := make(map[string]struct{}, cap(specs))
	for _, m := range cfg.Mounts {
		readOnly := m.Readonly != nil && *m.Readonly
		if m.MemoryStoreID != nil {
			return nil, fmt.Errorf("mount %q: memory-store mounts are not yet supported (no memory scope axis)", m.Destination)
		}
		// Key the seen-set on the CLEANED destination so normalization-
		// equivalent paths (e.g. "/mnt/data" and "/mnt/data/") collide here
		// rather than slipping past both this check (distinct raw keys) and the
		// nesting check below (identical cleaned paths are neither ancestor nor
		// descendant of each other), which would let two mounts land on the same
		// effective destination — the silent shadowing this check exists to stop.
		cleaned := filepath.Clean(m.Destination)
		if _, dup := seen[cleaned]; dup {
			return nil, fmt.Errorf("mount %q: duplicate destination across mounts (a second mount would silently shadow the first)", m.Destination)
		}
		// Ancestor/descendant destination pairs are rejected so the pre-mount
		// shadow guard never walks a LIVE earlier mount: a destination nested
		// under a mounted point would make the later guard's walk read broker
		// content and refuse bringup on any real session file. Checked on the
		// cleaned paths at a separator boundary, both directions.
		for prior := range seen {
			if strings.HasPrefix(cleaned, prior+string(filepath.Separator)) || strings.HasPrefix(prior, cleaned+string(filepath.Separator)) {
				return nil, fmt.Errorf("mount %q: destination is nested with %q (the later mount's pre-mount inspection would traverse the earlier live mount)", m.Destination, prior)
			}
		}
		seen[cleaned] = struct{}{}
		specs = append(specs, mountSpec{mount: m, readOnly: readOnly, serviceURL: o.serviceURL, caCertPEM: o.caCertPEM})
	}
	return specs, nil
}

// signalReady fires the readiness signal exactly once: it creates the ready-file
// when a path is configured, otherwise logs a single readiness line. The file is
// truncated on create so it is always fresh and content-free — a pure presence
// signal that never carries leftover bytes (run also removes any stale file at
// start, ME-01).
func (o *orchestrator) signalReady(n int) error {
	if o.readiness.ReadyFilePath != "" {
		// The ready-file is a content-free presence signal the host watches to
		// learn that every mount is live; the host process may observe it under
		// a different uid, so it is deliberately world-readable. It carries no
		// secret (it is created empty and truncated on every create).
		f, err := os.OpenFile(o.readiness.ReadyFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // G302: empty host-observed readiness signal, intentionally world-readable
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
//
// Points drain CONCURRENTLY: each unmount can block up to
// writebackDrainTimeout + unmountDetachGrace (the write-back drain plus the
// bounded kernel detach), so walking N points sequentially would stack those
// budgets to N x 123s — past the 150s stop_grace_period both shipped compose
// services pin — and the runtime would SIGKILL the process mid-drain,
// discarding the later mounts' write-back queues. Concurrent drain bounds
// whole-teardown cost at the MAX over points. The points are independent (one
// VFS and one FUSE server each; overlapping drain uploads are the same
// concurrency steady-state write-back already exercises), and each realPoint
// serializes its own doUnmount via unmountOnce, so the fan-out is safe by
// construction. Errors are collected per point and compacted in the points'
// index order, keeping the aggregated output deterministic and identical to
// the sequential form's.
func (o *orchestrator) unmountAll(points []point) []error {
	collected := make([]error, len(points))
	var wg sync.WaitGroup
	for i, p := range points {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := o.seam.unmount(p); err != nil {
				collected[i] = fmt.Errorf("unmount %q: %w", p.destination(), err)
			}
		}()
	}
	wg.Wait()

	var errs []error
	for _, err := range collected {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
