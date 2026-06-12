// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mounter is the seam between the loaded guest mount config and the
// VFS mount it will eventually drive.
//
// This package declares the interface and a not-implemented sentinel only. The
// concrete mount that binds a [mountcfg.Config] to a live VFS is built in a
// later phase; until then the no-op implementation returns [ErrNotImplemented]
// so every call site fails closed on an explicit, matchable error.
package mounter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	// Anchor the pinned rclone module as a direct dependency without
	// registering a backend or invoking any mount path. The core fs package
	// carries no backend registration on its own; the real mount wiring lands
	// in a later phase. This blank import keeps rclone in the module graph as a
	// direct, exact-tag dependency rather than a prunable indirect one.
	_ "github.com/rclone/rclone/fs"

	// Register the ocufs backend so its NewFs is reachable through the
	// configmap the orchestrator builds. This is the sole new dependency edge;
	// the orchestrator builds no other Fs and opens no second transport.
	_ "github.com/Wide-Moat/ocu-rclone-filestore/backend/ocufs"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// ErrNotImplemented is returned by the seam until the real mount lands. Call
// sites match it with errors.Is so the not-implemented path stays distinct from
// any future operational error.
var ErrNotImplemented = errors.New("mounter: not implemented")

// Mounter binds a validated guest mount config to the VFS mounts it describes.
// The single method takes the loaded config so the seam is typed end to end.
type Mounter interface {
	// Mount realizes every entry in cfg as a live mount and blocks until the
	// mounts are torn down, returning the terminal error (nil on clean
	// shutdown). The current implementation is a seam returning
	// ErrNotImplemented.
	Mount(cfg *mountcfg.Config) error
}

// orchestratorMounter realizes a config by running the orchestrator over a
// production pointMounter seam. The orchestration policy (fan-out, fail-fast,
// readiness, signal teardown) is wave-1 complete and fully unit-tested over a
// fake seam; the production seam body that builds the live ocufs-backed mounts
// lands in a later wave.
type orchestratorMounter struct {
	// newSeam constructs the production pointMounter. In wave 1 it returns the
	// not-implemented stub so callers fail closed on a matchable error; a later
	// wave swaps in the live, build-tagged seam.
	newSeam func() (pointMounter, error)
	// brokerSocketPath is the per-session socket path, an explicit runtime
	// input (flag/env) supplied by the entrypoint. The wave-1 stub path never
	// reaches the orchestrator's socket check.
	brokerSocketPath string
	// readiness carries the optional ready-file path (flag/env).
	readiness ReadinessConfig
}

// Mount constructs the production seam and runs the orchestrator. In wave 1 the
// seam constructor returns an error satisfying errors.Is(_, ErrNotImplemented),
// so every Mount on a valid config fails closed on that matchable sentinel
// until the live seam lands.
func (m orchestratorMounter) Mount(cfg *mountcfg.Config) error {
	seam, err := m.newSeam()
	if err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)

	o := &orchestrator{
		seam:             seam,
		readiness:        m.readiness,
		signals:          sig,
		brokerSocketPath: m.brokerSocketPath,
	}
	return o.run(context.Background(), cfg)
}

// notImplementedSeam is the wave-1 production seam stub. Its constructor returns
// an error wrapping ErrNotImplemented so the orchestrator never starts and the
// entrypoint fails closed on the matchable sentinel.
func notImplementedSeam() (pointMounter, error) {
	return nil, fmt.Errorf("mounter: live mount seam not yet wired: %w", ErrNotImplemented)
}

// New returns the orchestrator-backed mounter wired with the wave-1 stub seam.
// It exists so the entrypoint depends on a constructor rather than a concrete
// type and need not change when the live seam replaces the stub.
func New() Mounter {
	return orchestratorMounter{newSeam: notImplementedSeam}
}
