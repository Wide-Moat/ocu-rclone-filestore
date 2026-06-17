// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mounter is the seam between the loaded guest mount config and the
// live VFS mounts it drives.
//
// The orchestration policy — fan-out, fail-fast with best-effort cleanup,
// readiness-once, signal teardown — depends only on the unexported pointMounter
// seam and is fully unit-tested over a fake. The production seam builds the
// ocufs Fs, hands it to a mountlib.MountPoint, starts the live mount and bridges
// its lifecycle; it is build-tagged to the platforms the kernel mount method
// supports and fails closed elsewhere.
package mounter

import (
	"context"
	"errors"
	"os"

	// Anchor the pinned rclone module as a direct dependency. The core fs
	// package carries no backend registration on its own; the production mount
	// wiring lives in the build-tagged realpoint.go. This blank import keeps
	// rclone in the module graph as a direct, exact-tag dependency.
	_ "github.com/rclone/rclone/fs"

	// Register the ocufs backend so its NewFs is reachable through the
	// configmap the seam builds. This is the sole new Fs edge; the seam builds
	// no other Fs and opens no second transport.
	_ "github.com/Wide-Moat/ocu-rclone-filestore/backend/ocufs"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// errMountMethodUnavailable is the typed fail-closed error returned by the
// production seam constructor when the kernel mount method is unavailable —
// either the mount2 registry lookup returned nil on a supported platform, or
// the build landed on an unsupported platform/arch. The session surfaces it so
// main exits non-zero; the mount is never silently skipped (MNT-02).
var errMountMethodUnavailable = errors.New("mounter: mount method unavailable: cannot mount on this platform/arch")

// Mounter binds a validated guest mount config to the live VFS mounts it
// describes. The single method takes the loaded config so the seam is typed end
// to end.
type Mounter interface {
	// Mount realizes every entry in cfg as a live mount and blocks until the
	// mounts are torn down, returning the terminal error (nil on clean
	// shutdown).
	Mount(cfg *mountcfg.Config) error
}

// orchestratorMounter realizes a config by running the orchestrator over a
// production pointMounter seam constructed lazily inside Mount.
type orchestratorMounter struct {
	// newSeam constructs the production pointMounter, built lazily inside Mount.
	newSeam func() (pointMounter, error)
	// readiness carries the optional ready-file path (flag/env).
	readiness ReadinessConfig
	// signals is the termination-signal channel the entrypoint installs. When
	// nil, Mount installs a default SIGTERM/SIGINT channel.
	signals <-chan os.Signal
}

// Mount runs the orchestrator over the lazily constructed production seam. The
// transport values (service_url + ca_cert_pem) are read from the validated
// config and threaded onto the orchestrator; the per-mount auth_token rides on
// each mount.
func (m orchestratorMounter) Mount(cfg *mountcfg.Config) error {
	o := &orchestrator{
		newSeam:    m.newSeam,
		readiness:  m.readiness,
		signals:    m.signals,
		serviceURL: cfg.ServiceURL,
		caCertPEM:  cfg.CACertPEM,
	}
	return o.run(context.Background(), cfg)
}

// Option configures the mounter returned by New.
type Option func(*orchestratorMounter)

// WithReadiness sets the readiness configuration (the ready-file path sourced
// from a flag/env by the entrypoint).
func WithReadiness(rc ReadinessConfig) Option {
	return func(m *orchestratorMounter) { m.readiness = rc }
}

// WithSignals installs the termination-signal channel the orchestrator selects
// on for teardown. When unset, the mounter installs a default SIGTERM/SIGINT
// channel.
func WithSignals(sig <-chan os.Signal) Option {
	return func(m *orchestratorMounter) { m.signals = sig }
}

// New returns the orchestrator-backed mounter wired with the production seam
// (the live build-tagged seam on a supported platform, the fail-closed stub
// elsewhere). Functional options thread the readiness config and the signal
// channel from the entrypoint without changing Mount.
func New(opts ...Option) Mounter {
	m := orchestratorMounter{newSeam: defaultRealSeam}
	for _, opt := range opts {
		opt(&m)
	}
	return m
}
