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
	// newSeam constructs the production pointMounter. It is built lazily inside
	// Mount so the orchestrator's empty-broker-socket check fires BEFORE seam
	// construction — on an empty socket the socket hard error wins regardless of
	// platform, including where the unsupported-platform constructor would
	// itself error.
	newSeam func() (pointMounter, error)
	// brokerSocketPath is the per-session socket path, an explicit runtime input
	// (flag/env) supplied by the entrypoint.
	brokerSocketPath string
	// brokerSocketDirPath is the per-session socket DIRECTORY alternative:
	// each mount derives <dir>/<filesystem_id>.sock, matching the broker's
	// one-socket-per-filesystem provisioning. Exactly one of the two socket
	// inputs may be set; the orchestrator enforces the exclusivity.
	brokerSocketDirPath string
	// readiness carries the optional ready-file path (flag/env).
	readiness ReadinessConfig
	// signals is the termination-signal channel the entrypoint installs. When
	// nil, Mount installs a default SIGTERM/SIGINT channel.
	signals <-chan os.Signal
}

// Mount runs the orchestrator over the lazily constructed production seam. The
// orchestrator rejects an empty broker socket path before the seam is built, so
// that hard error wins over an unsupported-platform seam error.
func (m orchestratorMounter) Mount(cfg *mountcfg.Config) error {
	o := &orchestrator{
		newSeam:             m.newSeam,
		readiness:           m.readiness,
		signals:             m.signals,
		brokerSocketPath:    m.brokerSocketPath,
		brokerSocketDirPath: m.brokerSocketDirPath,
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

// WithBrokerSocket sets the per-session broker socket path, an explicit runtime
// input sourced from a flag/env. An empty value makes the orchestrator hard-fail
// before any mount.
func WithBrokerSocket(path string) Option {
	return func(m *orchestratorMounter) { m.brokerSocketPath = path }
}

// WithBrokerSocketDir sets the per-session broker socket DIRECTORY, an explicit
// runtime input sourced from a flag/env. Each mount derives its own socket path
// as <dir>/<filesystem_id>.sock, matching the broker's one-session-socket-per-
// filesystem provisioning, so a multi-filesystem config dials one broker
// instance per scope. Mutually exclusive with WithBrokerSocket; setting both
// makes the orchestrator hard-fail before any mount.
func WithBrokerSocketDir(dir string) Option {
	return func(m *orchestratorMounter) { m.brokerSocketDirPath = dir }
}

// WithSignals installs the termination-signal channel the orchestrator selects
// on for teardown. When unset, the mounter installs a default SIGTERM/SIGINT
// channel.
func WithSignals(sig <-chan os.Signal) Option {
	return func(m *orchestratorMounter) { m.signals = sig }
}

// New returns the orchestrator-backed mounter wired with the production seam
// (the live build-tagged seam on a supported platform, the fail-closed stub
// elsewhere). Functional options thread the readiness config, the broker socket
// path, and the signal channel from the entrypoint without changing Mount.
func New(opts ...Option) Mounter {
	m := orchestratorMounter{newSeam: defaultRealSeam}
	for _, opt := range opts {
		opt(&m)
	}
	return m
}

// AppliedSockets applies the given functional options to a fresh mounter and
// reports the resolved broker socket inputs: the single per-session socket
// (WithBrokerSocket) and the per-session socket directory (WithBrokerSocketDir).
//
// It exists so the entrypoint's option-assembly adapter is assertable across the
// package boundary — that the resolved single-socket value reaches the socket
// field and the directory value reaches the directory field, neither dropped nor
// transposed — without constructing a live mount. It applies the options exactly
// as New does and reads back only the two socket fields; it has no production
// caller.
func AppliedSockets(opts ...Option) (brokerSocket, brokerSocketDir string) {
	var m orchestratorMounter
	for _, opt := range opts {
		opt(&m)
	}
	return m.brokerSocketPath, m.brokerSocketDirPath
}
