// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/rclone/rclone/lib/atexit"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mounter"
)

// mountFunc realizes a loaded config under the given runtime inputs. run wires
// the production mounter; the table test injects a recording double so the
// flag/env resolution is asserted without a real mount. brokerSocket and
// brokerSocketDir are the two mutually exclusive socket inputs (single
// per-session socket vs per-session socket directory the mounts derive
// <filesystem_id>.sock from); the orchestrator enforces the exclusivity.
type mountFunc func(cfg *mountcfg.Config, rc mounter.ReadinessConfig, brokerSocket, brokerSocketDir string, signals <-chan os.Signal) error

// run parses args, loads the guest mount config from the --config path, sources
// the runtime inputs (ready-file and broker socket, each from a flag with an env
// fallback) and the termination-signal channel, and drives the mounter. It
// returns a non-nil error on every failure path and nil only on a clean
// shutdown. It never calls os.Exit; main maps the returned error to the exit
// code.
func run(args []string, stderr io.Writer) error {
	return runWith(args, stderr, productionMount)
}

// runWith is the testable core: it parses flags, resolves the runtime inputs,
// loads the config, and calls mount. The mount function is injected so the
// table test asserts the resolved ReadinessConfig and broker socket without
// mounting.
//
// run takes its own FlagSet rather than the global one so it can be called
// repeatedly (the table test relies on this).
func runWith(args []string, stderr io.Writer, mount mountFunc) error {
	fs := flag.NewFlagSet("ocu-rclone-filestore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the guest mount config file")
	showVersion := fs.Bool("version", false, "print the version and exit")
	readyFile := fs.String("ready-file", "", "optional path to create once all mounts are ready (env: OCU_READY_FILE)")
	brokerSocket := fs.String("broker-socket", "", "per-session broker socket path supplied at provision (env: OCU_BROKER_SOCKET)")
	brokerSocketDir := fs.String("broker-socket-dir", "", "per-session broker socket directory; each mount dials <dir>/<filesystem_id>.sock (env: OCU_BROKER_SOCKET_DIR; mutually exclusive with --broker-socket)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	// --version prints the build-stamped version and exits cleanly, BEFORE the
	// --config requirement: a version query must not need a config. It writes to
	// stderr (the FlagSet's output) so the one-line stdout/stderr contract stays
	// simple and the value is the same linker-stamped symbol the build sets.
	if *showVersion {
		fmt.Fprintf(stderr, "ocu-rclone-filestore %s\n", version)
		return nil
	}

	if *configPath == "" {
		return errors.New("missing required --config flag: pass the path to the guest mount config")
	}

	// Flag wins over env; an unset flag falls back to the env var. The ready-file
	// and broker socket paths are host-controlled RUNTIME inputs, never fields of
	// the frozen guest mount config schema (D2).
	resolvedReadyFile := resolveFlagOrEnv(*readyFile, "OCU_READY_FILE")
	resolvedBrokerSocket := resolveFlagOrEnv(*brokerSocket, "OCU_BROKER_SOCKET")
	resolvedBrokerSocketDir := resolveFlagOrEnv(*brokerSocketDir, "OCU_BROKER_SOCKET_DIR")

	cfg, err := mountcfg.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// This process owns signal handling: the orchestrator's channel below is
	// the SOLE handler, and the clean-shutdown contract (ordered unmount of
	// every mount, ready-file removal, return nil -> exit 0) depends on it.
	// rclone's atexit package would otherwise install its own SIGTERM/SIGINT
	// handler the first time a mount is waited on and os.Exit(128+sig) past
	// our ordered teardown — exit 143, mounts left up, a stale ready-file on
	// the shared volume. rclone exports IgnoreSignals exactly so an embedding
	// program can claim signal ownership; call it BEFORE any mount starts.
	atexit.IgnoreSignals()

	// Install the real termination-signal channel. The orchestrator selects on
	// it to tear down every live mount on SIGTERM/SIGINT.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)

	rc := mounter.ReadinessConfig{ReadyFilePath: resolvedReadyFile}
	return mount(cfg, rc, resolvedBrokerSocket, resolvedBrokerSocketDir, sig)
}

// resolveFlagOrEnv returns the flag value when set, otherwise the env var. An
// empty result is left to the downstream consumer to reject (the empty broker
// socket is a hard error in the orchestrator).
func resolveFlagOrEnv(flagVal, envKey string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envKey)
}

// newMounter constructs the mounter from the functional options productionMount
// assembles. It is a package-level seam (default: mounter.New) so a test can
// substitute a recording constructor and assert which option lands on which
// mounter field — that the resolved single-socket reaches WithBrokerSocket and
// the socket directory reaches WithBrokerSocketDir, neither dropped nor
// transposed — without driving a real kernel mount.
var newMounter = mounter.New

// productionMount wires the runtime inputs into the functional-options mounter
// and runs it. Mount(cfg) stays unchanged; the entrypoint contract does not
// break.
func productionMount(cfg *mountcfg.Config, rc mounter.ReadinessConfig, brokerSocket, brokerSocketDir string, signals <-chan os.Signal) error {
	return newMounter(
		mounter.WithReadiness(rc),
		mounter.WithBrokerSocket(brokerSocket),
		mounter.WithBrokerSocketDir(brokerSocketDir),
		mounter.WithSignals(signals),
	).Mount(cfg)
}
