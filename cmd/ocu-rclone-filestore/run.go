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
// flag/env resolution is asserted without a real mount. The transport
// (service_url + per-mount auth_token + ca_cert_pem) arrives in the config, so
// the only runtime input here is the ready-file.
type mountFunc func(cfg *mountcfg.Config, rc mounter.ReadinessConfig, signals <-chan os.Signal) error

// run parses args, loads the guest mount config from the --config path, sources
// the ready-file runtime input (flag with an env fallback) and the
// termination-signal channel, and drives the mounter. It returns a non-nil error
// on every failure path and nil only on a clean shutdown. It never calls
// os.Exit; main maps the returned error to the exit code.
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
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	// --version prints the build-stamped version and exits cleanly, BEFORE the
	// --config requirement: a version query must not need a config. It writes to
	// stderr (the FlagSet's output) so the one-line stdout/stderr contract stays
	// simple and the value is the same linker-stamped symbol the build sets.
	if *showVersion {
		if _, err := fmt.Fprintf(stderr, "ocu-rclone-filestore %s\n", version); err != nil {
			return fmt.Errorf("write version: %w", err)
		}
		return nil
	}

	if *configPath == "" {
		return errors.New("missing required --config flag: pass the path to the guest mount config")
	}

	// Flag wins over env; an unset flag falls back to the env var. The ready-file
	// path is a host-controlled RUNTIME input, never a field of the frozen guest
	// mount config schema.
	resolvedReadyFile := resolveFlagOrEnv(*readyFile, "OCU_READY_FILE")

	cfg, err := mountcfg.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Guarantee the VFS disk cache has a writable directory before any mount
	// starts, independent of HOME/env. The hardened posture's read-only rootfs
	// leaves only a tmpfs writable, and a missing HOME resolves the rclone cache
	// dir onto a read-only root-level path where the disk cache silently disables
	// (SEC-46 degrade). This binary-owned invariant redirects only when the
	// resolved default is not writable; an already-writable dir is left as-is.
	if err := mounter.EnsureWritableCacheDir(); err != nil {
		return fmt.Errorf("ensure VFS cache dir: %w", err)
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
	return mount(cfg, rc, sig)
}

// resolveFlagOrEnv returns the flag value when set, otherwise the env var. An
// empty result is left to the downstream consumer to handle (an empty ready-file
// disables the ready-file signal).
func resolveFlagOrEnv(flagVal, envKey string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envKey)
}

// newMounter constructs the mounter from the functional options productionMount
// assembles. It is a package-level seam (default: mounter.New) so a test can
// substitute a recording constructor and assert the readiness and signals
// options land on the mounter without driving a real kernel mount.
var newMounter = mounter.New

// productionMount wires the ready-file and signal runtime inputs into the
// functional-options mounter and runs it. The transport flows in cfg; Mount(cfg)
// stays unchanged and the entrypoint contract does not break.
func productionMount(cfg *mountcfg.Config, rc mounter.ReadinessConfig, signals <-chan os.Signal) error {
	return newMounter(
		mounter.WithReadiness(rc),
		mounter.WithSignals(signals),
	).Mount(cfg)
}
