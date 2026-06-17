<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Entrypoint — `cmd/ocu-rclone-filestore`

The guest mount binary's process shell. It turns a command-line invocation into
a resolved set of inputs and a single call into the mounter, then maps the
result onto a Unix exit code. No mount logic lives here: config schema work,
the outbound HTTPS transport, FUSE mounting, and ordered teardown all sit behind
one injected seam in `internal/mounter` and `internal/mountcfg`. Two files, and the split
between them is the whole design — `main` is the part that touches the process
(`os.Args`, `os.Exit`), `run` is everything testable.

## The process boundary

`main` is a four-line wrapper. It hands `os.Args[1:]` and `os.Stderr` to `run`,
prints `ocu-rclone-filestore: <err>` and exits 1 on a non-nil error, and exits 0
on nil. It is the only code that calls `os.Exit`; `run` returns errors and never
touches the exit code itself. That separation is what lets the table test drive
every branch without spawning a process.

`version` is a package var defaulting to `"dev"`, stamped at link time by the
release and container builds. Nothing at runtime depends on its value — it is
read only to answer `--version`.

## Flags, env, and the testable core

`run` delegates straight to `runWith`, passing the production mount function.
`runWith` is the heart of the package: it builds its **own** `FlagSet` rather
than the global one — which is what lets the table test call it repeatedly —
parses the flags, resolves the runtime inputs, loads the config, and calls the
injected mount function. The injection point is the `mountFunc` type; production
wires `productionMount`, and the test injects a recording double to assert the
resolved inputs without a real mount.

Three flags are accepted:

| Flag | Env fallback | Meaning |
| --- | --- | --- |
| `--config` | — | Path to the guest mount config. Required. |
| `--version` | — | Print the build-stamped version and exit 0. |
| `--ready-file` | `OCU_READY_FILE` | Optional path created once all mounts are ready. |

The ready-file resolves through `resolveFlagOrEnv`: a set flag wins, an unset
flag falls back to the env var, and an empty result is passed through untouched
(an empty ready-file simply disables the readiness signal). There is no socket
flag — the transport is config-derived.

## Runtime inputs versus config

The ready-file path is the one **host-controlled runtime input**, sourced from a
flag or env at launch. It is deliberately *not* a field of the guest mount config
schema: the config describes *what* to mount — destination, scope, read-only
versus write, cache knobs — and the transport it speaks (`service_url`,
`ca_cert_pem`, per-mount `auth_token`), while the ready-file describes *how this
process signals readiness* for this one session. The guest holds no BACKEND
credential: the per-mount `auth_token` it carries is a static session JWT, an
edge-only assertion the egress edge exchanges for the real storage credential.
The entrypoint reads no credential from the environment; the JWT arrives in the
validated config, and the endpoint is config-derived, not a runtime flag.

## Exit codes and signal ordering

Every failure path returns a non-nil error — a flag parse failure, a missing
`--config`, or a config that fails to load — and `main` turns any of them into
exit 1. The only nil returns are a clean `--version` short-circuit and a clean
shutdown after the mounter tears down. `--version` is checked *before* the
`--config` requirement, so a version query needs no config; it
writes to stderr (the `FlagSet`'s output), not stdout, to keep the output
contract simple.

Signal ownership is claimed in a fixed order, and the order is load-bearing:

1. `atexit.IgnoreSignals` is called **before any mount starts**. Upstream rclone
   would otherwise install its own `SIGTERM`/`SIGINT` handler the first time a
   mount is waited on and `os.Exit(128+sig)` straight past our teardown — leaving
   mounts up and a stale ready-file on the shared volume. rclone exports this
   entry point precisely so an embedding program can claim signal ownership.
2. A buffered signal channel is registered for `SIGTERM` and `SIGINT`, stopped on
   return via `defer`, and handed to the mounter as the **sole** handler. The
   mounter selects on it to unmount every live mount in order, remove the
   ready-file, and return — which `main` maps to exit 0.

Moving `IgnoreSignals` after the mounter is constructed, or making it
conditional, reopens exactly the bypass it exists to close.

`Code: run.go (run, runWith, resolveFlagOrEnv, productionMount, mountFunc), main.go (main, version).`
