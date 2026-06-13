<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Entrypoint — `cmd/ocu-rclone-filestore`

The guest mount binary's process shell. It turns a command-line invocation into
a resolved set of inputs and a single call into the mounter, then maps the
result onto a Unix exit code. No mount logic lives here: config schema work,
socket dialing, FUSE mounting, and ordered teardown all sit behind one injected
seam in `internal/mounter` and `internal/mountcfg`. Two files, and the split
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

Five flags are accepted:

| Flag | Env fallback | Meaning |
| --- | --- | --- |
| `--config` | — | Path to the guest mount config. Required. |
| `--version` | — | Print the build-stamped version and exit 0. |
| `--ready-file` | `OCU_READY_FILE` | Optional path created once all mounts are ready. |
| `--broker-socket` | `OCU_BROKER_SOCKET` | The per-session broker socket. |
| `--broker-socket-dir` | `OCU_BROKER_SOCKET_DIR` | Per-session socket directory; each mount dials `<dir>/<filesystem_id>.sock`. Mutually exclusive with `--broker-socket`. |

The ready-file and both socket inputs resolve through `resolveFlagOrEnv`: a set
flag wins, an unset flag falls back to the env var, and an empty result is
passed through untouched. `resolveFlagOrEnv` does not validate — the
empty-socket rejection and the exclusivity check are the mounter's, so a flag or
config error always surfaces before the socket check ever runs. The entrypoint
forwards both socket strings as-is and never joins a path or decides which one
wins; per-mount socket derivation belongs to the orchestrator.

## Runtime inputs are not config

The ready-file path and the broker socket are **host-controlled runtime
inputs**, sourced from flags and env at launch. They are deliberately *not*
fields of the guest mount config schema, and the socket path in particular is
never derived from a config `service_url` or any schema field. The config
describes *what* to mount — destination, scope, read-only versus write, cache
knobs; the runtime inputs describe *where this process reaches the broker and how
it signals readiness* for this one session. Keeping the socket out of the schema
is what lets one validated config run against any provision-time socket without
re-issuing the config. This is decision D2, and it is also why the guest stays
credential-free — nothing here reads or fabricates an auth token, and the
endpoint is handed in, not constructed.

## Exit codes and signal ordering

Every failure path returns a non-nil error — a flag parse failure, a missing
`--config`, or a config that fails to load — and `main` turns any of them into
exit 1. The only nil returns are a clean `--version` short-circuit and a clean
shutdown after the mounter tears down. `--version` is checked *before* the
`--config` requirement, so a version query needs no config and no socket; it
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
