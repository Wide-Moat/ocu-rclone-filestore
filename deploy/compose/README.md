<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Compose harness — real end-to-end exercise

This harness brings up the mount binary against two real broker instances over
shared per-session unix sockets, so the end-to-end exercise drives ordinary
file operations through the FUSE mount path.

## Services

- **broker-rw / broker-ro** — the real broker daemon (`ocu-filestored`) from
  the sibling public repo
  [github.com/Wide-Moat/ocu-filestore](https://github.com/Wide-Moat/ocu-filestore),
  built by `broker.Dockerfile` via a clone-at-ref builder pinned by the
  `BROKER_REF` build-arg (default `c0a817b`). The broker binds exactly one
  session socket per filesystem scope, named `<filesystem_id>.sock` under its
  session socket directory, so the harness runs one instance per filesystem:
  `broker-rw` serves `fsrw` with `read,write` intents; `broker-ro` serves
  `fsro` with `read` only. Each gets its own engine-root workspace volume and
  audit-sink volume; both run uid 0 because the broker accepts a unix-socket
  peer only from the SAME uid and the mount container must be root for FUSE.
  No workspace seeding: the exercise writes everything it reads via the rw
  mount, and the ro mount is only stat'ed and written-to-fail.
- **mount** — built from the repo-root `Dockerfile` (the static mount image).
  It is granted `/dev/fuse` and the `SYS_ADMIN` capability (FUSE needs both),
  the read-only guest config fixture at `fixtures/guest-config.json`, the
  shared socket volume, and the workspace bind. It is invoked with
  `--broker-socket-dir /sock`: each configured mount derives its own socket
  path `<filesystem_id>.sock` in that directory (`fsrw.sock` for the rw mount,
  `fsro.sock` for the ro mount) — matching the brokers' one-socket-per-
  filesystem provisioning. Nothing else crosses into the container: no
  object-store network path, no credential env, no second transport (SEC-25).

- **test-runner** — the live e2e gate (profile `test`; started explicitly via
  `docker compose run --rm test-runner`). `runner.Dockerfile` compiles the
  gated exercise package (`test/e2e`, build tag `e2e`) into a standalone test
  binary on a busybox base. The service presets the live gate
  (`RCLONE_OCUFS_LIVE`) and the mountpoint/ready-file env, polls the
  ready-file, resolves the mount process PID from the shared PID namespace,
  and runs the exercise. It receives the FUSE mounts through an `rslave` bind
  and shares the HOST PID namespace with the mount service: the
  graceful-teardown step signals the real mount process, and the runner
  survives that process's exit to finish its assertions (joining the mount
  container's own namespace would not survive it — the mount binary is that
  namespace's init, and its exit kills every process in the namespace).

Every service runs `network_mode: "none"`: the unix sockets on the shared
volume are the sole channel, and a unix socket needs no network stack.

## Shared volumes

- `broker-socket` (mounted at `/sock` everywhere) — each broker creates its
  `<filesystem_id>.sock` here; the mount derives and dials them.
- `mount-shared` (at `/run/ocu`) — carries the ready-file from the mount to
  the test runner.
- `broker-{rw,ro}-workspace`, `broker-{rw,ro}-audit` — per-broker engine
  roots and audit sinks (the broker refuses to start without an engine root,
  an audit sink and an upload ceiling).
- `/tmp/ocu-e2e-workspace` (host bind at `/workspace`, `rshared`) — the FUSE
  mount destinations. A bind with rshared propagation is required so the
  mounts created inside the mount container propagate to the host and into
  the test-runner's rslave bind; a named volume does not propagate mounts
  created after container start. Create `out/` and `in/` under it before
  `up` (see [`../../docs/e2e-local.md`](../../docs/e2e-local.md)).

## Readiness

The mount entrypoint creates the ready-file at `/run/ocu/mount-ready` once
every mount is up and removes it on teardown. The minimal runtime image
carries no shell, so readiness is observed from the shared volume (the e2e
runner polls that file before starting the exercise), not via a container
healthcheck.

## Running it

Real `/dev/fuse` needs a Linux kernel. On a non-Linux workstation, run the
harness inside a Lima VM that provides a real kernel and the FUSE device — see
[`../../docs/e2e-local.md`](../../docs/e2e-local.md) for the up → run →
teardown steps.
