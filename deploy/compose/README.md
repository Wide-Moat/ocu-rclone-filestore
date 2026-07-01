<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Compose harness — network-topology end-to-end exercise

This harness brings up the mount binary against the network-topology graph: the
guest dials its HTTPS `service_url` outbound to a storage egress edge, and the
edge validates the weak session JWT, strips it, exchanges it for the real
filestore credential keyed on `filesystem_id`, injects that credential, and
routes to the REST filestore. The end-to-end exercise drives ordinary file
operations through the FUSE mount path across that whole chain.

## The Envoy-only-hop invariant

Two networks split the graph. The **mount-facing** network carries the mount,
the runners, and the edge; the **edge-backend** network carries the edge plus
the filestore, control-plane, and exchange. The filestore (and control-plane and
exchange) sit on edge-backend **only**, so the guest has no direct route to
them — the edge is the only reachable storage hop. This deliberately relaxes the
old `network_mode: none` posture; confidentiality now rests on TLS-at-edge, the
filestore's scope validation (foreign-scope 403), and this single-hop property,
which `test/e2e/envoy_only_hop_test.go` asserts rather than assumes.

## Services

- **harness-init** — the bringup keystone (profile-less, runs once and exits).
  Generates the local CA and a leaf serving cert per service, the stable
  control-plane signing key, the per-scope weak session JWTs, and the rendered
  `guest-config.json` (with `service_url` pointed at the edge, `ca_cert_pem` set
  to the CA, and each mount's `auth_token` set to its weak JWT) into the shared
  volume. Every other service waits on its successful completion, so the trust
  graph and the fixture exist before any peer starts. It is idempotent: a re-run
  leaves existing artifacts in place so the CA never rotates out from under a
  running peer.
- **control-plane** — mints the weak session JWTs and publishes the JWKS the
  edge validates them against, over TLS. Signs with the stable key
  `harness-init` generated.
- **exchange** — the RFC-8693 token-exchange peer, over TLS. Validates the weak
  JWT against the control-plane JWKS and issues the real filestore credential as
  a second JWT bound to the scope; publishes that credential JWKS so the
  filestore can verify it with no shared map.
- **filestore** — the REST filestore peer, over TLS, on edge-backend only. Hosts
  the `fsrw`/`fsro`/`fsthrottle`/`fsconf` scopes on local-volume roots, validates
  the injected post-exchange credential against the exchange's credential JWKS,
  and applies the per-op token bucket on the throttle scope (SC2).
- **edge** — the live storage egress edge, over TLS, on both networks. Runs
  validate → strip → keyed-exchange → inject → route for every request — the
  live realisation of the chain the `envoy/envoy.yaml` deployment artifact
  expresses (kept in the tree as the validated artifact; the live F harness
  serves the equivalent chain in-repo pending real-Envoy keyed-injector
  resolution).
- **mount** — built from the repo-root `Dockerfile`. Granted `/dev/fuse` and the
  rendered guest config and workspace bind, and run hardened: `cap_drop: [ALL]`
  with only `CAP_SYS_ADMIN` granted back (the sole capability the in-process FUSE
  mount/umount path needs); the named `ocu-mount` AppArmor profile
  (`apparmor/ocu-mount.profile`) that permits only `mount fstype=fuse.*` plus the
  narrow path set the mount touches, NOT `apparmor=unconfined`; a narrow seccomp
  profile (`seccomp/mount-fuse.json`) that drops the broad `CAP_SYS_ADMIN`-gated
  admin syscall group and adds back only `mount`/`umount2` (plus the runtime's
  `clone`/`clone3`); `no-new-privileges`; and a read-only container rootfs with a
  single writable tmpfs for the rclone VFS cache (`/root/.cache`). The named
  AppArmor profile must be loaded into the host kernel before `up` (`sudo
  apparmor_parser -r apparmor/ocu-mount.profile`). The container runs as root so
  the kernel grants the mount permission; the hardening bounds that root. Unlike
  the old graph it has a real network stack (mount-facing only) and dials its
  `service_url` (the edge) outbound; it has no edge-backend membership, so no
  direct route to the filestore. The guest holds no backend credential: the
  per-mount `auth_token` is the weak JWT, and the real filestore credential never
  reaches it (it lives only between the edge and the filestore).
- **test-runner** — the live e2e gate (profile `test`; `docker compose run --rm
  test-runner`). Asserts `TestEnvoyOnlyHop` (the single-hop topology) then drives
  `TestE2EExercise`. Shares the HOST PID namespace with the mount so the
  graceful-teardown step signals the real mount process, and receives the FUSE
  mounts through an `rslave` bind.
- **conformance-runner** — the rclone standard backend suite
  (`TestFstestsLiveBroker`) run through the edge (profile `test`). Renders its
  ocufs remote at bringup via `conformance-bootstrap` (as `RCLONE_CONFIG_*` env
  overrides carrying the minted weak JWT and the CA PEM), then runs the suite. It
  never touches the FUSE mount, so every write/read-back is cold by construction.

## Shared volumes

- `shared` (at `/shared`) — the CA, leaf certs, signing key, weak tokens, and
  rendered guest config the init step writes and the peers read.
- `mount-shared` (at `/run/ocu`) — carries the ready-file from the mount to the
  test runner.
- `filestore-workspace` — the filestore engine root; each scope lives in a
  subdirectory of it. The runner mounts it read-only to assert the bytes the
  filestore persisted (objects are stored flat under each scope root, so the
  mount-relative path maps 1:1).
- `/tmp/ocu-e2e-mountroot` (host bind at `/mnt/user-data`, `rshared`) — the FUSE
  mount destinations under the canonical mount root. A bind with rshared
  propagation is required so mounts created inside the mount container propagate
  to the host and into the test-runner's rslave bind. Create `outputs/`,
  `uploads/`, `outputs2/` and `throttle/` under it before `up` (see
  [`../../docs/e2e-local.md`](../../docs/e2e-local.md)).

## Readiness

The mount entrypoint creates the ready-file at `/run/ocu/mount-ready` once every
mount is up and removes it on teardown. The minimal runtime image carries no
shell, so readiness is observed from the shared volume (the e2e runner polls that
file before starting the exercise), not via a container healthcheck.

## Running it

Real `/dev/fuse` needs a Linux kernel. On a non-Linux workstation, run the
harness inside a Lima VM that provides a real kernel and the FUSE device — see
[`../../docs/e2e-local.md`](../../docs/e2e-local.md) for the up → run → teardown
steps.
