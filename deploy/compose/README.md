# Compose harness — real end-to-end exercise

This harness brings up the mount binary against a broker over a shared
per-session unix socket, so the end-to-end exercise drives ordinary file
operations through the FUSE mount path.

## Services

- **mount** — built from the repo-root `Dockerfile` (the static mount image).
  It is granted `/dev/fuse` and the `SYS_ADMIN` capability (FUSE needs both),
  the read-only guest config fixture at `fixtures/guest-config.json`, and the
  shared socket volume. Nothing else crosses into the container: no object-store
  network path, no credential env, no second transport. The only outbound
  channel is the broker unix socket on the shared volume (SEC-25). The container
  is invoked with the shipped entrypoint contract: `--config`, `--broker-socket`,
  `--ready-file`.
- **broker** — a clearly-marked **placeholder** for wave 05-01. It is a
  do-nothing pinned base image that idles so the harness topology (the shared
  socket volume and start ordering) is exercisable now. It serves no file-op
  bodies. Wave 05-02 replaces this service with a build of the sibling broker
  repo at a pinned ref, which creates the per-session unix socket on the shared
  volume that the mount dials.

## Shared socket volume

The named volume `broker-socket` is mounted into both services at `/run/ocu`.
The broker creates the per-session unix socket there; the mount dials it. This
is the sole channel between the two services.

## Readiness

The mount entrypoint creates the ready-file at `/run/ocu/mount-ready` once every
mount is up and removes it on teardown. The minimal runtime image carries no
shell, so readiness is observed from the shared volume (the e2e runner waits on
that file), not via a container healthcheck.

## Running it

Real `/dev/fuse` needs a Linux kernel. On a non-Linux workstation, run the
harness inside a Lima VM that provides a real kernel and the FUSE device — see
[`../../docs/e2e-local.md`](../../docs/e2e-local.md) for the up → run → teardown
steps. In wave 05-01 the broker is a placeholder, so a local run skips the live
assertions; the live exercise runs in 05-02 once the real broker service is
wired and the live gate is set.
