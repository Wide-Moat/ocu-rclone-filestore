# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors

# CI /dev/fuse availability — decision record

## Probe wiring (05-02)

Whether the standard GitHub-hosted `ubuntu-latest` runner exposes `/dev/fuse`
to a workload container (and permits the `--device /dev/fuse` +
`--cap-add SYS_ADMIN` mount pattern) is now **probed in CI itself** rather
than assumed. The probe runs in two places with two distinct roles:

- **`ci.yml` → `fuse-probe` job (informational, every PR/push).** It checks
  `test -e /dev/fuse` on the runner, then performs a REAL FUSE mount inside a
  container granted only `/dev/fuse` + `SYS_ADMIN` (AppArmor unconfined —
  the exact device/capability posture the e2e harness uses), using the public
  rclone image pinned by digest mounting an in-memory remote (no credentials,
  no network). The outcome is written to the job summary and surfaced as a
  notice/warning. This job never fails the PR: it produces placement
  evidence, not enforcement.
- **`release.yml` → `e2e` job (hard, release path).** The job's first step
  requires `/dev/fuse` and **fails red** when absent, with no
  `continue-on-error` and no manual bypass. With the device present it runs
  the full live harness (real brokers + mount + test-runner).

What the workflow does with each probe outcome:

- **Hosted runner mounts FUSE in a container** → the live e2e gate runs on
  `ubuntu-latest` in GitHub CI as wired; no self-hosted/Lima host is needed.
- **Hosted runner cannot** → the release-path `e2e` job is red on the hosted
  runner *by design*, structurally blocking publish; the gate must then run
  on a **self-hosted runner** (or the tag must be cut from a flow whose `e2e`
  ran on a Lima host) as a HARD required check. The red job is the forcing
  function: there is no path to a published release that skipped the live
  gate.

## Decision

The **live** end-to-end exercise — the one that performs a real FUSE mount and
drives file operations through it against a live broker — runs on a host that
provides a real `/dev/fuse`:

- the **hosted runner itself**, if the probe above shows it exposes the FUSE
  device to containers (the preferred, cheapest placement), or
- a **self-hosted runner** on a Linux host that grants the FUSE device and the
  mount capability to the container, or
- a **local Lima run** on a developer workstation (see
  [`e2e-local.md`](e2e-local.md)).

The hosted CI continues to run, on every pull request, the subset that does not
need `/dev/fuse`: build (cross-compiled for linux amd64+arm64), vet, unit tests
with the coverage ratchet, the build-graph denylist, the FSL-header gate, and
the goreleaser **snapshot** build that proves the release artifacts build.

## Release gate

The release publishes only behind a green live e2e. In `release.yml` the
`publish` job declares `needs: [e2e]`: a red or absent `e2e` gate structurally
blocks the publish. The live e2e gate is **never silently skipped** — if the
host that provides `/dev/fuse` is unavailable, the `e2e` job is red and the
release is blocked. There is no `continue-on-error` and no manual bypass on the
release path. This is success criterion SC3.

## Scope

The decision was recorded in wave 05-01 with a placeholder `e2e` body
(skip-clean with the live gate unset). Wave 05-02 replaced that body with the
live broker exercise (hard `/dev/fuse` requirement, harness up, test-runner
run, teardown) and added the informational `fuse-probe` job to `ci.yml`; the
job name (`e2e`) and the publish dependency (`needs: [e2e]`) are unchanged.
