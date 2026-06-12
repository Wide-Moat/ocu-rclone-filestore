# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors

# CI /dev/fuse availability — decision record

## Working assumption — to be probed in 05-02

Whether the standard GitHub-hosted `ubuntu-latest` runner exposes `/dev/fuse`
to a workload container (and permits the `--device /dev/fuse` +
`--cap-add SYS_ADMIN` mount pattern) has **not been verified** and is treated
here as an open question, not a finding. Wave 05-02 runs an explicit probe on
the hosted runner — `test -e /dev/fuse` plus a container smoke that performs a
trivial FUSE mount — before committing to a runner placement. If the hosted
runner suffices, the live gate runs there and no self-hosted/Lima host is
needed for CI; the decision below covers the case where it does not.

## Decision

The **live** end-to-end exercise — the one that performs a real FUSE mount and
drives file operations through it against a live broker — runs on a host that
provides a real `/dev/fuse`:

- the **hosted runner itself**, if the 05-02 probe shows it exposes the FUSE
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

This is the decision recorded in wave 05-01. The `e2e` job's body in wave 05-01
is a placeholder that builds the gated runner and runs it with the live gate
unset, so it skips clean and the gate is green; the gate's structure (the job
and the publish dependency on it) is complete now. Wave 05-02 replaces the
`e2e` job body with the live broker exercise on a `/dev/fuse`-capable host,
keeping the job name and the publish dependency unchanged.
