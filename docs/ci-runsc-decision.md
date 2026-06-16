# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors

# Running the e2e gate under gVisor (runsc) — decision record

> **Superseded for the network topology.** This record describes the
> all-in-one runsc harness for the earlier unix-socket peer graph, which has
> since been replaced by the network-topology graph (the guest dials an HTTPS
> edge; no unix-socket peers remain). The all-in-one image and entrypoint it
> references have been removed. The gVisor findings below — FUSE serves in the
> sentry; teardown rides SIGTERM → process exit → sandbox reclaim — still hold
> and are the reason the network exercise is expected to pass on gVisor. The
> network re-proof is a tracked follow-up: a thin runtime overlay trips on the
> sentry's refusal of `rshared` root-mount propagation, so it needs a
> co-located single-sandbox harness re-cut for the network peers (see
> `e2e-local.md`, section 6). runc remains the hard release gate.

## Context

The runc-based live e2e gate (`ci-fuse-decision.md`) stands in for the
**native-kernel** guest contour: a real kernel services `/dev/fuse` and
`mount(2)` directly, which is what the production microVM-class guest also
gives the mount. gVisor (`runsc`) is a distinct, lighter isolation tier — the
sentry intercepts `/dev/fuse` and `mount(2)` and services FUSE with its own
in-sandbox implementation. This record captures whether the mount runs under
runsc, what the harness needs to be different there, and how the runsc gate is
placed in CI.

## What was confirmed by running it (not by reading docs)

A staged spike on a runsc-capable host (gVisor `release-20260601.0`, the
systrap platform — no `/dev/kvm`) established, each by a real run:

1. **FUSE serves under runsc.** A go-fuse v2 `DirectMountStrict` server — the
   exact production mount mechanic (in-process `mount(2)` against `/dev/fuse`,
   no `fusermount` helper, server-in-sandbox) — mounts and serves under
   `runsc`. Every opcode the exercise drives works identically to runc: small
   write/read, mkdir/rmdir, rename file, **rename directory**, large chunked
   write, **ranged read**, **a second concurrent mount** (the cold-read shape),
   and readdir.
2. **The `--fuse` runsc flag is deprecated and a no-op** on current runsc.
   In-sandbox FUSE serving is available under the plain `runsc` runtime; no
   experimental flag gates it. (Earlier gVisor releases gated it behind
   `--fuse`; that gate is gone.)
3. **Peer credentials do not survive the gofer.** The broker accepts a
   unix-socket peer only with the same uid. A bind-mounted host socket dialled
   across two `runsc` sandboxes is gofer-proxied and the broker sees the peer
   uid as `(uid_t)-1`, so it rejects the mount. An **in-sentry** socket — both
   peers in one sandbox — preserves the peer uid and the same-uid check passes
   exactly as under runc.
4. **`--pid host` is ignored by the sentry.** A container given `--pid host`
   under `runsc` still gets the sentry's private PID namespace, so a separate
   runner container cannot see or signal the mount process. The host sees only
   the `runsc-sandbox`/`runsc-gofer` wrappers, not the workload.
5. **In-process `server.Unmount()` does not return under the sentry.** The data
   path is unaffected; only go-fuse's graceful in-process unmount-return blocks.
   Teardown therefore relies on `SIGTERM` → process exit → the sandbox
   reclaiming the mount — which is exactly what the exercise's teardown step
   drives.

Findings (3) and (4) together mean the runc harness's multi-container topology
cannot work under runsc. Both dissolve when the brokers, the mount, and the
runner share **one** sandbox: the sockets become in-sentry (peercred preserved)
and the mount PID becomes an ordinary sibling the runner signals directly. This
is also the production gVisor session-sandbox shape, so the co-located harness
is faithful to the target deployment, not a workaround for it.

## Decision

The runsc leg ran the **same** brokers, mount binary, and test binaries as the
runc leg, but co-located in one sandbox via a dedicated all-in-one image (since
removed with the unix-socket graph). No test assertion changed; the exercise and
conformance binaries were byte-for-byte the ones the runc harness compiled. The
conformance suite (socket-direct, no FUSE) was the safe first green that
de-risked the in-sentry socket independently of the FUSE path.

The brokers' loopback metrics/ingress binds (`-ops-listen`, `-north-listen`)
are disabled in the co-located orchestrator: separate containers each bind the
defaults in their own network namespace, but co-located they share one loopback
and would collide. The south unix socket is the only channel the harness uses.

## CI placement

- **`ci.yml` → `runsc-probe` job (informational, every PR/push).** Mirrors the
  `fuse-probe` job: it checks whether `runsc` is installed and can run a trivial
  container, and records the result to the job summary as a notice. It never
  fails the PR — hosted `ubuntu-latest` runners do not reliably provide a
  registered `runsc` runtime, so this job produces placement evidence, not
  enforcement.
- **The runsc e2e/conformance run is a self-hosted / Lima-gated leg**, parallel
  to how the live FUSE e2e is gated. It is **additive and advisory**: a green
  runsc run is not a release blocker in this iteration. The runc/native-kernel
  leg remains the **hard, non-skippable** gate that fail-closes a publish
  (`ci-fuse-decision.md`, SC3).

## Promotion path

The runsc leg stays advisory until it has run green and stable across enough
iterations to justify promotion to a required check. A third contour — a
Firecracker-microVM leg, the production-faithful one — is the natural
completion of the tier set if a KVM-capable runner becomes available; it is out
of scope here.
