# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors

# Running the end-to-end harness locally under Lima

A real FUSE mount needs a Linux kernel and a real `/dev/fuse`. On a non-Linux
workstation, run the compose harness inside a Lima VM that provides both. These
steps take the network-topology harness up, run the live exercise (plus the
Envoy-only-hop assertion and the conformance round-trip), and tear it down.

## Prerequisites

- `limactl` (Lima) installed.
- A Lima VM that runs a Linux kernel with Docker available inside it. The VM
  must expose `/dev/fuse` to containers and allow the `SYS_ADMIN` capability —
  a standard Linux VM does.
- Network access from the VM only for the base image pulls; the harness peers
  and the edge are built from this repo's own `test/harness` tree (no external
  clone).
- AppArmor caveat: on an AppArmor-enforcing host (e.g. Ubuntu), the default
  container profile denies the mount syscall even with `CAP_SYS_ADMIN`, so a
  FUSE mount inside a container fails with `permission denied`. The compose
  harness therefore runs the mount service under a tailored, NAMED AppArmor
  profile, `ocu-mount` (`deploy/compose/apparmor/ocu-mount.profile`), that
  permits only `mount fstype=fuse.*` onto the mount root plus the narrow set of
  paths the mount path touches, and denies the rest — not `apparmor=unconfined`.
  A named profile must be loaded into the host kernel BEFORE `docker compose up`,
  or the mount container fails at create with `unable to apply apparmor profile
  ... no such file or directory` and never starts. Load it once per host (it
  persists until reboot):

  ```sh
  limactl shell <vm> sudo apparmor_parser -r deploy/compose/apparmor/ocu-mount.profile
  ```

  Add `-W` to have the parser warn on anything it would not enforce. The CI and
  release e2e jobs run this same load step before bring-up.

## The graph in one breath

The guest mount dials its HTTPS `service_url` outbound to the **edge**; the edge
validates the weak session JWT, strips it, exchanges it for the real filestore
credential keyed on `filesystem_id`, injects that credential, and routes to the
REST **filestore**. The **control-plane** mints the weak JWTs and serves the
JWKS; the **exchange** peer does the RFC-8693 trade. Two networks split the
graph so the edge is the only storage hop the guest can reach
(`deploy/compose/README.md` has the full topology).

## 1. Bring up a Lima VM with Docker

Start a Lima VM that ships Docker (or install Docker inside it). There is no
registered `lima-*` Docker context by default, so run every `docker` command
inside the VM via `limactl shell <vm> docker ...`:

```sh
limactl shell <vm> docker compose version   # confirm compose is available
```

Confirm the FUSE device is present inside the VM:

```sh
limactl shell <vm> test -e /dev/fuse && echo "fuse device present"
```

Make sure the repository is visible inside the VM at its host path (add a Lima
mount for it if not) so `docker compose -f <repo>/deploy/compose/...` resolves.

## 2. Prepare the workspace bind

The mount destinations are a host bind with `rshared` propagation, so the FUSE
mounts created inside the mount container propagate to the test-runner (a named
volume cannot propagate mounts created after container start). Recreate the
directories fresh on the Docker host (the Lima VM) before bringing the harness
up — the mount refuses to shadow residue left by an aborted previous run, and
on a persistent VM that residue survives. Lazy-unmount any stale scope mount
FIRST: an `rm` through a live stale FUSE mount would delete broker-side
content.

```sh
limactl shell <vm> sh -c 'for d in outputs uploads outputs2 throttle; do sudo umount -l "/tmp/ocu-e2e-mountroot/$d" 2>/dev/null || true; done; sudo rm -rf /tmp/ocu-e2e-mountroot; mkdir -p /tmp/ocu-e2e-mountroot/outputs /tmp/ocu-e2e-mountroot/uploads /tmp/ocu-e2e-mountroot/outputs2 /tmp/ocu-e2e-mountroot/throttle'
```

## 3. Bring up the harness

From the repository root, build and start the peers, the edge, and the mount.
The `harness-init` service runs first (it generates the CA, the leaf certs, the
weak JWTs, and the rendered guest config into the shared volume); every other
service waits on it.

Load the named AppArmor profile into the VM kernel first (once per host; see the
caveat under Prerequisites) — the mount service references it by name and will
not start until it is loaded:

```sh
limactl shell <vm> sudo apparmor_parser -r deploy/compose/apparmor/ocu-mount.profile
limactl shell <vm> docker compose -f deploy/compose/docker-compose.yml up --build -d harness-init control-plane exchange filestore edge mount
```

The mount service runs hardened: the `ocu-mount` AppArmor profile (above),
`cap_drop: [ALL]` with only `CAP_SYS_ADMIN` granted back (the sole capability
the in-process FUSE mount/umount path needs), `no-new-privileges`, a read-only
container rootfs with a single writable tmpfs for the rclone VFS disk cache
(`/root/.cache`), and a narrow seccomp profile
(`deploy/compose/seccomp/mount-fuse.json`) that removes the broad
`CAP_SYS_ADMIN`-gated admin syscall group and adds back only `mount`/`umount2`
(plus the runtime's `clone`/`clone3`). The container still runs as root — that
is required so the kernel grants the `CAP_SYS_ADMIN` mount permission; the
hardening above bounds what that root can do.

The mount entrypoint creates the ready-file at `/run/ocu/mount-ready` on the
`mount-shared` volume once every mount is up; the test-runner polls it before
starting the exercise, so there is nothing to wait on by hand.

## 4. Run the live exercise

The exercise runs INSIDE the harness, in the `test-runner` compose service
(profile `test`, so a plain `up` never starts it). The runner asserts
`TestEnvoyOnlyHop` (the single-hop topology) and then drives `TestE2EExercise`.
It has the live gate `RCLONE_OCUFS_LIVE` and the mountpoint/ready-file env
preset, receives the FUSE mounts through an `rslave` bind, and joins the host
PID namespace (`pid: host`) so the graceful-teardown step signals the real mount
process — and SURVIVES that process's exit to finish its assertions. The host
namespace is the runner's alone, not a mount-service privilege: the mount itself
runs in its own private PID namespace (it is PID 1 there). The runner cannot
instead share the mount's namespace (`pid: service:mount`), because there the
mount is PID 1 and the kernel SIGKILLs the runner the instant the teardown
SIGTERMs it (exit 137), before the post-teardown assertions can run. The runner
resolves the mount PID itself; you never export a PID by hand.

```sh
limactl shell <vm> docker compose -f deploy/compose/docker-compose.yml run --rm test-runner
```

Run the backend conformance round-trip (it renders its remote at bringup and
goes through the edge, never touching the FUSE mount):

```sh
limactl shell <vm> docker compose -f deploy/compose/docker-compose.yml run --rm conformance-runner
```

Two SC2 caveats:

- **Throttle (step 12).** SEC-46 throttling is broker-side and the guest never
  simulates it. The filestore applies a tight per-op token bucket on the
  throttle scope (`fsthrottle`, 2 ops/s, burst 2); a burst of writes against it
  drives the scope over budget so the filestore refuses the over-budget ops with
  an unmapped status the guest surfaces as a clean EIO at the FUSE boundary —
  correct SEC-46 behaviour (the pacer rides out transfer-path throttle but does
  not retry VFS metadata ops). Step 12 proves the throttle fires and that a
  caller backing off and retrying recovers the write byte-identical broker-side.
  It needs `OCU_E2E_THROTTLE_MOUNT` and `OCU_E2E_BROKER_THROTTLE_WORKSPACE` set
  (the harness exports both); missing either is a fail-closed hard error. To run
  the rest of the exercise without the throttle scope, opt into a partial run:

  ```sh
  OCU_E2E_ALLOW_PARTIAL=1 docker compose -f deploy/compose/docker-compose.yml run --rm test-runner
  ```

  A partial run is for local iteration only — the release gate never sets it,
  so a release cannot publish until step 12 actually runs green. (Step 9 is a
  thin alias that skips to step 12, kept so a localized failure still reads in
  step order.)

- **Teardown (step 10).** The runner SIGTERMs the mount process as its last
  step, so after a full (non-partial) run the mount service is down by design.
  Re-run `up -d mount` before another exercise round.

## 5. Tear down

```sh
limactl shell <vm> docker compose -f deploy/compose/docker-compose.yml --profile test down -v
```

The `-v` removes the shared volumes (CA/tokens/config, ready-file, filestore
workspace) so the next run starts clean. On graceful teardown the mount unmounts
every mount and the ready-file is removed.

## 6. gVisor (runsc) tier — re-proof deferred (follow-up)

FUSE serving in the gVisor sentry was already proven on a prior tier. The
storage leg is network on every tier, so the network exercise is expected to
work on gVisor too: the mount dials the edge over the docker network, and this
graph has no unix-socket peers, so the old UDS peer-uid blocker is gone.

A thin runtime overlay ([`docker-compose.runsc.yml`](../deploy/compose/docker-compose.runsc.yml))
runs the mount under `runtime: runsc`, but the full exercise does NOT pass
through it as-is: the sentry rejects the `rshared` root-mount propagation the
multi-container graph uses to propagate the FUSE mounts from the mount container
out to the test-runner —

```
root mount propagation option must specify private or slave: "shared"
```

gVisor supports only `private`/`slave` root propagation. Re-proving the network
exercise on gVisor therefore needs a **co-located, single-sandbox harness shape**
(the mount and the runner in one sandbox, no cross-container mount propagation),
the same all-in-one shape the prior socket harness used, re-cut for the network
peers. That is a larger piece than a runtime flag and is left as a follow-up;
the overlay file documents the attempt and the exact blocker. runc remains the
hard release gate; the gVisor tier is additive/advisory
([`ci-runsc-decision.md`](ci-runsc-decision.md)).

## Notes

- This binary builds openly on the public rclone project; the mount path uses
  rclone's pure-Go FUSE mount, so the image is fully static and needs no
  libfuse.
- The release-path e2e gate runs this same harness (see
  [`ci-fuse-decision.md`](ci-fuse-decision.md) for where it runs and why the
  release requires a green live gate either way).
