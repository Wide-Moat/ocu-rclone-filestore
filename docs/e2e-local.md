# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors

# Running the end-to-end harness locally under Lima

A real FUSE mount needs a Linux kernel and a real `/dev/fuse`. On a non-Linux
workstation, run the compose harness inside a Lima VM that provides both. These
steps take the harness up, run the live exercise, and tear it down.

## Prerequisites

- `limactl` (Lima) installed.
- A Lima VM that runs a Linux kernel with Docker available inside it. The VM
  must expose `/dev/fuse` to containers and allow the `SYS_ADMIN` capability —
  a standard Linux VM does.
- Network access from the VM: the broker image build clones the sibling public
  broker repo (github.com/Wide-Moat/ocu-filestore) at the pinned ref.
- AppArmor caveat: on an AppArmor-enforcing host (e.g. Ubuntu), the default
  container profile denies the mount syscall even with `CAP_SYS_ADMIN`, so a
  FUSE mount inside a container fails with `permission denied`. The compose
  harness therefore runs the mount service with
  `security_opt: [apparmor=unconfined]`; a tailored AppArmor profile allowing
  `mount fstype=fuse.*` is the stricter alternative if your environment
  forbids unconfined containers.

## 1. Bring up a Lima VM with Docker

Start a Lima VM that ships Docker (or install Docker inside it), then point your
Docker client at the VM's Docker context so `docker` / `docker compose` commands
run against the Linux kernel:

```sh
limactl start                 # start (or create) a Docker-capable Linux VM
docker context use lima-<vm>  # Lima registers the context as lima-<vmname>
```

For a VM named `ocu-linux` the context is `lima-ocu-linux`. Alternatively, skip
the context switch entirely and run every `docker` command inside the VM via
`limactl shell <vm> docker ...`.

Confirm the FUSE device is present inside the VM:

```sh
limactl shell <vm> test -e /dev/fuse && echo "fuse device present"
```

## 2. Prepare the workspace bind

The mount destinations are a host bind with `rshared` propagation, so the FUSE
mounts created inside the mount container propagate to the test-runner (a named
volume cannot propagate mounts created after container start). Create the
directories on the Docker host (the Lima VM) before bringing the harness up:

```sh
limactl shell <vm> mkdir -p /tmp/ocu-e2e-workspace/out /tmp/ocu-e2e-workspace/in /tmp/ocu-e2e-workspace/out2 /tmp/ocu-e2e-workspace/throttle
```

## 3. Bring up the harness

From the repository root, build and start the brokers and the mount. The broker
image is built by a clone-at-ref builder pinned by `BROKER_REF` (default
`c0a817b`); override it with `BROKER_REF=<ref>` in the environment if the pin
moves:

```sh
docker compose -f deploy/compose/docker-compose.yml up --build -d broker-rw broker-ro broker-throttle mount
```

The mount entrypoint creates the ready-file at `/run/ocu/mount-ready` on the
`mount-shared` volume once every mount is up; the test-runner polls it before
starting the exercise, so there is nothing to wait on by hand.

## 4. Run the live exercise

The exercise runs INSIDE the harness, in the `test-runner` compose service
(profile `test`, so a plain `up` never starts it). The runner has the live gate
`RCLONE_OCUFS_LIVE` and the mountpoint/ready-file env preset, receives the FUSE
mounts through an `rslave` bind, and shares the host PID namespace with the
mount service so the graceful-teardown step signals the real mount process —
and survives that process's exit to finish its assertions. It resolves the
mount PID itself; you never export a PID by hand.

```sh
docker compose -f deploy/compose/docker-compose.yml run --rm test-runner
```

Two SC2 caveats:

- **Throttle (step 9).** SEC-46 throttling is broker-side and the guest never
  simulates it. Until the broker's ops-per-second affordance is present in the
  pinned ref and wired here, step 9 FAILS the run (fail-closed). To run the
  rest of the exercise anyway, opt into a partial run explicitly:

  ```sh
  OCU_E2E_ALLOW_PARTIAL=1 docker compose -f deploy/compose/docker-compose.yml run --rm test-runner
  ```

  A partial run is for local iteration only — the release gate never sets it,
  so a release cannot publish until step 9 actually runs green.

- **Teardown (step 10).** The runner SIGTERMs the mount process as its last
  step, so after a full (non-partial) run the mount service is down by design.
  Re-run `up -d mount` before another exercise round.

## 5. Tear down

```sh
docker compose -f deploy/compose/docker-compose.yml down -v
```

The `-v` removes the shared volumes (sockets, ready-file, broker workspaces and
audit sinks) so the next run starts clean. On graceful teardown the mount
unmounts every mount and the ready-file is removed.

## Notes

- This binary builds openly on the public rclone project; the mount path uses
  rclone's pure-Go FUSE mount, so the image is fully static and needs no
  libfuse.
- The release-path e2e gate runs this same harness (see
  [`ci-fuse-decision.md`](ci-fuse-decision.md) for where it runs and why the
  release requires a green live gate either way).
