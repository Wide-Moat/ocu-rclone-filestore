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
limactl shell <vm> mkdir -p /tmp/ocu-e2e-mountroot/outputs /tmp/ocu-e2e-mountroot/uploads /tmp/ocu-e2e-mountroot/outputs2 /tmp/ocu-e2e-mountroot/throttle
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

- **Throttle (step 12).** SEC-46 throttling is broker-side and the guest never
  simulates it. The `broker-throttle` service runs with a tight per-session
  token bucket (`-ops-per-second 2 -ops-burst 2`); a burst of writes against it
  drives the broker over budget so it refuses the over-budget ops with the
  throttle class. That ceiling is a uniform per-op fail-closed gate (it counts
  every op the same and denies before decoding the body), so a throttled op
  surfaces a clean EIO at the FUSE boundary — correct SEC-46 behaviour, matching
  how plain rclone behaves (the pacer rides out transfer-path throttle but does
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
docker compose -f deploy/compose/docker-compose.yml down -v
```

The `-v` removes the shared volumes (sockets, ready-file, broker workspaces and
audit sinks) so the next run starts clean. On graceful teardown the mount
unmounts every mount and the ready-file is removed.

## 6. Run the same exercise under gVisor (runsc)

The runc harness above stands in for the native-kernel guest contour (a real
guest kernel services `/dev/fuse` and `mount(2)` directly). The lighter gVisor
tier is different: the `runsc` sentry intercepts `/dev/fuse` and `mount(2)` and
services FUSE with its own in-sandbox implementation. The mount runs there, but
two boundary facts force a different harness shape, so the runsc leg uses a
dedicated **all-in-one** image
([`runsc-aio.Dockerfile`](../deploy/compose/runsc-aio.Dockerfile)) that runs the
brokers, the mount, and the test runner in **one** sandbox rather than the
separate containers the runc compose uses:

- **Peer credentials.** The broker accepts a unix-socket peer only with the same
  uid. A bind-mounted host socket dialled across two `runsc` sandboxes is gofer-
  proxied and does not preserve the peer uid (the broker sees `(uid_t)-1` and
  rejects the mount). An in-sentry socket — both peers in one sandbox — preserves
  it, so the same-uid check passes exactly as under runc.
- **Teardown signalling.** The sentry owns a private PID namespace and ignores
  `--pid host`, so a separate runner container cannot see (let alone signal) the
  mount process. Co-located, the mount PID is an ordinary sibling the runner
  signals directly.

This is the production gVisor session-sandbox shape (the session's broker and
mount share one sandbox), so the runsc leg is faithful to it, not a workaround.

### Prerequisites for the runsc leg

- gVisor installed and registered as a Docker runtime. The `runsc` runtime needs
  `--host-uds=all` in its `runtimeArgs` (host unix-socket passthrough). The
  `--fuse` runsc flag is **deprecated and a no-op** on current runsc; in-sandbox
  FUSE serving is available without it.

  ```jsonc
  // /etc/docker/daemon.json
  {
    "runtimes": {
      "runsc": { "path": "/usr/bin/runsc", "runtimeArgs": ["--host-uds=all"] }
    }
  }
  ```

  Then `sudo systemctl restart docker` and confirm with
  `docker info | grep -i runtimes`.

### Build and run

```sh
docker build -f deploy/compose/runsc-aio.Dockerfile -t ocu-runsc-aio:dev \
  --build-arg BROKER_REF=v0.1.0-rc.4 .

# Conformance only (socket-direct, no FUSE — the safe first green):
docker run --rm --runtime=runsc \
  --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  -e OCU_RUNSC_STAGE=conformance ocu-runsc-aio:dev

# The full exercise (FUSE data path + cold read + SC2 throttle + teardown):
docker run --rm --runtime=runsc \
  --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  -e OCU_RUNSC_STAGE=exercise ocu-runsc-aio:dev

# Both, in order (default):
docker run --rm --runtime=runsc \
  --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  ocu-runsc-aio:dev
```

The same image runs under `--runtime=runc` (swap the flag) as a co-located
control for the multi-container compose harness — the orchestrator and the
binaries are identical; only the runtime changes.

### Notes specific to runsc

- The mount's data-path opcodes (write/read, mkdir/rmdir, rename file and dir,
  large chunked write, ranged read, a second concurrent mount for the cold read)
  all serve under the sentry. The one behavioural difference is that go-fuse's
  in-process `server.Unmount()` does not return under the sentry, so teardown
  relies on `SIGTERM` → process exit → the sandbox reclaiming the mount — which
  is exactly what the exercise's teardown step drives. No assertion changes.
- runsc is the **additive, advisory** tier; the runc/native-kernel leg remains
  the hard release gate (see [`ci-runsc-decision.md`](ci-runsc-decision.md)).

## Notes

- This binary builds openly on the public rclone project; the mount path uses
  rclone's pure-Go FUSE mount, so the image is fully static and needs no
  libfuse.
- The release-path e2e gate runs this same harness (see
  [`ci-fuse-decision.md`](ci-fuse-decision.md) for where it runs and why the
  release requires a green live gate either way).
