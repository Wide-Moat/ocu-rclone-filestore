# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors

# Running the end-to-end harness locally under Lima

A real FUSE mount needs a Linux kernel and a real `/dev/fuse`. On a non-Linux
workstation, run the compose harness inside a Lima VM that provides both. These
steps take the harness up, run the gated exercise, and tear it down.

## Prerequisites

- `limactl` (Lima) installed.
- A Lima VM that runs a Linux kernel with Docker available inside it. The VM
  must expose `/dev/fuse` to containers and allow the `SYS_ADMIN` capability —
  a standard Linux VM does.

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

## 2. Build the mount image and bring up the harness

From the repository root, build the static mount image and start the harness.
The compose file lives at `deploy/compose/docker-compose.yml`; it builds the
mount image from the repo-root `Dockerfile` and brings up the mount service with
`/dev/fuse` + `SYS_ADMIN` and the placeholder broker sharing the socket volume:

```sh
docker compose -f deploy/compose/docker-compose.yml up --build -d
```

The mount entrypoint creates the ready-file at `/run/ocu/mount-ready` on the
shared volume once every mount is up. The mount image is distroless (no shell,
no `ls`), so observe the shared volume from the broker side, which has busybox:

```sh
docker compose -f deploy/compose/docker-compose.yml exec broker ls /run/ocu/
```

(or stream the file out of the mount container without an exec:
`docker compose -f deploy/compose/docker-compose.yml cp mount:/run/ocu/mount-ready -`)

## 3. Run the gated exercise

The exercise runner is the build-tagged `test/e2e` package. It skips clean
unless the live gate `RCLONE_OCUFS_LIVE` is set and the harness exports the
mountpoints and socket. Set the gate and the mountpoint/socket env the runner
reads, then run it:

```sh
export RCLONE_OCUFS_LIVE=1
export OCU_E2E_RW_MOUNT=/workspace/out
export OCU_E2E_RO_MOUNT=/workspace/in
export OCU_E2E_READY_FILE=/run/ocu/mount-ready
go test -tags e2e ./test/e2e/ -run TestE2EExercise -count=1
```

In wave 05-01 the broker is a placeholder, so the live assertions skip until the
real broker is wired. Wave 05-02 supplies the real broker service and the
endpoint; running with the gate set against that service exercises the full
sequence end to end. With the gate unset the runner skips clean everywhere,
including on a plain workstation with no Lima VM.

## 4. Tear down

```sh
docker compose -f deploy/compose/docker-compose.yml down -v
```

The `-v` removes the shared socket volume so the next run starts clean. On
graceful teardown the mount unmounts every mount and the ready-file is removed.

## Notes

- This binary builds openly on the public rclone project; the mount path uses
  rclone's pure-Go FUSE mount, so the image is fully static and needs no
  libfuse.
- Whether hosted CI can run this live exercise is probed in wave 05-02; see
  [`ci-fuse-decision.md`](ci-fuse-decision.md) for the runner-placement
  decision and why the release requires a green live gate either way.
