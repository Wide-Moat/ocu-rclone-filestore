# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# All-in-one harness image for the gVisor (runsc) end-to-end leg.
#
# Unlike the runc harness (docker-compose.yml), which runs the brokers, the
# mount, and the test runner as SEPARATE containers, the runsc leg co-locates
# them in ONE image driven by runsc-aio-entrypoint.sh — because under runsc
# each container is its own sentry sandbox, and both the broker's same-uid
# peer-credential check and the teardown step's PID signalling only work when
# the broker, the mount, and the runner share one sandbox (one process tree,
# one PID namespace, in-sentry unix sockets). See the entrypoint header for the
# full rationale; this mirrors the production gVisor session-sandbox shape.
#
# The image carries the four production/test binaries (broker daemon, mount
# binary, the gated e2e exercise, the backend conformance suite), the two
# fixtures, and a shell to orchestrate them. It is a HARNESS image only and is
# never the shipped artifact; the shipped mount image is the distroless
# Dockerfile at the repo root.
#
# Build context: the repository root. The sibling
# runsc-aio.Dockerfile.dockerignore replaces the root .dockerignore for THIS
# build so the gated test package and the backend enter the context.

# --- broker builder: clone the sibling public broker repo at the pinned ref --
# Same builder and pin discipline as broker.Dockerfile.
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS broker-builder
ARG BROKER_REF=v0.1.0-rc.4
WORKDIR /src
RUN git clone https://github.com/Wide-Moat/ocu-filestore.git . \
 && git checkout --detach "${BROKER_REF}"
ENV CGO_ENABLED=0
RUN go build -trimpath -o /ocu-filestored ./cmd/ocu-filestored

# --- mount + test builder: build the guest binary and both test binaries -----
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS guest-builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
# The production mount binary.
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /ocu-rclone-filestore ./cmd/ocu-rclone-filestore
# The gated exercise (build tag e2e) and the backend conformance suite, each as
# a standalone static test binary — identical to runner.Dockerfile /
# conformance.Dockerfile so the runsc leg runs the SAME tests as the runc leg.
RUN go test -c -tags e2e -trimpath -o /e2e.test ./test/e2e/
RUN go test -c -trimpath -o /conformance.test ./backend/ocufs/

# --- runtime: busybox with all four binaries + fixtures + the orchestrator ---
# busybox 1.37.0-glibc pinned by digest (same base the runner/conformance
# images use); the static binaries need no libc and the shell drives the
# in-sandbox orchestration.
FROM busybox@sha256:4279d9b47df4c1b02d80efd8d02cd59b3a8182c1e785a4ff3f6983bee19dc8b0 AS runtime

COPY --from=broker-builder /ocu-filestored /ocu-filestored
COPY --from=guest-builder /ocu-rclone-filestore /ocu-rclone-filestore
COPY --from=guest-builder /e2e.test /e2e.test
COPY --from=guest-builder /conformance.test /conformance.test

# Fixtures: the guest mount config and the conformance rclone config.
COPY deploy/compose/fixtures/guest-config.json /etc/ocu/guest-config.json
COPY deploy/compose/fixtures/conformance-rclone.conf /etc/ocu/conformance-rclone.conf

# rclone's fstests bootstrap locates fstest/testserver/init.d relative to the
# working directory; an empty directory satisfies the lookup for a backend with
# no test server (see conformance.Dockerfile). The orchestrator cd's to /work
# before running the conformance binary.
RUN mkdir -p /work/fstest/testserver/init.d

COPY deploy/compose/runsc-aio-entrypoint.sh /usr/local/bin/runsc-aio-entrypoint.sh
RUN chmod +x /usr/local/bin/runsc-aio-entrypoint.sh

# Runs as root: the mount's FUSE mount(2) needs CAP_SYS_ADMIN (Docker grants
# added caps only to a root container user), and the brokers must share that
# uid for the same-uid peer-credential accept. Harness image, host-confined to
# exactly /dev/fuse + SYS_ADMIN at run time.
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/usr/local/bin/runsc-aio-entrypoint.sh"]
