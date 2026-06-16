# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Conformance-runner image. Compiles the rclone standard backend test suite
# (backend/ocufs, TestFstestsLiveBroker) into a standalone static test binary
# on a minimal busybox base. The binary configures its OWN ocufs remote and
# dials the broker session socket DIRECTLY — it never touches the FUSE mount
# or its VFS cache, so every fstests write/read-back round-trip is inherently
# broker-cold (the read can only be served by the broker's fileDownload path).
# It holds no broker credential (SEC-25): socket_path + filesystem_id are the
# only handles, supplied through the rclone config.
#
# Build context: the repository root (see docker-compose.yml). The sibling
# conformance.Dockerfile.dockerignore replaces the root .dockerignore for THIS
# build so the backend package enters the context.

# Builder. Pinned by digest; the tag comment records the human-readable
# reference next to the digest. golang:1.26-bookworm.
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compile (don't run) the backend conformance suite into a static standalone
# test binary. No -tags e2e: the fstests suite lives in the plain backend
# package, not behind the e2e build tag the exercise runner uses.
ENV CGO_ENABLED=0
RUN go test -c -trimpath -o /conformance.test ./backend/ocufs/

# Also build the conformance-bootstrap step that renders the rclone remote at
# bringup (service_url + minted weak JWT + CA PEM through the new transport).
RUN go build -trimpath -o /conformance-bootstrap ./test/harness/cmd/conformance-bootstrap

# Runtime. busybox 1.37.0-glibc pinned by digest (the static test binary needs
# no libc; the shell drives the broker-socket readiness poll).
FROM busybox@sha256:4279d9b47df4c1b02d80efd8d02cd59b3a8182c1e785a4ff3f6983bee19dc8b0 AS runtime

COPY --from=builder /conformance.test /conformance.test
COPY --from=builder /conformance-bootstrap /conformance-bootstrap

# rclone's fstests bootstrap (fstest/testserver.Start) unconditionally locates
# an fstest/testserver/init.d directory relative to the working directory
# before it checks whether the remote even has a start command — and errors out
# ("run from within rclone source") when the directory is absent, regardless of
# remote. The ocufs remote is a plain backend with no test-server to launch, so
# an EMPTY init.d directory satisfies the lookup: the bootstrap finds it, sees
# the remote has no start command, and no-ops. Create it and run the binary
# from /work so the relative lookup resolves.
WORKDIR /work
RUN mkdir -p /work/fstest/testserver/init.d

# The command (poll for the broker session socket, then exec the test binary
# from /work) is supplied by the compose service.
