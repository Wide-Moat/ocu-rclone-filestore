# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Test-runner image for the e2e harness. Builds the gated exercise package
# (test/e2e, build tag e2e) into a standalone test binary and ships it on a
# minimal busybox base — the shell is needed only for the ready-file poll and
# the mount-PID resolution in the compose command. The runner drives ordinary
# file operations against the FUSE mountpoints; it carries no broker client
# and dials no socket (SEC-25 holds for the runner too).
#
# Build context: the repository root (see docker-compose.yml). The sibling
# runner.Dockerfile.dockerignore replaces the root .dockerignore for THIS
# build so the gated test package enters the context.

# Builder. Pinned by digest; the tag comment records the human-readable
# reference next to the digest. golang:1.26-bookworm.
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compile (don't run) the gated exercise into a static standalone test binary.
ENV CGO_ENABLED=0
RUN go test -c -tags e2e -trimpath -o /e2e.test ./test/e2e/

# Runtime. busybox 1.37.0-glibc pinned by digest (the static test binary needs
# no libc; the shell drives the readiness poll and PID resolution).
FROM busybox@sha256:4279d9b47df4c1b02d80efd8d02cd59b3a8182c1e785a4ff3f6983bee19dc8b0 AS runtime

COPY --from=builder /e2e.test /e2e.test

# The command (poll the ready-file, resolve the mount PID, exec the test
# binary) is supplied by the compose service.
