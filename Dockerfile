# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Mount-side container image. Two stages: a builder that produces a fully
# static CGO_ENABLED=0 binary (mount2/go-fuse is pure Go, so no libfuse and no
# glibc are linked), and a minimal runtime that carries ONLY that binary. The
# runtime image holds no object-store client, no network tool, and no second
# transport (SEC-25): the outbound HTTPS connection to the configured service_url
# (the egress edge) is the sole external handle. The container needs /dev/fuse +
# SYS_ADMIN from the host at run time; neither is baked into the image.

# Builder. Pinned by digest; the tag comment records the human-readable
# reference next to the digest. golang:1.26-bookworm.
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS builder

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src

# Resolve modules first so the dependency layer caches independently of source.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the source tree (the build context is narrowed by .dockerignore to
# the source only).
COPY . .

# Fully static build: CGO disabled, trimmed paths, version stamped via ldflag.
# GOARCH follows the build platform so the same Dockerfile builds amd64 and
# arm64 under buildx.
ENV CGO_ENABLED=0
RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /ocu-rclone-filestore \
      ./cmd/ocu-rclone-filestore

# Stage the empty mount destination directories the guest config points at,
# under the canonical /mnt/user-data mount root (outputs and uploads). The
# distroless runtime has no shell and the mount binary does not create
# destinations, so the mountpoints must exist in the image; staged here and
# copied below so the runtime stage stays a plain COPY. Root-owned, traversable
# by the root runtime user.
RUN mkdir -p /staging/mnt/user-data/outputs /staging/mnt/user-data/uploads

# Runtime. Distroless static, pinned by digest; the tag comment records the
# human-readable reference. gcr.io/distroless/static-debian12 ROOT variant:
# FUSE mount(2) needs the SYS_ADMIN capability in the effective set, and
# Docker grants added capabilities only to a root container user — a non-root
# user gets empty permitted/effective sets and mount(2) is permanently EPERM.
# The container stays confined to exactly /dev/fuse + SYS_ADMIN granted by the
# host at run time, the standard FUSE container posture.
FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS runtime

# Only the static binary and the empty mountpoint directories cross into the
# runtime image. No shell, no package manager, no extra tooling — the attack
# surface is the one binary plus its outbound HTTPS connection to the egress edge.
COPY --from=builder /staging/ /
COPY --from=builder /ocu-rclone-filestore /ocu-rclone-filestore

# The container is invoked as the mount binary; the host supplies --config and
# optionally --ready-file (or OCU_READY_FILE) as args/env per the shipped
# entrypoint contract. The transport is config-derived (service_url + ca_cert_pem
# + per-mount auth_token); there is no socket flag.
#
# Reviewed exception to the "last USER must not be root" rule: this guest MUST
# run as root because the FUSE mount(2) syscall needs CAP_SYS_ADMIN in the
# effective set and Docker grants added capabilities only to a root container
# user (a non-root user gets empty permitted/effective sets and mount(2) is
# permanently EPERM). The container is confined to exactly /dev/fuse +
# SYS_ADMIN granted by the host, with no shell, package manager, or extra
# tooling — the minimal FUSE container posture. The rationale is also recorded
# above the runtime FROM.
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/ocu-rclone-filestore"]
