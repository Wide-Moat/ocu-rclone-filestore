# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Harness peer image for the network e2e graph. Builds ONE harness cmd main
# (selected by the CMD_PKG build arg) into a static binary on a minimal base.
# The same Dockerfile builds every peer — filestore, control-plane, exchange,
# the live edge, the harness-init keystone, and the conformance-bootstrap step —
# so the layer cache is shared across services and only the final compile differs.
#
# These are HARNESS binaries under test/harness; none is the shipped guest mount
# (that is the repo-root Dockerfile). They serve TLS using leaf certs the local
# CA issues; the guest is told only the edge's CA PEM as ca_cert_pem.
#
# Build context: the repository root (see docker-compose.yml). The sibling
# peer.Dockerfile.dockerignore lets the test/harness tree enter the context.

# Builder. Pinned by digest; the tag comment records the human-readable
# reference next to the digest. golang:1.26-bookworm.
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The cmd package to build, e.g. ./test/harness/cmd/filestored. Supplied per
# service by the compose build args so one Dockerfile serves every peer.
ARG CMD_PKG
ENV CGO_ENABLED=0
RUN test -n "$CMD_PKG" || (echo "CMD_PKG build arg is required" >&2; exit 1)
RUN go build -trimpath -o /peer "$CMD_PKG"

# Stage the writable mount targets owned by the nonroot UID/GID (65532) so the
# runtime stage stays a plain COPY (distroless has no shell for mkdir/chown).
# A fresh named volume inherits the image directory's owner, so harness-init
# (-> /shared) and filestore (-> /workspace) come up writable for the nonroot
# account without a root entrypoint.
RUN mkdir -p /staging/shared /staging/workspace \
    && chown -R 65532:65532 /staging

# Runtime. Distroless static (debian12) nonroot variant, pinned by digest; the
# tag comment records the human-readable reference. The nonroot variant ships
# UID/GID 65532 (nonroot) as the default user, so no adduser/addgroup is needed
# — and none would work on a shell-less image. None of the peers needs a
# privileged port (they serve TLS on high ports) or any host capability, so the
# unprivileged default user is correct. gcr.io/distroless/static-debian12:nonroot.
FROM gcr.io/distroless/static-debian12@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639 AS runtime

COPY --from=builder /peer /peer
COPY --from=builder --chown=65532:65532 /staging/shared /shared
COPY --from=builder --chown=65532:65532 /staging/workspace /workspace

USER 65532:65532

ENTRYPOINT ["/peer"]
