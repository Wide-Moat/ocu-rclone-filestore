# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Broker-side image for the e2e harness. The broker is the sibling PUBLIC repo
# github.com/Wide-Moat/ocu-filestore; this builder clones it at a pinned ref
# (build-arg BROKER_REF) and builds the static ocu-filestored daemon, so the
# harness is reproducible on a fresh checkout and in CI with no submodule and
# no broker source vendored into this tree. Bumping the pin is a one-line
# build-arg change.

# Builder. Pinned by digest; the tag comment records the human-readable
# reference next to the digest. golang:1.26-bookworm (carries git).
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS builder

# The pinned broker ref. b31673f is the peer-confirmed south-face ref this
# wave integrates against (one broker instance per filesystem_id; session
# socket provisioned as <south-socket-dir>/<filesystem_id>.sock).
ARG BROKER_REF=b31673f

WORKDIR /src

# Full clone (all branches) so a ref that lives on a feature branch resolves;
# then detach at the pinned ref. The clone is the ONLY network access in this
# image build; the runtime stage and the running broker have no network at all.
RUN git clone https://github.com/Wide-Moat/ocu-filestore.git . \
 && git checkout --detach "${BROKER_REF}"

# Fully static build, same discipline as the mount image: CGO disabled,
# trimmed paths.
ENV CGO_ENABLED=0
RUN go build -trimpath -o /ocu-filestored ./cmd/ocu-filestored

# Runtime. Distroless static, pinned by digest (same base as the mount image),
# ROOT variant: the broker accepts a unix-socket connection only from a peer
# with the SAME uid (peer-credential check at Accept), and the mount container
# must run as root because FUSE mount(2) needs CAP_SYS_ADMIN, which Docker
# grants only to a root container user — so the broker container runs uid 0
# too. No shell, no package manager; the attack surface is the one binary plus
# the volumes the harness mounts (socket dir, workspace, audit sink).
FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS runtime

COPY --from=builder /ocu-filestored /ocu-filestored

# Reviewed exception to the "last USER must not be root" rule: uid 0 is
# required for the same-uid peer-credential accept check against the root
# mount container (rationale above the runtime FROM).
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/ocu-filestored"]
