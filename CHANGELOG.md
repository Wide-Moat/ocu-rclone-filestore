<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Authored files in this repository are licensed under FSL-1.1-Apache-2.0; each
release converts to Apache-2.0 two years after its publication. Files derived
from upstream rclone retain rclone's MIT license with attribution preserved
(see `NOTICE`).

Nothing has been tagged yet. Until the first release, all changes live under
`Unreleased`.

## [Unreleased]

### Added

- Mount configuration loader that reads the single-shape mount-config input
  with strict decoding (unknown fields are rejected), holds the top-level
  trust anchor (`ca_cert_pem`) and each mount's session token (`auth_token`),
  and enforces the per-mount scope as an exclusive choice between a filesystem
  id and a memory store id.
- HTTPS/REST transport client (`internal/brokerrpc`) that reaches storage over
  the egress edge at the `v1/filestore/fs/<op>` routes, covering chunked
  upload, ranged read, cursor-based directory pagination, mapping of deny
  reasons to their filesystem-facing errors, and a pacer that applies backoff
  when the storage tier signals throttling.
- The `ocufs` rclone backend (`backend/ocufs`) that drives every file
  operation exclusively over that transport, holding no backend credential and
  opening no second transport.
- FUSE frontend in `internal/mounter` with multimount orchestration: it
  brings up each configured mount, publishes a ready-file once the mounts
  are serving, and performs a graceful unmount on shutdown.
- Live end-to-end exercise harness that mounts through the egress edge to a
  REST filestore and walks the full data path, asserting the egress edge is the
  only hop the guest reaches.
- A `--version` flag on the mount binary.
- Continuous integration gates: cross-platform build (linux amd64 and arm64),
  `go vet`, unit and conformance tests, a coverage ratchet, secret scanning
  (gitleaks and trufflehog), SAST (semgrep), SCA (trivy), conventional-commit
  enforcement, and a lexicon denylist job.
- Release pipeline via goreleaser on `v*` tags, producing checksums and an
  SBOM, gated on a passing live end-to-end run.
- Community-health documentation: `CONTRIBUTING.md`, `SECURITY.md`, and a
  referenced code of conduct.
- System-architecture document (`docs/architecture.md`) with diagrams: the
  system-context and container views, the trust boundaries and host-side
  credential seam, the end-to-end data path of a file operation, the south
  face, a per-package component decomposition, and a requirement-to-code
  discharge map.

### Changed

- Transport is now HTTPS/REST over TLS rather than a guest-local socket. The
  guest dials an outbound `https://` `service_url`, trusting only the inspecting
  edge's CA (`ca_cert_pem`), and reaches storage at the
  `v1/filestore/fs/<op>` routes. There is no socket flag; the transport is
  config-derived.
- Authorization is now a per-mount static session JWT presented as
  `Authorization: Bearer`, carried by each mount's `auth_token` in the
  single-shape mount config. An Envoy egress edge validates the weak JWT against
  the control-plane JWKS, strips it, exchanges it (RFC 8693) for the real
  storage credential keyed on `filesystem_id`, and injects that credential
  before the REST filestore. The JWT is an edge-only assertion; the guest still
  holds no backend or object-store credential.
- Canonical guest mountpoints are `/mnt/user-data/uploads/` (read-only inputs)
  and `/mnt/user-data/outputs/` (read-write sink).
- The live end-to-end exercise runs the network topology end to end in a Lima
  VM (mount → egress edge → REST filestore) and asserts the edge is the only
  hop the guest reaches.

[Unreleased]: https://github.com/Wide-Moat/ocu-rclone-filestore/commits/main
