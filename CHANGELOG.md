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

- Mount configuration loader that reads the per-mount input contract with
  strict decoding (unknown fields are rejected) and enforces the scope as an
  exclusive choice between a filesystem id and a memory store id.
- Broker RPC client (`internal/brokerrpc`) for the file-operation RPC,
  covering chunked upload, ranged read, cursor-based directory pagination,
  mapping of broker deny reasons to their filesystem-facing errors, and a
  pacer that applies backoff when the broker signals throttling.
- The `ocufs` rclone backend (`backend/ocufs`) that drives every file
  operation exclusively through the broker RPC, holding no backend
  credential and opening no second transport.
- FUSE frontend in `internal/mounter` with multimount orchestration: it
  brings up each configured mount, publishes a ready-file once the mounts
  are serving, and performs a graceful unmount on shutdown.
- Live end-to-end exercise harness that mounts against a broker and walks the
  full data path over a downloadable prefix.
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
  credential seam, the end-to-end data path of a file operation, the broker
  south face, a per-package component decomposition, and a requirement-to-code
  discharge map.

[Unreleased]: https://github.com/Wide-Moat/ocu-rclone-filestore/commits/main
