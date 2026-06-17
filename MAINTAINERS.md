<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Maintainers

This repository is the guest-side mount binary of Open Computer Use. It is
maintained by the Open Computer Use Contributors.

- **Primary maintainer contact:** developer@widemoat.ai

## How decisions are made

- **Architecture is decided upstream.** Specifications, ADRs, and the frozen
  wire contracts live in
  [`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use)
  under `docs/architecture/`. We do not re-decide here what an ADR already
  decided; if a decision must change, it changes in the architecture repository
  first and this repository follows.
- **Implementation decisions happen in the open, via pull request.** How the
  guest side implements an upstream decision — the backend package, the FUSE
  frontend, the HTTPS/REST transport client (`internal/brokerrpc`), the build
  and release plumbing — is reviewed
  and agreed in PR threads on this repository.

## Review bar

Maintainers hold every change to the bar already set for contributors in
[`CONTRIBUTING.md`](./CONTRIBUTING.md):

- **One PR per logical change**, branched off `main`.
- **Conventional commits**, enforced by the commit-lint CI gate.
- **Tests are required.** New behaviour ships with tests; the coverage ratchet
  never drops, and a bug fix ships with a regression test.
- **All CI gates green** before merge: build, vet, unit and conformance tests,
  the coverage ratchet, secret scanning, SAST, dependency CVE scanning, and the
  conventional-commits check.
- **Every authored source file carries the FSL SPDX header.** Files derived
  from upstream rclone keep their upstream MIT header and attribution (see
  `NOTICE`).
- **The broker boundary is non-negotiable.** A change that gives the guest a
  backend credential, an object-store client, a second transport, or an
  authorization decision the broker should own is not merged, however
  convenient.

No change merges without a maintainer's review and approval. Maintainers do not
self-merge substantive changes without a second maintainer's review where one
is available.

## Becoming a maintainer

Maintainership is earned, then offered. The path is sustained, high-quality
contribution — reviewed PRs that respect the boundaries above, helpful and
accurate review of others' work, and dependable follow-through — after which an
existing maintainer extends an invitation. There is no application form.

## Security

Do not report vulnerabilities through PRs, public issues, or this contact for
disclosure. Follow [`SECURITY.md`](./SECURITY.md) and use GitHub's private
vulnerability reporting. For general contribution guidance, see
[`CONTRIBUTING.md`](./CONTRIBUTING.md) and the project
[Code of Conduct](./CODE_OF_CONDUCT.md).
