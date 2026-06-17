<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Contributing

Thanks for your interest in contributing to `ocu-rclone-filestore`, the
guest-side mount binary of Open Computer Use.

## Before you start

- **The architecture is decided elsewhere.** The specifications, ADRs, and the
  frozen wire contracts live in
  [`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use)
  under `docs/architecture/`. This repository implements the guest side of the
  storage broker's south face; it does not re-decide what an ADR already
  decided. If a decision must change, it changes in the architecture repository
  first.
- **Read the security boundary.** The guest holds no backend credential and no
  object-store client, never bypasses the broker, and never makes an
  authorization decision the broker should own. A change that crosses those
  lines will not be accepted, however convenient.
- **Keep the rclone diff at zero.** This is a thin wrapper module over
  [rclone](https://github.com/rclone/rclone): rclone is a pinned dependency, our
  backend registers through rclone's public registry, and our entrypoint drives
  rclone's mount machinery. We do not fork rclone. Files derived from upstream
  keep their upstream license and attribution (see `NOTICE`).

## Development

```sh
go build ./...
go test ./... -cover
go vet ./...
gofmt -l .          # must print nothing
golangci-lint run   # structural lint; config is .golangci.yml (pinned: v2.12.1)
```

Install the linter with `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.1`
(the version CI pins), or run it however you prefer — the gate is the committed
`.golangci.yml`, so a local run reproduces CI exactly. Build it with Go 1.26 (a
binary built with an older Go refuses to run against this go-1.26 module).

The full end-to-end exercise needs a real `/dev/fuse` (a Linux kernel) and the
egress edge plus the harness peer graph. On a non-Linux workstation, run it
inside a Lima VM — see
[`docs/e2e-local.md`](./docs/e2e-local.md). The live exercise is gated behind
`RCLONE_OCUFS_LIVE` and the compose harness under `deploy/compose/`.

## Pull requests

- **One PR per logical change**, branched off `main`.
- **Conventional commits.** The commit-lint CI gate enforces this; PR titles
  follow the same convention.
- **Tests are required.** New behaviour ships with tests; the coverage gate
  ratchets and never drops. Bug fixes ship with a regression test that fails
  before the fix.
- **Every authored source file carries the FSL SPDX header** (see existing
  files for the per-language comment form). Files derived from upstream rclone
  keep their upstream MIT header untouched.
- **English only** in code, comments, commit messages, and docs.
- **All CI gates must pass**: build, vet, `gofmt`, golangci-lint, unit +
  conformance tests, the coverage ratchet, secret scanning, SAST, dependency
  CVE scanning, and the conventional-commits check.

## Reporting bugs and requesting features

Use the issue templates. For anything security-sensitive, follow
[`SECURITY.md`](./SECURITY.md) and report privately rather than opening an
issue.

## Code of Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By
participating you agree to abide by it.
