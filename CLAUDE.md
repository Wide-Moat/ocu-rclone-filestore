# Project Instructions — ocu-rclone-filestore

This repository is the **guest-side mount binary** of Open Computer Use: an
rclone-based FUSE mount whose backend speaks the broker's file-operation RPC.
The **architecture and specifications** are the source of truth and live in
`Wide-Moat/open-computer-use` under `docs/architecture/`. Do not re-decide
here what an ADR already decided; if a decision must change, it changes in
the architecture repo first.

This repo is **public**.

## Read before implementing

- `docs/architecture/components/04-storage-broker.md` — the south face this
  binary talks to.
- `contracts/storage/mount-config.schema.json` — the mount's input: per-mount
  destination, scope (`filesystem_id` XOR `memory_store_id`), read-only vs
  write mounts, VFS cache knobs. The guest-side config carries **no
  auth_token**; credential material stays host-side at provision.
- `contracts/storage/file-ops.schema.json` — the RPC the backend speaks.
  Operation names and authorization axes are pinned; bodies marked TBD stay
  TBD — never invent a body here and code against it.
- NFR rows (in `manifesto/02-nfrs.md`): SEC-25 (no backend protocol in the
  guest), SEC-43 (host-derived attribution; guest-supplied ids are hints),
  SEC-46 (per-session ceilings are broker-side; the mount must tolerate
  throttling), SEC-73 (downloadable is broker-resolved; the mount never
  enforces it).

## Load-bearing rules

- The guest holds no backend credential, no object-store client, no
  upstream secret. The only handle is the session-scoped `filesystem_id`.
- The mount never bypasses the broker: no direct network path to any
  backend, no second transport.
- Upstream rclone code keeps its MIT license and attribution; our additions
  carry FSL-1.1-Apache-2.0 headers. Keep the two separable (NOTICE lists
  the split).
- Fork discipline: track upstream rclone minimally — one backend package
  plus the smallest possible diff elsewhere, so rebases stay cheap and the
  diff is auditable.

## Writing discipline

- State facts in this project's own words. Specs, ADRs, and the frozen wire
  contracts are the only citable sources for behaviour; committed files
  never quote or name third-party material (public open-source dependencies
  cited by their public URL are fine).
- All code, comments, commit messages, PR titles and descriptions, and docs
  are **English only**. No exceptions.

## License headers

Every new source file we author starts with:

```
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
```

(comment syntax per language). Files derived from upstream rclone keep their
upstream MIT headers untouched.

## Git

- Identity: `i@yambr.com`. Verify before committing.
- Conventional commits. End commit messages with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Branch off `main`; one PR per logical change. No merge without an explicit
  per-PR instruction.

## CI gates (strict from commit 1)

Every PR must pass: secrets scan (gitleaks + trufflehog, any hit blocks),
naming denylist (lexicon job; the list is maintained outside the tree), SAST
(semgrep CRITICAL blocks), SCA (trivy CRITICAL blocks), conventional-commits.
Coverage and property gates wire in as the code lands.
