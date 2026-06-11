<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ocu-rclone-filestore

The guest-side mount binary of Open Computer Use: it mounts the per-session
filestore into the guest filesystem tree and translates file operations into
the broker's file-operation RPC. Built on [rclone](https://github.com/rclone/rclone)
(MIT): rclone supplies the mount machinery; this repo adds a backend that
speaks the broker RPC instead of any object-store protocol.

The guest holds **no backend credential and no object-store client** — only a
session-scoped mount handle (`filesystem_id`). Every byte goes through the
broker ([`ocu-filestore`](https://github.com/Wide-Moat/ocu-filestore)), which
custodies the one backend credential and resolves authorization per request.

The architecture and specifications live in
[`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use):
the broker component spec (`docs/architecture/components/04-storage-broker.md`,
south face) and the contracts `contracts/storage/mount-config.schema.json`
(what the mount is told) and `contracts/storage/file-ops.schema.json` (what
the mount speaks).

## Status

Early development. The binary is built as a **thin wrapper module** over
rclone: rclone is a pinned dependency in `go.mod`, our backend registers
through rclone's public backend registry, and our own entrypoint drives
rclone's mount machinery for multiple concurrent mounts. The diff against
upstream rclone is zero. See [`docs/fork-shape.md`](./docs/fork-shape.md) for
why this shape was chosen over a source fork, and
[`docs/requirements.md`](./docs/requirements.md) for what the binary must do.

## Language note

This binary is Go because it builds on rclone. The guest-agent language rule
in the architecture repo (ADR-0012) covers the sandbox guest agent; the mount
binary is delivered tooling inside the guest image, pinned to rclone's
ecosystem by the buy-over-build rule.

## Sibling repos

- [`ocu-filestore`](https://github.com/Wide-Moat/ocu-filestore) — the broker this binary talks to
- [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox) — sandbox executor + control plane

## License

Our files: FSL-1.1-Apache-2.0 — see [LICENSE](./LICENSE); each release
converts to Apache-2.0 two years after publication. Code derived from
upstream rclone remains under rclone's MIT license with attribution preserved
(see NOTICE when the fork lands). `LICENSE-APACHE` / `LICENSE-MIT` are
dependency reference texts.
