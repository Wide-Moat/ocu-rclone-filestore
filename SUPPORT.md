<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Support

This repository, `ocu-rclone-filestore`, is the **guest-side mount binary** of
Open Computer Use: an rclone-based FUSE mount whose backend reaches storage
over HTTPS/REST via the egress edge. The storage architecture and the
specifications it implements live in a **separate upstream repository**
(`Wide-Moat/open-computer-use`). Routing your question to the right place gets
you a faster answer.

## Before you ask

1. Read the [README](README.md) for what this binary does and how to build and
   run it.
2. Check the [`docs/`](docs/) directory for usage and operational notes.
3. Search existing [issues](https://github.com/Wide-Moat/ocu-rclone-filestore/issues)
   and [discussions](https://github.com/Wide-Moat/ocu-rclone-filestore/discussions)
   in case your question is already answered.

## Where to get help

### Architecture and design questions

Questions about the storage architecture, the file-operation contract, mount
configuration semantics, or any cross-component design decision belong
**upstream**, not here. Open them at
[Wide-Moat/open-computer-use](https://github.com/Wide-Moat/open-computer-use).
This repository implements the guest-side mount; it does not own the
architecture.

### Bugs and feature requests

For defects or enhancement ideas specific to this mount binary, open a GitHub
issue using the provided
[issue templates](https://github.com/Wide-Moat/ocu-rclone-filestore/issues/new/choose).
A clear reproduction, the binary version, and your platform (`linux/amd64` or
`linux/arm64`) help us move quickly.

### Security issues

**Do not open a public issue for a security problem.** Report vulnerabilities
privately through GitHub's private vulnerability reporting as described in
[SECURITY.md](SECURITY.md). This keeps users protected while a fix is prepared.

### General questions

Use [GitHub Discussions](https://github.com/Wide-Moat/ocu-rclone-filestore/discussions)
if enabled. If Discussions are not available, open a regular issue with the
question template and we will help from there.

## Scope reminder

This is the guest-side FUSE mount only. It holds no backend credential and
never bypasses the broker. If your question concerns the broker's behaviour,
the wire contract it serves, or the wider system design, the upstream
architecture repository is the right home for it.
