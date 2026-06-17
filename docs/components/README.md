<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Component documentation — index

This directory documents each package of the guest-side mount binary in
detail: one document per package, covering its purpose, files, and key types.
For the system-level picture — what the binary is, the trust boundaries it
lives inside, the data path of a single file operation, and how the packages
fit together — start with the overview in [`../architecture.md`](../architecture.md).
The documents here are the per-package detail those sections point down into.

![Package map: the entrypoint loads config and drives the mounter, which builds the ocufs backend per mount, which reaches the egress edge only through brokerrpc and its single outbound HTTPS connection.](../diagrams/03-package-map.svg)

## Components

Listed in dependency order: the entrypoint loads and validates config, then
drives the mounter, which builds the `ocufs` backend, which speaks to the
broker through `brokerrpc`. The wire reference is the authoritative detail
behind the `brokerrpc` package.

| Document | Package | Responsibility |
|---|---|---|
| [`01-entrypoint.md`](./01-entrypoint.md) | `cmd/ocu-rclone-filestore` | Process shell: parse argv, source the ready-file runtime input, load config, claim signals, drive the mounter, map result to an exit code. |
| [`02-mountcfg.md`](./02-mountcfg.md) | `internal/mountcfg` | Strictly decode the host-supplied guest mount config into a typed `*Config`; enforce every structural rule and hold the single-shape transport material — `service_url`, `ca_cert_pem`, per-mount `auth_token` (SEC-25). |
| [`03-contract.md`](./03-contract.md) | `internal/contract` | Validate config documents against the vendored mount-config schema root — the single-shape conformance check (SEC-25). |
| [`06-mounter.md`](./06-mounter.md) | `internal/mounter` | Orchestrate N mounts from a validated config: fan out, fail fast with cleanup, map config to VFS/FUSE options, mount over the direct kernel path (no `fusermount`), signal readiness once, tear down on signal. |
| [`05-ocufs-backend.md`](./05-ocufs-backend.md) | `backend/ocufs` | The rclone backend: map rclone's `Fs`/`Object` surface onto broker RPC through the `brokerClient` seam; own path canonicalization, the read-only gate, and the listing depth filter. |
| [`04-brokerrpc.md`](./04-brokerrpc.md) | `internal/brokerrpc` | The only egress: the HTTPS/REST client over the outbound `service_url` to the egress edge, with a static Bearer session JWT; owns the op→intent table, the three-axis authorization stamp, multipart upload / chunked download, and the HTTP-status error mapping. |
| [`07-wire-reference.md`](./07-wire-reference.md) | `internal/brokerrpc` (wire) | The authoritative guest-side map of the broker file-ops service: transport, the 18 operations, authorization metadata, chunk arithmetic, ranged read, cursor pagination, and the HTTP-status-to-error mapping. |

## Reading order

Someone new to the binary should read [`../architecture.md`](../architecture.md)
first for the end-to-end picture, then walk these documents in the table order
above — it follows the binary's own call chain, from process start down to the
single outbound HTTPS connection the mount talks through. The wire reference
([`07-wire-reference.md`](./07-wire-reference.md)) is reference material for the
`brokerrpc` package: read it when you need the exact message shapes and error
mapping, not as part of the first pass.

## See also

- [`../architecture.md`](../architecture.md) — system overview: trust
  boundaries, the credential seam, the data path, and the requirement-to-discharge map.
- [`../fork-shape.md`](../fork-shape.md) — why the binary is a thin wrapper over
  rclone rather than a source fork, and the exact rclone seams it relies on.
- [`../requirements.md`](../requirements.md) — the invariants and defaults the
  binary must satisfy, distilled from the canon.
