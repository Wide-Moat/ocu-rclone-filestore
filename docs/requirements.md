<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Requirements and defaults

Distilled from the architecture canon (component-04 south face, the
mount-config and file-ops contracts, and the NFR rows they cite) for the team
building this binary. The canon wins on any conflict.

## What the binary is

A thin wrapper module over rclone whose backend reaches storage over
HTTPS/REST via the egress edge instead of any object-store protocol. It mounts
one or more per-session filesystems into the guest tree and translates VFS
operations into file-operation requests. Mount verbs only — it serves nothing,
proxies nothing, exposes no HTTP/S3 facade.

## Invariants (build targets)

| # | Rule | Source |
|---|---|---|
| 1 | The guest-side mount config carries a per-mount `auth_token` — a scoped, short-lived session JWT the guest presents at the egress hop — and the scope handle (`filesystem_id`); it carries no BACKEND/object-store key. The JWT is an edge-only assertion the Envoy edge validates and exchanges for the real storage credential, so no backend secret ever reaches the guest config or environment | mount-config contract; NFR-SEC-25 |
| 2 | Exactly one of `filesystem_id` / `memory_store_id` is set per mount (XOR); both or neither is a hard config error | mount-config contract |
| 3 | The backend speaks only the file-ops RPC to the broker; no direct network path to any object store, no second transport | NFR-SEC-25 / SEC-16 |
| 4 | Guest-supplied ids in RPC calls are hints; the broker attributes by host-derived identity — the mount must not depend on its self-asserted id being trusted | NFR-SEC-43 |
| 5 | Per-mount read-only vs writable disposition comes from mount config (e.g. an inbound staging mount is read-only; an outputs mount is writable); the mount enforces it at the VFS layer as well | mount-config contract |
| 6 | Broker-side throttling (per-session file-ops/s, in-flight bytes) surfaces as backpressure, not data loss; a throttled write retries or fails the VFS call cleanly | NFR-SEC-46 |
| 7 | `downloadable` is broker-resolved; the mount neither sees nor enforces it | NFR-SEC-73 |
| 8 | Mount failure at session start is a hard session-start error, never a silently missing directory | component-04 south face |

## Defaults (config-driven, per mount)

| Knob | Note | Source |
|---|---|---|
| VFS cache mode | per-mount, direction-appropriate (read-only mounts cache aggressively; writable mounts bound write-back) | mount-config contract (`vfs_cache_mode`) |
| Backend cache TTL | per-mount | mount-config contract (`backend_cache_ttl`, `cache_duration_s`) |
| Dir/file permissions | per-mount | mount-config contract (`dir_perms`, `file_perms`) |
| VFS cache size ceiling | per-mount | mount-config contract (`vfs_cache_max_size`) |

Numeric defaults are deployment configuration delivered in mount config; the
binary ships no hard-coded policy values.

## Fork discipline

- One backend package + the smallest possible diff elsewhere; rebases onto
  upstream rclone stay cheap and the diff auditable.
- Upstream MIT headers untouched; our files carry FSL-1.1-Apache-2.0.
- rclone passes the dependency policy gates (MIT license; established
  multi-maintainer project with signed releases).

## Deliberately out of scope

- Serving, share-by-link, preview — north-face concerns; the broker owns
  them.
- Any enforcement of authorization policy — the broker re-derives the three
  axes per request; the mount is a dumb translator with local caching.
- Credential handling of any kind.
