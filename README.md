<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ocu-rclone-filestore

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Wide-Moat/ocu-rclone-filestore/badge)](https://scorecard.dev/viewer/?uri=github.com/Wide-Moat/ocu-rclone-filestore)

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
the mount speaks). For how this binary fits that system — the trust boundaries,
the host-side credential seam, the end-to-end data path of a file operation,
and what each package in this repo is responsible for — see
[`docs/architecture.md`](./docs/architecture.md).

## Quickstart

You need **Go 1.26+** (see `go.mod`) and a running broker that exposes a
per-session AF_UNIX socket. An actual mount needs Linux with `/dev/fuse`; on
macOS, run it inside the Lima harness (see [`docs/e2e-local.md`](./docs/e2e-local.md)).

**Build:**

```sh
go build -o ocu-rclone-filestore ./cmd/ocu-rclone-filestore
./ocu-rclone-filestore --version
```

**Write a minimal mount config** (`mount.json`). One read-write mount of one
session scope — note there is no `auth_token`: the guest holds no credential.

```json
{
  "schema_version": "v1alpha",
  "service_url": "https://broker.internal",
  "mounts": [
    {
      "destination": "/workspace/out",
      "filesystem_id": "session_01HXYZ_chat",
      "writes": true,
      "vfs_cache_mode": "writes",
      "cache_duration_s": 3600,
      "vfs_cache_max_size": "1G",
      "dir_perms": "0755",
      "file_perms": "0644"
    }
  ]
}
```

`destination` must be an absolute path (not bare `/`). `filesystem_id` is the
session scope; the broker resolves authorization from it.

**Run** it against the broker's socket:

```sh
./ocu-rclone-filestore --config mount.json --broker-socket /run/ocu/session.sock
```

The flags:

| Flag | Env | Meaning |
| --- | --- | --- |
| `--config` | — | path to the mount config (required) |
| `--broker-socket` | `OCU_BROKER_SOCKET` | the per-session broker socket path |
| `--broker-socket-dir` | `OCU_BROKER_SOCKET_DIR` | a directory; each mount dials `<dir>/<filesystem_id>.sock` (mutually exclusive with `--broker-socket`) |
| `--ready-file` | `OCU_READY_FILE` | optional path touched once every mount is up |
| `--version` | — | print the version and exit |

`/workspace/out` is now a live filesystem backed by the broker. Any failure to
bring up a mount is a hard, non-zero exit — never a silently missing directory.
For a full local run with real brokers, see [`docs/e2e-local.md`](./docs/e2e-local.md).

## Status

Prerelease, tracking the broker toward a joint `v0.1.0`. The full data path is
implemented — multi-mount, chunked upload, ranged read and whole-object
download, the read-only double-gate, and the broker deny/throttle mapping — and
every release is gated by a live end-to-end exercise that drives real broker
instances and asserts the bytes reach the broker's own workspace (not just the
local cache). Supply-chain hardening is in place: keyless Sigstore signing, a
per-archive SBOM, and a SLSA build-provenance attestation, with the publish step
fail-closed behind the e2e gate (see [Verifying a release](#verifying-a-release)).

The binary is built as a **thin wrapper module** over rclone: rclone is a pinned
dependency in `go.mod`, our backend registers through rclone's public backend
registry, and our own entrypoint drives rclone's mount machinery for multiple
concurrent mounts. The diff against upstream rclone is zero. See
[`docs/architecture.md`](./docs/architecture.md) for the system architecture and
per-package responsibilities, [`docs/fork-shape.md`](./docs/fork-shape.md) for
why this wrapper shape was chosen over a source fork, and
[`docs/requirements.md`](./docs/requirements.md) for the invariants the binary
must satisfy.

## Language note

This binary is Go because it builds on rclone. The guest-agent language rule
in the architecture repo (ADR-0012) covers the sandbox guest agent; the mount
binary is delivered tooling inside the guest image, pinned to rclone's
ecosystem by the buy-over-build rule.

## Documentation

Start at [`docs/`](./docs/) — its [README](./docs/README.md) routes you by what
you need:

- **Build and run it** → the [Quickstart](#quickstart) above.
- **The system picture** (trust boundaries, the credential seam, the data path) →
  [`docs/architecture.md`](./docs/architecture.md).
- **Per-package detail** → [`docs/components/`](./docs/components/README.md).
- **Run it locally with real brokers** → [`docs/e2e-local.md`](./docs/e2e-local.md).
- **Why a wrapper, not a fork** → [`docs/fork-shape.md`](./docs/fork-shape.md).
- **The invariants it must satisfy** → [`docs/requirements.md`](./docs/requirements.md).

## Sibling repos

- [`ocu-filestore`](https://github.com/Wide-Moat/ocu-filestore) — the broker this binary talks to
- [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox) — sandbox executor + control plane

## Verifying a release

Every release archive is signed keyless with Sigstore (no long-lived key) and
carries a SLSA build-provenance attestation tied to this repository and the
release workflow. Verify provenance with the GitHub CLI, and the signature with
cosign:

```sh
# 1. SLSA build provenance (binds the artifact to this repo + workflow):
gh attestation verify ocu-rclone-filestore_<ver>_linux_amd64.tar.gz \
  --owner Wide-Moat

# 2. Keyless signature of the checksums file (the workflow's OIDC identity is
#    the trust anchor; --certificate-identity-regexp pins the release workflow
#    on a tag ref). The signature, certificate, and inclusion proof are carried
#    in one self-contained .cosign.bundle per file:
cosign verify-blob \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity-regexp \
    '^https://github.com/Wide-Moat/ocu-rclone-filestore/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 3. Check the archive(s) you downloaded against the now-trusted checksums:
sha256sum --ignore-missing -c checksums.txt
```

## License

Our files: FSL-1.1-Apache-2.0 — see [LICENSE](./LICENSE); each release
converts to Apache-2.0 two years after publication. Code derived from
upstream rclone remains under rclone's MIT license with attribution preserved
(see NOTICE when the fork lands). `LICENSE-APACHE` / `LICENSE-MIT` are
dependency reference texts.
