<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ocu-rclone-filestore

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Wide-Moat/ocu-rclone-filestore/badge)](https://scorecard.dev/viewer/?uri=github.com/Wide-Moat/ocu-rclone-filestore)

The guest-side mount binary of Open Computer Use: it mounts the per-session
filestore into the guest filesystem tree and translates file operations into
HTTPS/REST requests sent through the egress edge. Built on [rclone](https://github.com/rclone/rclone)
(MIT): rclone supplies the mount machinery; this repo adds a backend that
reaches storage over HTTPS/REST via the egress edge instead of any object-store
protocol.

The guest holds **no backend credential and no object-store client**. It dials
an outbound HTTPS `service_url`, trusting only the inspecting edge's CA, and
presents a static session JWT — an edge-only assertion. An Envoy egress edge
validates that JWT, strips it, and exchanges it (RFC 8693) for the real storage
credential keyed on `filesystem_id` before the request reaches the broker
([`ocu-filestore`](https://github.com/Wide-Moat/ocu-filestore)), which custodies
the one backend credential and resolves authorization per request.

The architecture and specifications live in
[`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use):
the broker component spec (`docs/architecture/components/04-storage-broker.md`,
south face) and the contracts `contracts/storage/mount-config.schema.json`
(what the mount is told) and `contracts/storage/file-ops.schema.json` (what
the mount speaks). For how this binary fits that system — the trust boundaries,
the host-side credential seam, the end-to-end data path of a file operation,
and what each package in this repo is responsible for — see
[`docs/architecture.md`](./docs/architecture.md).

![The big picture: the guest sandbox talks to this binary, which dials outbound over HTTPS to the Envoy egress edge; the edge exchanges the guest's session JWT for the real credential before the broker, which holds the credential and reaches the backend storage.](./docs/diagrams/01-big-picture.svg)

## Quickstart

You need **Go 1.26+** (see `go.mod`) and an HTTPS `service_url` reachable via the
egress edge (in the local harness, the Envoy edge in the compose graph). An
actual mount needs Linux with `/dev/fuse`; on macOS, run it inside the Lima
harness (see [`docs/e2e-local.md`](./docs/e2e-local.md)).

![The four steps: have the prerequisites, build the binary, write a mount config, run it.](./docs/diagrams/04-setup.svg)

**Build:**

```sh
go build -o ocu-rclone-filestore ./cmd/ocu-rclone-filestore
./ocu-rclone-filestore --version
```

**Write a mount config** (`mount.json`). The config is single-shape: a
top-level `service_url` + `ca_cert_pem` (the edge's trust anchor) and a `mounts`
array. Each mount carries its own `auth_token` — the static session JWT, an
edge-only assertion, not a backend key — its `filesystem_id` scope, and its own
`readonly` posture. The two canonical mounts are the read-only inputs at
`/mnt/user-data/uploads/` and the read-write sink at `/mnt/user-data/outputs/`:

```json
{
  "schema_version": "v1alpha",
  "service_url": "https://edge.internal",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "mounts": [
    {
      "destination": "/mnt/user-data/uploads",
      "filesystem_id": "session_01HXYZ_inputs",
      "auth_token": "eyJhbGciOi...inputs-session-jwt...",
      "readonly": true,
      "vfs_cache_mode": "minimal",
      "cache_duration_s": 3,
      "vfs_cache_max_size": "512M",
      "dir_perms": "0755",
      "file_perms": "0644"
    },
    {
      "destination": "/mnt/user-data/outputs",
      "filesystem_id": "session_01HXYZ_chat",
      "auth_token": "eyJhbGciOi...outputs-session-jwt...",
      "readonly": false,
      "vfs_cache_mode": "writes",
      "cache_duration_s": 3600,
      "vfs_cache_max_size": "1G",
      "dir_perms": "0755",
      "file_perms": "0644"
    }
  ]
}
```

`destination` must be an absolute path (not bare `/`). `readonly` is
host-enforced — the agent cannot flip it. `filesystem_id` is the session scope;
the edge attests it from the validated JWT and the broker resolves authorization
from it. The read-only inputs mount uses a short `cache_duration_s` so
externally-written user data appears promptly, while the read-write outputs sink
uses a long window since the agent is the writer.

**Run** it:

```sh
./ocu-rclone-filestore --config mount.json
```

The transport is config-derived — there is no socket flag. The flags:

| Flag | Env | Meaning |
| --- | --- | --- |
| `--config` | — | path to the mount config (required) |
| `--ready-file` | `OCU_READY_FILE` | optional path touched once every mount is up |
| `--version` | — | print the version and exit |

`/mnt/user-data/uploads` and `/mnt/user-data/outputs` are now live filesystems
served over HTTPS/REST through the egress edge. Any failure to bring up a mount
is a hard, non-zero exit — never a silently missing directory. For a full local
run of the network topology, see [`docs/e2e-local.md`](./docs/e2e-local.md).

## Status

Prerelease, tracking the broker toward a joint `v0.1.0`. The full data path is
implemented — multi-mount, multipart upload, ranged read and whole-object
download, the read-only double-gate, and the broker deny/throttle mapping — and
every release is gated by a live end-to-end exercise that drives the guest
outbound through the Envoy egress edge to the REST filestore on a Lima
network-topology graph, positively asserts the edge is the only reachable hop,
and proves the bytes reach the broker's own store via a cold read (not just the
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
- **See it, not read it** → [`docs/diagrams/`](./docs/diagrams/) — rendered SVGs
  of the big picture, a file's read/write path, the package map, and the setup flow.
- **Per-package detail** → [`docs/components/`](./docs/components/README.md).
- **Run it locally with real brokers** → [`docs/e2e-local.md`](./docs/e2e-local.md).
- **Why a wrapper, not a fork** → [`docs/fork-shape.md`](./docs/fork-shape.md).
- **The invariants it must satisfy** → [`docs/requirements.md`](./docs/requirements.md).

## Sibling repos

- [`ocu-filestore`](https://github.com/Wide-Moat/ocu-filestore) — the broker this binary talks to
- [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox) — sandbox executor + control plane

## Verifying a release

Every release archive is signed keyless with Sigstore (no long-lived key),
carries a SLSA build-provenance attestation tied to this repository and the
release workflow, and ships a signed CycloneDX SBOM. Verify provenance with the
GitHub CLI, and the signatures (checksums and SBOM) with cosign:

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

# 4. (Optional) Verify the SBOM for an archive. Each archive ships a CycloneDX
#    SBOM (<archive>.sbom.json) signed with the same keyless identity and
#    carried in its own .cosign.bundle:
cosign verify-blob \
  --bundle ocu-rclone-filestore_<ver>_linux_amd64.tar.gz.sbom.json.cosign.bundle \
  --certificate-identity-regexp \
    '^https://github.com/Wide-Moat/ocu-rclone-filestore/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ocu-rclone-filestore_<ver>_linux_amd64.tar.gz.sbom.json
```

## License

Our files: FSL-1.1-Apache-2.0 — see [LICENSE](./LICENSE); each release
converts to Apache-2.0 two years after publication. Code derived from
upstream rclone remains under rclone's MIT license with attribution preserved
(see NOTICE when the fork lands). `LICENSE-APACHE` / `LICENSE-MIT` are
dependency reference texts.
