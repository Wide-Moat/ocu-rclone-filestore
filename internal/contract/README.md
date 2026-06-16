<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Vendored mount-config schema

`testdata/mount-config.schema.json` is a byte-identical copy of the canonical
mount-config schema. The architecture repo holds the canon; this copy backs the
schema-conformance test so the build does not depend on a canon checkout being
present.

## Source

- Canonical repo: the Open Computer Use architecture repo, at
  `contracts/storage/mount-config.schema.json`.
- Copied at commit: `9ec2664d217904d5b0da52cfce97aef0c28c38c0`.

The vendored file keeps its own embedded SPDX header from canon; it is not
edited here. Divergence between this copy and canon is a defect — canon wins,
and any contract change happens in the architecture repo first.

## What the conformance test checks

The schema is a single mount-config shape: one top-level object carrying
`schema_version`, `service_url`, `ca_cert_pem`, and a `mounts` array, where each
mount carries its own `auth_token`, its `filesystem_id`/`memory_store_id` scope,
and its `readonly` posture. The conformance test compiles and validates against
the schema root — so accept fixtures (which hold `auth_token` and `ca_cert_pem`)
validate, and a document that violates a structural rule fails.

## Refresh procedure

Set `OCU_ARCH_REPO` to wherever the architecture repo is checked out; the
parity script and test read the same variable and skip with a notice when it
is unset (hermetic run).

1. Re-copy the file from the canonical source:
   `cp "${OCU_ARCH_REPO}/contracts/storage/mount-config.schema.json" internal/contract/testdata/mount-config.schema.json`
2. Update the "Copied at commit" hash above to the canon `HEAD` at copy time
   (`git -C "${OCU_ARCH_REPO}" rev-parse HEAD`).
3. Re-run the parity check: `bash scripts/check-contract-parity.sh`.
4. Re-run the conformance test: `go test ./internal/contract/`.
