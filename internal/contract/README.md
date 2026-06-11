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
- Copied at commit: `73e82c66a2df834683276ead83aa1571a1476ed0`.

The vendored file keeps its own embedded SPDX header from canon; it is not
edited here. Divergence between this copy and canon is a defect — canon wins,
and any contract change happens in the architecture repo first.

## What the conformance test checks

The schema root is `oneOf[GuestMountConfig, ProvisionMountConfig]`. A document
carrying a provision-side credential marker is a valid `ProvisionMountConfig`,
so validating against the root would accept it. The conformance test therefore
compiles and validates against the `#/$defs/GuestMountConfig` subschema entry
point, never the root — so accept fixtures validate against the guest branch and
a document carrying `auth_token` fails it.

## Refresh procedure

1. Re-copy the file from the canonical source:
   `cp "${OCU_ARCH_REPO:-/Users/nick/open-computer-use}/contracts/storage/mount-config.schema.json" internal/contract/testdata/mount-config.schema.json`
2. Update the "Copied at commit" hash above to the canon `HEAD` at copy time
   (`git -C "${OCU_ARCH_REPO:-/Users/nick/open-computer-use}" rev-parse HEAD`).
3. Re-run the parity check: `bash scripts/check-contract-parity.sh`.
4. Re-run the conformance test: `go test ./internal/contract/`.
