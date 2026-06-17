<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# `internal/contract` — guest mount-config conformance

This package answers one question about a mount-config document: does it
conform to the frozen mount-config contract? It validates against the vendored
JSON Schema, compiled at its root, so a document is accepted exactly when it
satisfies the single mount-config shape.

## The shape it validates

The schema is a single flat object (`type: object`). Its required top-level
fields are `schema_version`, `service_url`, `ca_cert_pem`, and `mounts`;
unknown top-level fields are refused (`additionalProperties: false`).
`service_url` must be an `https://` URL, and `ca_cert_pem` must be a PEM
certificate — the inspecting edge's trust anchor the guest holds so it can dial
the egress hop over TLS.

Each entry in the `mounts` array carries its own scoped session token in the
required `auth_token` field — the static `Authorization: Bearer` the mount
presents at the egress edge. The token is a weak, short-lived, edge-only
assertion: the egress edge validates it, strips it, and exchanges it for the
real storage credential keyed on the mount's `filesystem_id`. It is never a
backend or object-store key, and no backend credential ever reaches the guest.

Per mount, the only `oneOf` is the scope choice: exactly one of `filesystem_id`
or `memory_store_id` must be present (a filesystem id XOR a memory store id).
Both-present or neither-present is a hard error. Beyond scope, each mount
requires `destination`, `auth_token`, `readonly`, `vfs_cache_mode`,
`cache_duration_s`, `vfs_cache_max_size`, `dir_perms`, and `file_perms`.

## Using it

`NewGuestValidator(schemaBytes, schemaID)` compiles the schema once and
`Validate(documentBytes)` checks one document, returning `nil` to accept or the
schema library's structured error to reject. `schemaID` must be the schema's
own `$id`: `NewGuestValidator` registers the document under that id and compiles
that root, so a wrong id fails to compile rather than silently selecting a
different node. The constructor wraps its failure paths with distinct messages
(`parse vendored schema`, `register vendored schema under`, `compile vendored
schema`); `Validate` returns the library error unwrapped, so a caller wanting a
stable prefix wraps it itself.

Code: `contract.go` (`NewGuestValidator` compiles `schemaID`),
`testdata/mount-config.schema.json` (root `required` and per-mount `oneOf`).

## What holds it true

The vendored copy under `testdata/` is byte-identical to the canonical schema in
the architecture repo, which owns the contract — this package validates against
it, never re-decides it. `TestVendoredSchemaParity` checks that byte identity
through `check-contract-parity.sh`, reading the canon location only from
`OCU_ARCH_REPO` and skipping cleanly when it is unset, so a hermetic run stays
green. A green local run with `OCU_ARCH_REPO` unset means the parity check was
*skipped*, not that the copy matches canon.

Two suites guard the behaviour. `TestSchemaConformance` sweeps the `accept/` and
`reject/` fixture directories — accept fixtures must validate, reject fixtures
must fail — and fails on an empty directory so the suite cannot pass by losing
its inputs. The accept fixtures are `accept/guest_minimal.json` (a single RW
mount) and `accept/guest_with_readonly.json` (an RW mount plus an RO mount);
the reject fixtures are `reject/both_ids.json` (both scope ids set),
`reject/http_service_url.json` (a non-`https` `service_url`), and
`reject/missing_ca_cert.json` (the trust anchor absent). `TestLoaderSchemaParity`
feeds every fixture (this package's sets plus the loader's own testdata) through
both `mountcfg.Load` and `Validate` and fails if the two reach different
verdicts: a document the schema rejects but the loader accepts is a divergence,
the reverse silently narrows the contract. It also pins the expected shared
verdict per fixture, so both halves cannot drift together unnoticed.

Adding a new config shape means dropping a `*.json` into the right `accept/` or
`reject/` directory; the sweeps pick it up.
