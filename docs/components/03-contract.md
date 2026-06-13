<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# `internal/contract` — guest mount-config conformance

This package answers one question about a mount-config document: is it a valid
*guest* config? It validates against the vendored JSON Schema, but pointed at
the guest variant alone — so a config carrying provisioning credentials is
refused as an observable property, not a hope.

## Why the entry point matters

The vendored schema's root is `oneOf[GuestMountConfig, ProvisionMountConfig]`.
The two variants split on credentials: `GuestMountConfig` sets
`additionalProperties: false` and has no `auth_token`; `ProvisionMountConfig`
*requires* `auth_token`. A document with an `auth_token` is therefore a valid
`ProvisionMountConfig` and a valid match for the root `oneOf`. Validating
against the root would silently accept it.

So the validator never compiles the root. It compiles the
`#/$defs/GuestMountConfig` subschema as the validation entry point. Against the
guest branch the same document fails: `auth_token` is an additional property
the guest forbids. That refusal is the contract-level discharge of NFR-SEC-25
(no backend credential reaches the guest), and it is exercised by the
`provision_with_token.json` reject fixture — a document that would pass the
root and must fail here.

Code: `contract.go` (`guestEntryPoint`), `testdata/mount-config.schema.json` (root `oneOf` line 193, `GuestMountConfig` line 106, `ProvisionMountConfig` line 144).

## Using it

`NewGuestValidator(schemaBytes, schemaID)` compiles the guest entry point once;
`Validate(documentBytes)` checks one document and returns `nil` to accept or the
schema library's structured error to reject. `schemaID` must be the schema's own
`$id` — `NewGuestValidator` registers the document under that id, then resolves
the guest fragment relative to it, so a wrong id fails to compile rather than
silently selecting the wrong node. The constructor wraps its failure paths with
distinct messages (`parse vendored schema`, `register vendored schema under`,
`compile guest entry point`); `Validate` returns the library error unwrapped, so
a caller wanting a stable prefix wraps it itself.

## What holds it true

The vendored copy under `testdata/` is byte-identical to the canonical schema in
the architecture repo, which owns the contract — this package validates against
it, never re-decides it. `TestVendoredSchemaParity` checks that byte identity
through `check-contract-parity.sh`, reading the canon location only from
`OCU_ARCH_REPO` and skipping cleanly when it is unset, so a hermetic run stays
green. A green local run with `OCU_ARCH_REPO` unset means the parity check was
*skipped*, not that the copy matches canon.

Two suites guard the behaviour. `TestSchemaConformance` sweeps the `accept/` and
`reject/` fixture directories — accept fixtures must validate against the guest
branch, reject fixtures must fail it — and fails on an empty directory so the
suite cannot pass by losing its inputs. `TestLoaderSchemaParity` feeds every
fixture (this package's sets plus the loader's own testdata) through both
`mountcfg.Load` and `Validate` and fails if the two reach different verdicts: a
document the schema rejects but the loader accepts is a divergence, the reverse
silently narrows the contract. It also pins the expected shared verdict per
fixture, so both halves cannot drift together unnoticed.

Adding a new config shape means dropping a `*.json` into the right `accept/` or
`reject/` directory; the sweeps pick it up.
