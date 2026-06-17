<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Storage egress edge (Envoy)

`envoy.yaml` is the deployment artifact for the storage leg's egress edge. It
expresses, in stock Envoy filters, the chain a guest's weak session token must
pass through before any request reaches the filestore upstream:

1. **Validate** — `envoy.filters.http.jwt_authn` validates the inbound weak
   session JWT. The verification key set is fetched from the control-plane's
   published JWKS via `remote_jwks` (no key material lives in the config). The
   issuer and audiences are pinned; a missing or invalid token draws 401 before
   any later filter runs.
2. **Strip** — the same provider sets `forward: false`, so the weak JWT is
   removed from the request after a successful validation. Nothing downstream —
   in particular the filestore upstream — ever sees it.
3. **Exchange + inject** — `envoy.filters.http.credential_injector` performs the
   RFC-8693 token exchange and injects the resulting real filestore credential
   on `Authorization` in place of the stripped weak JWT. The exchange is keyed
   on the validated `filesystem_id` (ratified decision #3: `credential_injector`
   with a per-`filesystem_id` keyed lookup, **not** `ext_proc`). The keyed
   mapping is OCU configuration/code driving the injector's credential source;
   Envoy itself stays stock.
4. **Route** — `envoy.filters.http.router` routes the now-credentialled request
   to the filestore upstream cluster.

## Validation status

Validated with **real Envoy v1.31.10** (`envoy --mode validate`):

- The full config with the `credential_injector` filter elided validates
  cleanly: the listener, the `jwt_authn` provider with `remote_jwks` and
  `forward: false`, the route table, the router, and both TLS upstream clusters
  all load under real Envoy (`configuration ... OK`, 2 clusters, 1 listener).
- The `credential_injector` filter message is itself recognized and
  proto-validated by real Envoy (it is a work-in-progress extension in 1.31 and
  emits the corresponding WIP warning).

**Deferred to the Phase F live run:** the `generic` injected-credentials source
descriptor
(`envoy.extensions.injected_credentials.generic.v3.Generic`) is compiled into
the binary but is not resolvable in the minimal image's config-validation
descriptor pool, so `--mode validate` cannot type-resolve that one nested
`typed_config` ahead of a live serving build. The keyed exchange→inject
behaviour is **proven by the chain harness** today
(`test/harness/edgeglue` + the swap test in `test/harness/edgeswap`); the same
behaviour is to be re-proven against a live serving Envoy in Phase F.

## What is proven where

- **Proven by harness (now):** validate → strip → RFC-8693 exchange → inject;
  the forwarded `Authorization` is the real exchanged credential, not the
  inbound weak JWT; the filestore never sees the weak JWT; a missing/invalid
  token is rejected before the filestore; a foreign-scope token is denied.
- **Proven by real-Envoy `--mode validate` (now):** the listener, the
  `jwt_authn` + `remote_jwks` + `forward: false` provider, the route table, the
  router, and the TLS clusters.
- **Deferred to real Envoy in Phase F:** the live serving of the keyed
  `credential_injector` generic source against a running control-plane,
  exchange, and filestore.
