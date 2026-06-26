# Constitution — guest-side rclone FUSE mount

> The canonical source for behaviour is the architecture repository's frozen
> contracts (`contracts/storage/`) and NFR rows (`manifesto/`). This document
> restates the component's load-bearing invariants as facts derived from those
> contracts and NFRs; it does not re-decide them.

This is the "never" spine of the guest-side rclone FUSE mount. Every invariant
below cites its guard and its verification state. An invariant is presented as
**ENFORCED** only when a mutation of the guard was applied and a test went
**RED**; anything weaker is stated honestly as such.

## What this component is

The guest-side rclone FUSE mount binary exposes a per-session filesystem inside
the guest by mounting an rclone backend that speaks **outbound HTTPS/REST** to
the storage edge. Each mount carries a single weak, scoped, short-lived
**session JWT** that the guest presents as a static `Authorization: Bearer`.
The inspecting Envoy edge **validates that token, strips it, and exchanges it**
for the real backend storage credential keyed on `filesystem_id`. The guest
therefore holds **no backend credential**, runs **no object-store client**, and
has **no second transport** — its only handle on storage is the session-scoped
`filesystem_id`.

## Verification states

- **ENFORCED** — a mutation of the guard was applied and a test went RED.
- **ENFORCED-by-absence-grep** — the only guard is a negative grep; there is no
  RED-on-mutation test. Real posture, but not mutation-proven. Stated as such.
- **amd64-CI-only** — kernel-enforced behaviour binding only on the amd64 CI
  runner; the arm64 dev host cannot prove it.

A guard whose test stays GREEN under mutation pins nothing. Kernel-network and
kernel-isolation claims (AppArmor inet mediation, seccomp filtering, PID-namespace
isolation, image-rootfs EROFS, effective-capability set) are amd64-CI-bound; a
local arm64 pass is not evidence for them. Compose-content pins are
arch-independent.

---

## Data-path and credential invariants

### 1. The guest must never set `downloadable=true` — ENFORCED

The perimeter-exit decision is broker-resolved, never guest-enforced. The guest
stamps `downloadable=false` and nothing else.

- **Guard:** `internal/brokerrpc/intent.go:87` — `StampAuthMeta` hardcodes
  `Downloadable: false` as the sole write site for that field.
- **Mutation → RED:** flipping `false` → `true` makes 18 per-op tests RED and a
  committed source-scan test RED.
- **Canon tie:** NFR-SEC-73 (downloadable is broker-resolved; the mount never
  enforces it).

### 2. A mount must never carry both or neither scope id — ENFORCED

`filesystem_id` XOR `memory_store_id` — exactly one. A config of any other shape
is rejected before it can take effect.

- **Guard:** `internal/mountcfg/mountcfg.go:146-150` — presence-keyed XOR;
  `hasFS == hasMem` returns `&ErrMountScope{...}` (exported type `ErrMountScope`,
  at `mountcfg.go:149`). The separate present-but-empty-id checks at
  `mountcfg.go:151-156` return `ErrScopeID`.
- **Mutation → RED:** changing `==` → `!=` makes the both-ids, neither-id, and
  empty-variant cases RED.
- **Canon tie:** the mount-config single-shape contract
  (`contracts/storage/mount-config.schema.json`: scope is XOR).

### 3. The guest must never mint, sign, or refresh a token — ENFORCED

The guest forwards the static session JWT unmodified and holds no backend
credential. It is a presenter, not an issuer.

- **Guard:** `internal/brokerrpc/client.go:108` — `setAuthHeader` sets
  `Authorization = "Bearer " + c.authToken`, forwarded verbatim.
- **Mutation → RED:** appending to the Bearer value makes
  `TestClientSetsContentTypeAndBearer`
  (`internal/brokerrpc/client_test.go:79`) RED.
- **Canon tie:** NFR-SEC-25 (no backend protocol or credential in the guest);
  the edge validates, strips, and exchanges the token.

### 4. The guest must never have a direct network path to the backend — ENFORCED

Every byte to storage traverses the inspecting edge. No second transport, no
bypass.

- **Guard:** `deploy/compose/docker-compose.yml:286-287` — the mount service is
  attached to the `mount-facing` network only, with no `edge-backend` membership,
  so the guest has no L3 route to the filestore. The filestore in turn sits on
  `edge-backend` only (`docker-compose.yml:208-209`). Plus the e2e
  `TestEnvoyOnlyHop`.
- **Mutation → RED:** giving the mount a route to a live filestore listener makes
  `TestEnvoyOnlyHop` RED.
- **Canon tie:** NFR-SEC-25 (no backend protocol in the guest); the mount never
  bypasses the edge.

### 5. A memory-store mount must never silently proceed — ENFORCED (both sites)

A memory-store scope must be a hard error in the mount path; it must not fall
through and quietly mount.

- **Guard (two sites, both ENFORCED):**
  - **site-1** `internal/mounter/options.go:108` — the fixture in
    `internal/mounter/options_test.go::TestBuildOcufsConfigmapMemoryStoreIsHardError`
    carries a valid `filesystem_id` and asserts the error names the memory-store
    axis, so neutering this site alone goes RED. (Previously this was a
    composite-masking vacuous guard, fixed by adding the discriminating fixture.)
  - **site-2** the mountcfg loader — mutating the condition makes the harness
    test RED.
- **Canon tie:** the mount-config single-shape contract; a memory-store scope is
  a build-time hard stop in this guest.

### 6. The guest must never emit audit nor implement audit fail-closed logic — ENFORCED-by-absence-grep

File-op audit authorship is host-side. The guest neither produces audit events
nor fails closed on audit.

- **Guard:** a negative grep over `internal/` + `cmd/`. There is **no committed
  source-scan test** that goes RED when an audit-emit call is added — so this is
  **ENFORCED-by-absence-grep, not a mutation-RED CHECK**. The grep is
  vacuous-by-design: it catches an audit path only when re-run by hand and stays
  GREEN otherwise. To promote it to a true CHECK, add a committed source-scan
  test that goes RED on an injected audit-emit call, as item 1 already has.
- **Canon tie:** audit durability is a host-side concern (NFR-SEC-79);
  host-derived attribution per NFR-SEC-43.

---

## FUSE-hardening posture controls

The six levers are declared once in a shared compose anchor (`x-mount-posture`)
and merged by both the mount service and the same-image posture-probe witness, so
the witnessed posture cannot drift from the live mount. The compose-content pins
are arch-independent and go RED on mutation regardless of host. The
kernel-enforced subset — image-rootfs EROFS, effective-capability set, AppArmor
inet mediation, narrow-seccomp serve path — binds only on the amd64 CI runner.

### Single-source posture anchor — ENFORCED

- **Guard:** `test/posture/compose_posture_test.go::TestMountMergesPostureAnchor`
  (`compose_posture_test.go:153`) asserts the `x-mount-posture` anchor exists, is
  merged by ≥2 services (mount + posture-probe witness), and that the mount
  service carries no inline `cap_drop`/`cap_add`/`security_opt`/`read_only`/
  `tmpfs` key that would shadow the anchor.
- **Mutation → RED:** dropping a merge reference, or re-declaring any posture key
  inline on the mount service, goes RED.

### 7. AppArmor named enforce profile (never `unconfined`) — ENFORCED

- **Guard:** `test/posture/compose_posture_test.go::TestMountAppArmorIsNarrowNotUnconfined`
  asserts `security_opt` carries `apparmor=ocu-mount` and never `unconfined`.
- **Mutation → RED:** `ocu-mount` → `unconfined` goes RED.
- **Scope:** pins compose content. The inet-mediation kernel sub-rules bind on
  amd64 CI only.

### 8. `cap_drop: ALL` + single `cap_add: SYS_ADMIN` — ENFORCED

- **Guard (content):** `test/posture/compose_posture_test.go::TestMountCapabilitiesDropAllAddOnlySysAdmin`
  asserts `cap_drop == [ALL]` AND `cap_add == [SYS_ADMIN]` exactly.
- **Mutation → RED:** adding any extra capability goes RED.
- **amd64 runtime binding:** `test/e2e/mount_runtime_posture_test.go::TestMountRuntimePosture/capeff_only_sys_admin`
  reads the effective capability set via procfs and asserts `CapEff` is
  `CAP_SYS_ADMIN` only.

### 9. `no-new-privileges: true` — ENFORCED

- **Guard:** `test/posture/compose_posture_test.go::TestMountNoNewPrivileges`.
- **Mutation → RED:** deleting the line goes RED.

### 10. `read_only` rootfs + tmpfs `/root/.cache` — ENFORCED

The image rootfs must never be writable; the VFS cache tmpfs is load-bearing.

- **Guard (content):** `test/posture/compose_posture_test.go::TestMountReadOnlyRootWithCacheTmpfs`.
- **Mutation → RED:** removing `read_only: true` goes RED.
- **amd64 runtime binding:** `test/e2e/mount_runtime_posture_test.go::TestMountRuntimePosture/image_rootfs_read_only`
  writes to an image-rootfs path and asserts EROFS; `/tmpfs_cache_writable`
  asserts the cache tmpfs stays writable.

### 11. Narrow seccomp (default-ERRNO + deliberate adds) — ENFORCED

Never broaden the default to ALLOW, nor drop the deliberate
`{mount, umount2, clone, clone3}` adds.

- **Guard (content):** `test/posture/seccomp_test.go::TestSeccompDefaultActionDenies`
  asserts `defaultAction == SCMP_ACT_ERRNO`; `TestSeccompAllowsDeliberateSyscalls`
  asserts the deliberate adds are present.
- **Mutation → RED:** default → ALLOW goes RED; removing `mount`/`umount2` goes
  RED.
- **Scope:** the serve-path-not-over-tightened binding (the narrow set does not
  break the FUSE serve path) is amd64 CI live-e2e.

### 12. Private PID namespace on the mount service — ENFORCED

Never give the mount service `pid: host`. The test-runner deliberately keeps
`pid: host` for teardown; that asymmetry is intentional.

- **Guard (content):** `test/posture/compose_posture_test.go::TestMountKeepsPrivatePIDNamespace`
  (`compose_posture_test.go:238`) asserts the mount service carries no `pid:`
  override — the compose-default private PID namespace. Any non-empty `pid` value
  (`host`, `service:*`, `container:*`) goes RED.
- **amd64 runtime binding:** the live-e2e teardown step on amd64 CI reaps a mount
  service that cannot see host PIDs; giving the mount `pid: host` fails the
  isolation assertion in that step.

---

## Quality gate

### 13. Authored-package coverage must never regress below 90% — ENFORCED

- **Guard:** `.coverage-floor:1` (value `90.00`), enforced by
  `internal/coverage/coverage_test.go`.
- **Mutation → RED:** changing the floor (`90` → `50`, or `90` → `95`) against a
  fixed profile flips the gate RED both ways.
- **Canon tie:** repo quality gate (coverage floor, ratcheted to 90).

---

## Status tally

Thirteen numbered invariants plus the single-source posture anchor:

- **ENFORCED (mutation-RED proven):** 13 — invariants 1, 2, 3, 4, 5, 7, 8, 9,
  10, 11, 12, 13, and the single-source posture anchor.
- **ENFORCED-by-absence-grep (caveated, not mutation-RED):** 1 — invariant 6.

The kernel-enforced subset of the posture controls (invariants 8, 10, 11, 12)
binds on the amd64 CI runner only; the compose-content pins are arch-independent.
