#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Frozen-contract binding for the vendored mount-config schema. Three legs,
# each with a precisely scoped claim:
#
#   1. Hermetic checksum leg (ALWAYS runs; no network, no environment): the
#      vendored schema's sha256 must match the committed pin file. This proves
#      schema<->pin CONSISTENCY only — it is tamper-EVIDENCE that converts
#      silent drift into a conspicuous multi-file diff; it cannot by itself
#      prove the pinned bytes are canon.
#   2. Canon-ref leg (OCU_CANON_REF_CHECK=1; network): fetch the schema from
#      the public architecture repository at the commit recorded in CANON-REF
#      and byte-compare. This proves the vendored bytes exist at that named
#      public canon commit, so arbitrary non-canon bytes cannot pass.
#   3. Deep leg (OCU_ARCH_REPO set): byte-compare against a local canon
#      checkout, for machines that have one.
#
# Residual, by design: a single change that re-records the schema, the pin,
# and CANON-REF together can still move the vendored copy to a DIFFERENT real
# canon-history state. Freeze AUTHORITY therefore rests on review of
# contract-touching diffs; these legs make such a change loud, not impossible.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTDATA="${REPO_ROOT}/internal/contract/testdata"
VENDORED="${TESTDATA}/mount-config.schema.json"
PIN_FILE="${VENDORED}.sha256"
REF_FILE="${TESTDATA}/CANON-REF"
CANON_RAW_BASE="https://raw.githubusercontent.com/Wide-Moat/open-computer-use"
CANON_SCHEMA_PATH="contracts/storage/mount-config.schema.json"

if [[ ! -f "${VENDORED}" ]]; then
  echo "error: vendored schema missing at ${VENDORED}" >&2
  exit 1
fi

# ── Leg 1: hermetic checksum pin (always) ────────────────────────────────────

sha256_of() {
  # Portable digest: sha256sum on Linux, shasum -a 256 where sha256sum is
  # absent (macOS). Either way only the hex digest is emitted.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [[ ! -f "${PIN_FILE}" ]]; then
  echo "error: checksum pin file missing at ${PIN_FILE}; the frozen-contract gate cannot run without it." >&2
  exit 1
fi

want="$(awk 'NR==1 {print $1}' "${PIN_FILE}")"
got="$(sha256_of "${VENDORED}")"
if [[ "${got}" != "${want}" ]]; then
  echo "error: vendored schema sha256 does not match the committed pin." >&2
  echo "  pinned: ${want}" >&2
  echo "  actual: ${got}" >&2
  echo "If the frozen contract was deliberately refreshed from canon, re-record" >&2
  echo "BOTH the pin file and CANON-REF in the same commit, stating the canon" >&2
  echo "commit the new copy is blessed against. Any other cause is drift." >&2
  exit 1
fi
echo "ok: vendored schema matches the committed sha256 pin."

# ── Leg 2: canon-ref binding (network; opt in with OCU_CANON_REF_CHECK=1) ────

if [[ "${OCU_CANON_REF_CHECK:-}" == "1" ]]; then
  if [[ ! -f "${REF_FILE}" ]]; then
    echo "error: CANON-REF missing at ${REF_FILE}; the canon-ref leg cannot run without it." >&2
    exit 1
  fi
  ref="$(tr -d '[:space:]' < "${REF_FILE}")"
  if [[ ! "${ref}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: CANON-REF must hold one full 40-hex commit SHA; got '${ref}'." >&2
    exit 1
  fi
  fetched="$(mktemp)"
  trap 'rm -f "${fetched}"' EXIT
  if ! curl -fsSL --retry 3 --connect-timeout 10 --max-time 60 "${CANON_RAW_BASE}/${ref}/${CANON_SCHEMA_PATH}" -o "${fetched}"; then
    echo "error: could not fetch the canon schema at commit ${ref} from the public architecture repository; failing closed (an unreachable pin is a re-bless signal, not a pass)." >&2
    exit 1
  fi
  if ! cmp -s "${fetched}" "${VENDORED}"; then
    echo "error: vendored schema differs from canon at the pinned commit ${ref}." >&2
    echo "Refresh the vendored copy from canon and re-record the pin file and" >&2
    echo "CANON-REF in the same commit, or fix the vendored copy back to the" >&2
    echo "blessed bytes." >&2
    diff -u "${fetched}" "${VENDORED}" >&2 || true
    exit 1
  fi
  echo "ok: vendored schema is byte-identical to canon at the pinned commit ${ref}."
fi

# ── Leg 3: deep parity against a local canon checkout (OCU_ARCH_REPO) ────────

CANON_ROOT="${OCU_ARCH_REPO:-}"
if [[ -n "${CANON_ROOT}" ]]; then
  CANON="${CANON_ROOT}/${CANON_SCHEMA_PATH}"
  if [[ ! -f "${CANON}" ]]; then
    echo "notice: canonical schema source absent at ${CANON}; deep parity leg skipped (the checksum and canon-ref legs enforce)."
  elif cmp -s "${CANON}" "${VENDORED}"; then
    echo "ok: vendored schema is byte-identical to the local canon checkout at ${CANON}."
  else
    echo "error: vendored schema differs from the local canon checkout. Refresh it from source and re-record the pin and CANON-REF:" >&2
    echo "  cp '${CANON}' '${VENDORED}'" >&2
    diff -u "${CANON}" "${VENDORED}" >&2 || true
    exit 1
  fi
fi

exit 0
