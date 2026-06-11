#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert the vendored mount-config schema is byte-identical to the canonical
# source. When the canonical checkout is absent (hermetic CI), skip with a
# notice and exit 0; never fail a build for a missing canon checkout.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDORED="${REPO_ROOT}/internal/contract/testdata/mount-config.schema.json"

# The canon location comes only from the environment; there is no default
# path. An unset variable is a hermetic run, not an error.
CANON_ROOT="${OCU_ARCH_REPO:-}"

if [[ ! -f "${VENDORED}" ]]; then
  echo "error: vendored schema missing at ${VENDORED}" >&2
  exit 1
fi

if [[ -z "${CANON_ROOT}" ]]; then
  echo "notice: OCU_ARCH_REPO is unset; skipping parity check (hermetic run). Set it to the architecture repo checkout to enable."
  exit 0
fi

CANON="${CANON_ROOT}/contracts/storage/mount-config.schema.json"

if [[ ! -f "${CANON}" ]]; then
  echo "notice: canonical schema source absent at ${CANON}; skipping parity check (hermetic run)."
  exit 0
fi

if cmp -s "${CANON}" "${VENDORED}"; then
  echo "ok: vendored schema is byte-identical to canon at ${CANON}."
  exit 0
fi

echo "error: vendored schema differs from canon. Refresh it from source and re-run:" >&2
echo "  cp '${CANON}' '${VENDORED}'" >&2
diff -u "${CANON}" "${VENDORED}" >&2 || true
exit 1
