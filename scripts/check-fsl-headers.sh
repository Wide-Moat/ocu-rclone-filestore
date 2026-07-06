#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Authored-file FSL-header gate. Every source file we author must carry the
# FSL SPDX identifier near the top. Fails listing any authored file that is
# missing it.
#
# Exemption: the vendored mount-config schema keeps its own embedded canon
# SPDX header (it is copied byte-identically from the architecture repo and
# must not be rewritten), so it is excluded from this gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

HEADER="SPDX-License-Identifier: FSL-1.1-Apache-2.0"

# Vendored files that carry their own canon SPDX header and must not be
# rewritten to ours.
EXEMPT=(
  "internal/contract/testdata/mount-config.schema.json"
)

is_exempt() {
  local candidate="$1"
  local e
  for e in "${EXEMPT[@]}"; do
    [[ "${candidate}" == "${e}" ]] && return 0
  done
  return 1
}

missing=()
while IFS= read -r f; do
  [[ -z "${f}" ]] && continue
  is_exempt "${f}" && continue
  # Inspect the first lines where a header would sit.
  if ! head -n 10 "${f}" | grep -qF "${HEADER}"; then
    missing+=("${f}")
  fi
done < <(git ls-files '*.go' '*.sh' '*.yml' '*.yaml' 'Dockerfile' '*.Dockerfile')

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "error: the following authored file(s) are missing the FSL header line:" >&2
  echo "  ${HEADER}" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 1
fi

echo "ok: all authored *.go/*.sh/*.yml/*.yaml/Dockerfile files carry the FSL header (vendored schema exempt)."
exit 0
