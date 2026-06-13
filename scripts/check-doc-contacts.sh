#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Documentation contact-address gate. Public-facing prose must point readers
# at the project contact (developer@widemoat.ai), never a maintainer's
# personal address. Fails listing any documentation file that carries the
# personal address, with the rewrite to apply.
#
# Scope is documentation only (*.md and docs/). Source files are out of
# scope; the secrets and lexicon gates cover those.
#
# Exemption: CLAUDE.md names the personal address as the committing-identity
# policy (which git author to use), not as a public contact, so it is
# excluded from this gate.
#
# Modes:
#   (default)  scan the working tree — used by CI and ad-hoc runs.
#   --staged   scan the staged content from the index — used by the
#              pre-commit hook so the gate catches exactly what is about to be
#              committed, ignoring unstaged edits.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

MODE="worktree"
if [[ "${1:-}" == "--staged" ]]; then
  MODE="staged"
fi

# The personal address that must not surface in public documentation, and the
# project contact to use instead.
FORBIDDEN="i@yambr.com"
REPLACEMENT="developer@widemoat.ai"

# Documentation files that legitimately name the forbidden address for a
# reason other than public contact, and are therefore not rewritten.
EXEMPT=(
  "CLAUDE.md"
)

is_exempt() {
  local candidate="$1"
  local e
  for e in "${EXEMPT[@]}"; do
    [[ "${candidate}" == "${e}" ]] && return 0
  done
  return 1
}

# List the documentation files in scope, and emit each file's content on
# stdout, depending on the mode. Staged mode reads from the index so the gate
# sees exactly what is being committed; worktree mode reads the files on disk.
list_files() {
  if [[ "${MODE}" == "staged" ]]; then
    git diff --cached --name-only --diff-filter=ACMR -- '*.md' 'docs/**'
  else
    git ls-files '*.md' 'docs/**'
  fi
}

file_content() {
  local f="$1"
  if [[ "${MODE}" == "staged" ]]; then
    git show ":${f}"
  else
    cat "${f}"
  fi
}

hits=()
while IFS= read -r f; do
  [[ -z "${f}" ]] && continue
  is_exempt "${f}" && continue
  while IFS= read -r line; do
    hits+=("${f}:${line}")
  done < <(file_content "${f}" | grep -nF "${FORBIDDEN}" || true)
done < <(list_files)

if [[ ${#hits[@]} -gt 0 ]]; then
  echo "error: documentation must not carry the personal address ${FORBIDDEN}." >&2
  echo "       rewrite it to the project contact ${REPLACEMENT}:" >&2
  printf '  - %s\n' "${hits[@]}" >&2
  exit 1
fi

echo "ok: no documentation file carries ${FORBIDDEN} (CLAUDE.md identity policy exempt)."
exit 0
