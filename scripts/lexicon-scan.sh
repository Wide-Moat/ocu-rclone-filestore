#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Lexicon naming gate. Reads a newline-separated term list from the
# LEXICON_DENYLIST environment variable and fails if any term appears in the
# tree. The term list itself is never committed: it lives only in the
# environment (a repository secret in CI), is read here, and is never echoed
# to stdout/stderr or written to disk. On a hit, only the matching file path
# is reported — never the matched value.
#
# Behavior contract:
#   - LEXICON_DENYLIST empty or unset -> skip-with-notice to stderr, exit 0
#     (do NOT fail closed: an unset secret is a configuration state, not a hit).
#   - LEXICON_DENYLIST set            -> case-insensitive search over the tree
#     (excluding .git); any hit -> report matching path(s) only, exit 1.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# An optional first argument narrows the search root (used by the local test);
# defaults to the repository root.
SCAN_ROOT="${1:-${REPO_ROOT}}"

if [[ -z "${LEXICON_DENYLIST:-}" ]]; then
  echo "notice: LEXICON_DENYLIST is empty or unset; skipping lexicon scan." >&2
  exit 0
fi

# Collect the matching file paths without ever emitting the matched term.
# grep is run per term. -F matches the term as a fixed string, never a regular
# expression, so metacharacters in a term cannot change (or break) the match;
# the term is delivered as a pattern file on stdin (-f -) so it never appears
# in the process argv. -I skips binary files, -l prints only paths, -r
# recurses, -i is case-insensitive. The .git directory is excluded.
#
# Exit-code discipline (fail closed): grep exits 0 on a match (a hit), 1 on no
# match (clean), and >=2 on an error. An error must fail the scan — a swallowed
# grep failure would report green over a real hit.
hit_paths=()
while IFS= read -r term; do
  [[ -z "${term}" ]] && continue
  set +e
  paths="$(printf '%s\n' "${term}" | grep -rIilF --exclude-dir=.git -f - "${SCAN_ROOT}" 2>/dev/null)"
  rc=$?
  set -e
  if [[ ${rc} -ge 2 ]]; then
    echo "error: lexicon scan could not evaluate a denylist term (grep exit ${rc}); failing closed. The term value is intentionally not printed." >&2
    exit 1
  fi
  [[ ${rc} -ne 0 ]] && continue
  while IFS= read -r path; do
    [[ -z "${path}" ]] && continue
    hit_paths+=("${path}")
  done <<< "${paths}"
done <<< "${LEXICON_DENYLIST}"

if [[ ${#hit_paths[@]} -gt 0 ]]; then
  # Deduplicate paths; report paths only, never the term value.
  printf '%s\n' "${hit_paths[@]}" | sort -u | while IFS= read -r p; do
    echo "lexicon: denied term matched in file: ${p}" >&2
  done
  echo "error: lexicon scan found denied term(s); see paths above. The term value is intentionally not printed." >&2
  exit 1
fi

echo "ok: lexicon scan found no denied terms."
exit 0
