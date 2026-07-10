#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Lexicon naming gate. Reads a newline-separated term list from the
# LEXICON_DENYLIST environment variable and fails if any term appears in the
# tree. The term list itself is never committed: it lives only in the
# environment (a repository secret in CI), is read here, and is never echoed
# to stdout/stderr or written to disk. On a hit, only the matching file path
# is reported — never the matched value (and in aggregate-only mode, only a
# count of matching files).
#
# Behavior contract:
#   - LEXICON_DENYLIST empty or unset:
#       * LEXICON_REQUIRE_DENYLIST set (non-empty) -> exit 1 with an
#         actionable, term-free message. CI sets this flag so a secretless
#         run (fork PR, Dependabot PR, or a missing repository secret) is a
#         loud red, never a silent green: "no term list available" and "scan
#         passed" are different verdicts and must never share an exit code.
#       * otherwise -> skip-with-notice to stderr, exit 0 (the local-dev
#         default; a developer without the secret is not a CI verdict).
#   - LEXICON_DENYLIST set -> case-insensitive fixed-string search over the
#     tree (excluding .git); any hit -> exit 1.
#       * default: report the deduplicated matching path(s) only, never the
#         matched value.
#       * LEXICON_AGGREGATE_ONLY set (non-empty) -> report ONLY the count of
#         matching files — no paths, no values. For scans over untrusted
#         trees whose FILENAMES are attacker-chosen: echoing a matching path
#         into a public log would let a chosen filename act as a
#         term-membership oracle.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# An optional first argument narrows the search root (used by the local test
# and the fork-advisory workflow); defaults to the repository root.
SCAN_ROOT="${1:-${REPO_ROOT}}"

if [[ -z "${LEXICON_DENYLIST:-}" ]]; then
  if [[ -n "${LEXICON_REQUIRE_DENYLIST:-}" ]]; then
    {
      echo "error: LEXICON_DENYLIST is empty or unset and this run requires it (LEXICON_REQUIRE_DENYLIST is set); failing closed."
      echo "A secretless run cannot prove the tree clean. Likely states and remedies:"
      echo "  - fork pull request: repository secrets are never exposed to fork-triggered runs, so this required check cannot pass on a fork branch (branch protection has no admin bypass). A maintainer must vet the change and re-push the branch in-repo; applying the 'lexicon-fork-scan' label first gives an advisory aggregate verdict on the fork content."
      echo "  - Dependabot pull request: Dependabot-triggered runs read the separate Dependabot secrets store; mirror LEXICON_DENYLIST into it (Settings -> Secrets and variables -> Dependabot), then re-run this check."
      echo "  - same-repo branch: the LEXICON_DENYLIST repository secret is missing; restore it, then re-run this check."
    } >&2
    exit 1
  fi
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
  hit_count="$(printf '%s\n' "${hit_paths[@]}" | sort -u | wc -l | tr -d '[:space:]')"
  if [[ -n "${LEXICON_AGGREGATE_ONLY:-}" ]]; then
    # Aggregate-only: the verdict and a coarse count, nothing else. Paths are
    # withheld because on an untrusted tree the filenames themselves are
    # attacker-chosen and a per-path report would be a membership oracle.
    echo "error: lexicon scan found denied term(s) in ${hit_count} matching file(s). Aggregate-only mode: paths and term values are intentionally not printed." >&2
    exit 1
  fi
  # Deduplicate paths; report paths only, never the term value.
  printf '%s\n' "${hit_paths[@]}" | sort -u | while IFS= read -r p; do
    echo "lexicon: denied term matched in file: ${p}" >&2
  done
  echo "error: lexicon scan found denied term(s) in ${hit_count} matching file(s); see paths above. The term value is intentionally not printed." >&2
  exit 1
fi

echo "ok: lexicon scan found no denied terms."
exit 0
