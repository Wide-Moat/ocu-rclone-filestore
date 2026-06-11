#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Local test harness for scripts/lexicon-scan.sh. Verifies both halves of the
# scan's contract without ever using a real denylist term:
#   (a) unset/empty LEXICON_DENYLIST -> exit 0 AND a notice on stderr;
#   (b) a throwaway NON-SECRET token present in a temp file ->
#       exit non-zero AND the token value absent from captured output (no-leak).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="${SCRIPT_DIR}/lexicon-scan.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# ── (a) unset/empty secret -> skip-with-notice, exit 0 ──────────────────────
set +e
out_a="$(LEXICON_DENYLIST= bash "${SCAN}" 2>&1 >/dev/null)"
rc_a=$?
set -e
[[ ${rc_a} -eq 0 ]] || fail "unset secret should exit 0, got ${rc_a}"
echo "${out_a}" | grep -qi "skipping lexicon scan" \
  || fail "unset secret should write a skip notice to stderr"
echo "PASS (a): unset secret exits 0 with a stderr notice"

# ── (b) throwaway token present -> exit non-zero, no-leak ────────────────────
# A deliberately meaningless, non-secret marker. Never a real denylist term.
THROWAWAY="zzqforbiddenmarkerzz"

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_TEST}"' EXIT
printf 'some content with %s embedded\n' "${THROWAWAY}" > "${TMPDIR_TEST}/sample.txt"

set +e
combined_b="$(LEXICON_DENYLIST="${THROWAWAY}" bash "${SCAN}" "${TMPDIR_TEST}" 2>&1)"
rc_b=$?
set -e
[[ ${rc_b} -ne 0 ]] || fail "throwaway-term hit should exit non-zero, got ${rc_b}"

# No-leak: the token value must not appear anywhere in captured output. The
# scan reports the matching path only, never the matched value.
if printf '%s' "${combined_b}" | grep -qF "${THROWAWAY}"; then
  fail "no-leak violated: token value appeared in scan output"
fi
# Sanity: the matching path should be reported.
echo "${combined_b}" | grep -q "sample.txt" \
  || fail "scan should report the matching file path"
echo "PASS (b): throwaway-term hit exits non-zero and never leaks the term value"

echo "ALL PASS: lexicon-scan.sh contract verified"
exit 0
