#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Local test harness for scripts/lexicon-scan.sh. Verifies the scan's contract
# without ever using a real denylist term:
#   (a) unset/empty LEXICON_DENYLIST -> exit 0 AND a notice on stderr;
#   (b) a throwaway NON-SECRET token present in a temp file ->
#       exit non-zero AND the token value absent from captured output (no-leak);
#   (c)/(d) regex-shaped terms are matched as fixed strings, no leak;
#   (e) empty secret + LEXICON_REQUIRE_DENYLIST -> exit non-zero (fail closed);
#   (f) LEXICON_REQUIRE_DENYLIST + secret + clean tree -> exit 0;
#   (g) LEXICON_AGGREGATE_ONLY + a hit -> exit non-zero, output carries a
#       count and NEITHER the matching path NOR the token value.

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

# ── (c) regex-metacharacter terms are matched as fixed strings ───────────────
# A term shaped like an invalid regular expression (unclosed bracket) that is
# literally present must be caught: terms are fixed strings, never patterns,
# and a grep evaluation error must fail the scan rather than report green.
THROWAWAY_BRACKET="foo[bar"
printf 'content with %s literally embedded\n' "${THROWAWAY_BRACKET}" \
  > "${TMPDIR_TEST}/bracket.txt"

set +e
combined_c="$(LEXICON_DENYLIST="${THROWAWAY_BRACKET}" bash "${SCAN}" "${TMPDIR_TEST}" 2>&1)"
rc_c=$?
set -e
[[ ${rc_c} -ne 0 ]] \
  || fail "invalid-regex-shaped term literally present should exit non-zero, got ${rc_c}"
if printf '%s' "${combined_c}" | grep -qF "${THROWAWAY_BRACKET}"; then
  fail "no-leak violated: regex-shaped token value appeared in scan output"
fi
echo "${combined_c}" | grep -q "bracket.txt" \
  || fail "scan should report the matching file path for the regex-shaped term"
echo "PASS (c): invalid-regex-shaped term is caught as a fixed string, no leak"

# ── (d) a star-bearing term matches its literal occurrence ───────────────────
# Under regex semantics 'b*' would never match a literal '*'; fixed-string
# matching must catch the literal occurrence.
THROWAWAY_STAR="zzqab*cdzzq"
printf 'content with %s literally embedded\n' "${THROWAWAY_STAR}" \
  > "${TMPDIR_TEST}/star.txt"

set +e
combined_d="$(LEXICON_DENYLIST="${THROWAWAY_STAR}" bash "${SCAN}" "${TMPDIR_TEST}" 2>&1)"
rc_d=$?
set -e
[[ ${rc_d} -ne 0 ]] \
  || fail "star-bearing term literally present should exit non-zero, got ${rc_d}"
if printf '%s' "${combined_d}" | grep -qF "${THROWAWAY_STAR}"; then
  fail "no-leak violated: star-bearing token value appeared in scan output"
fi
echo "${combined_d}" | grep -q "star.txt" \
  || fail "scan should report the matching file path for the star-bearing term"
echo "PASS (d): star-bearing term is caught as a fixed string, no leak"

# ── (e) empty secret + strict mode -> fail closed with an actionable message ─
set +e
out_e="$(LEXICON_DENYLIST= LEXICON_REQUIRE_DENYLIST=1 bash "${SCAN}" 2>&1)"
rc_e=$?
set -e
[[ ${rc_e} -ne 0 ]] \
  || fail "strict mode with an empty secret should exit non-zero, got ${rc_e}"
echo "${out_e}" | grep -qi "failing closed" \
  || fail "strict mode should state the fail-closed verdict"
echo "${out_e}" | grep -qi "fork pull request" \
  || fail "strict mode should name the fork-PR state and its remedy"
echo "${out_e}" | grep -qi "Dependabot" \
  || fail "strict mode should name the Dependabot secrets-store remedy"
echo "PASS (e): strict mode fails closed on an empty secret with an actionable message"

# ── (f) strict mode + secret + clean tree -> exit 0 ──────────────────────────
CLEAN_DIR="${TMPDIR_TEST}/clean"
mkdir -p "${CLEAN_DIR}"
printf 'clean content, nothing denied here\n' > "${CLEAN_DIR}/clean.txt"
set +e
LEXICON_DENYLIST="${THROWAWAY}" LEXICON_REQUIRE_DENYLIST=1 \
  bash "${SCAN}" "${CLEAN_DIR}" >/dev/null 2>&1
rc_f=$?
set -e
[[ ${rc_f} -eq 0 ]] \
  || fail "strict mode with the secret over a clean tree should exit 0, got ${rc_f}"
echo "PASS (f): strict mode with the secret present passes a clean tree"

# ── (g) aggregate-only mode: a hit reds with a count, no path, no value ──────
set +e
combined_g="$(LEXICON_DENYLIST="${THROWAWAY}" LEXICON_AGGREGATE_ONLY=1 \
  bash "${SCAN}" "${TMPDIR_TEST}" 2>&1)"
rc_g=$?
set -e
[[ ${rc_g} -ne 0 ]] \
  || fail "aggregate-only hit should exit non-zero, got ${rc_g}"
printf '%s' "${combined_g}" | grep -qE 'in [0-9]+ matching file' \
  || fail "aggregate-only output should carry a matching-file count"
if printf '%s' "${combined_g}" | grep -qF "sample.txt"; then
  fail "aggregate-only output must not name a matching path"
fi
if printf '%s' "${combined_g}" | grep -qF "${THROWAWAY}"; then
  fail "no-leak violated: token value appeared in aggregate-only output"
fi
echo "PASS (g): aggregate-only hit reports a count and neither path nor value"

echo "ALL PASS: lexicon-scan.sh contract verified"
exit 0
