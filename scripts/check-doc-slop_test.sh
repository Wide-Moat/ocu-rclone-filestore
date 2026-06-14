#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Self-test for scripts/check-doc-slop.sh. Proves both halves of the gate's
# contract against throwaway fixtures committed to a scratch git repo:
#   (a) each slop tell is detected in the form it actually takes in a real,
#       rendered Markdown doc — line-ref citations (line, line:col, line-range),
#       and Mermaid Note style INSIDE a ```mermaid fence (the only form GitHub
#       renders);
#   (b) the allowed forms are NOT flagged — name-only footers, table sources,
#       bare filenames, and citations inside fenced (``` and ~~~) or indented
#       code blocks, plus the word "note" in ordinary prose.
#
# The script scopes to git-tracked Markdown, so the fixtures are created inside
# a temporary git repo and staged. No network, no dependence on the real tree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="${SCRIPT_DIR}/check-doc-slop.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

cd "${TMP}"
git init -q
git config user.email "test@example.com"
git config user.name "doc slop test"
# The scanner cd's to its own repo root. Run an isolated copy from the scratch
# repo so REPO_ROOT resolves to the scratch tree.
mkdir -p scripts
cp "${SCAN}" scripts/check-doc-slop.sh
chmod +x scripts/check-doc-slop.sh

run_scan() {
  set +e
  out="$(bash scripts/check-doc-slop.sh 2>&1)"
  rc=$?
  set -e
}

write_file() { mkdir -p "$(dirname "$1")"; printf '%b' "$2" > "$1"; }

# ── (a) each slop tell is detected, in its real form ────────────────────────
write_file docs/lineref.md 'absPath canonicalizes the wire path (ocufs.go:315).\n'
write_file docs/lineref-col.md 'see the assignment (ocufs.go:315:8) for the value.\n'
write_file docs/lineref-range.md 'the block (ocufs.go:315-320) does the parse.\n'
# Mermaid Note style must be detected INSIDE a fenced ```mermaid block — the
# only form that renders, and the form the gate must catch.
write_file docs/noteover.md '```mermaid\nsequenceDiagram\n    Note over A,B: this is house-style-banned\n```\n'
write_file docs/notesemi.md '```mermaid\nsequenceDiagram\n    Note right of A: do this; then that\n```\n'
git add -A >/dev/null
run_scan
[[ ${rc} -ne 0 ]] || fail "expected non-zero exit on the slop fixtures, got 0:
${out}"
echo "${out}" | grep -q "docs/lineref.md.*line-ref-in-prose"       || fail "missed (file.go:NN)"
echo "${out}" | grep -q "docs/lineref-col.md.*line-ref-in-prose"   || fail "missed (file.go:NN:CC)"
echo "${out}" | grep -q "docs/lineref-range.md.*line-ref-in-prose" || fail "missed (file.go:NN-MM)"
echo "${out}" | grep -q "docs/noteover.md.*mermaid-note-over"      || fail "missed fenced Mermaid 'Note over'"
echo "${out}" | grep -q "docs/notesemi.md.*mermaid-note-semicolon" || fail "missed ';' in a fenced Mermaid Note"
echo "PASS (a): all slop tells detected in their real (fenced/coordinate) forms"

# ── (b) allowed forms are NOT flagged ───────────────────────────────────────
rm -f docs/lineref.md docs/lineref-col.md docs/lineref-range.md docs/noteover.md docs/notesemi.md
write_file docs/ok-footer.md 'absPath canonicalizes every wire path.\n\nCode: ocufs.go (absPath, cleanPath), object.go (Open).\n'
write_file docs/ok-table.md '| symbol | source | note |\n| --- | --- | --- |\n| absPath | ocufs.go | canonicalizes the path |\n'
write_file docs/ok-bare.md 'The logic lives in errors.go and is tested in errors_test.go.\nA bare (ocufs.go) without a line number is fine, and the word note in prose is fine.\n'
write_file docs/ok-note.md '```mermaid\nsequenceDiagram\n    Note right of Broker: resolves the downloadable prefix\n```\n'
# A coordinate inside a backtick fence, a tilde fence, and an indented code
# block must NOT be flagged — all three are example output, not prose.
write_file docs/ok-fence-backtick.md 'Example output below:\n```\npanic at (ocufs.go:315)\n```\n'
write_file docs/ok-fence-tilde.md 'Example output below:\n~~~text\npanic at (ocufs.go:315)\n~~~\n'
write_file docs/ok-indented.md 'Example output below:\n\n    panic at (ocufs.go:315)\n\nback to prose.\n'
git add -A >/dev/null
run_scan
[[ ${rc} -eq 0 ]] || fail "allowed forms were flagged (rc=${rc}):
${out}"
echo "PASS (b): no false positives (footers, tables, bare names, prose 'note', backtick/tilde/indented code)"

echo "ALL PASS: check-doc-slop.sh detects real-form slop and spares the allowed forms"
