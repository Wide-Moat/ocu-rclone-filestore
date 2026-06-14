#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Documentation anti-slop gate. Fails when committed Markdown carries the
# mechanical tells of machine-generated "slop" docs — technically accurate,
# unreadable. These are the deterministic, false-positive-free signals; the
# fuzzier judgments (a template stamped on every package, a fact restated three
# times) are left to human review, not gated here.
#
# What it flags:
#   1. A parenthesized file-with-line-number citation in PROSE — `(ocufs.go:315)`,
#      `(ocufs.go:315:8)`, `(ocufs.go:315-320)`. A reader navigates by NAME, not
#      coordinate; a line number welded onto a clause is the loudest slop signal
#      and rots on the next refactor. Cite the identifier instead: "absPath
#      canonicalizes every wire path." (Citations inside code blocks are exempt —
#      there they are example output, not prose.)
#   2. Mermaid `Note over` INSIDE A ```mermaid FENCE. `Note over A,B: ...` is
#      valid, GitHub-rendered Mermaid; this project standardizes on the
#      directional `Note right of` / `Note left of` form for a consistent diagram
#      voice, so `Note over` is flagged as a house-style deviation, not a
#      rendering defect.
#   3. A `;` inside a Mermaid `Note` line. A literal `;` terminates a Mermaid
#      statement and truncates the note; use a dash.
#
# Rules 2 and 3 run on the RAW fenced content (real Mermaid only ever lives
# inside a ```mermaid fence on GitHub), and fire ONLY inside such a fence so the
# ordinary word "note" in prose never matches. Rule 1 runs on fence-stripped
# content so a coordinate in example output is not mistaken for prose.
#
# What it deliberately does NOT flag (these are correct, per the doc standard):
#   - A `Code:` footer line naming files without line numbers:
#     `Code: ocufs.go (absPath, cleanPath), object.go (Open).`
#   - A `Source` column in a table naming a file.
#   - A bare filename in prose (`errors.go`) — that is a name, not a coordinate.
#   - Anything inside a fenced (``` or ~~~) or 4-space/tab-indented code block,
#     which is example output or a literal, not prose.
#
# Scope: git-tracked Markdown only (the same discipline the other gate scripts
# use), so the check is identical in any checkout and never reaches untracked
# local scratch directories.
#
# Modes:
#   (default)  scan the working tree — used by CI and ad-hoc runs.
#   --staged   scan staged content from the index — used by a pre-commit hook.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

MODE="worktree"
if [[ "${1:-}" == "--staged" ]]; then
  MODE="staged"
fi

# A parenthesized source-file citation carrying a line number, optionally with a
# column (:NN:CC) or a line range (:NN-MM) — the forms gofmt/govet/staticcheck
# themselves print. A bare `(ocufs.go)` (no line number) is allowed; only the
# brittle coordinate is the slop tell.
LINEREF_RE='\([A-Za-z0-9_./-]+\.(go|sh|ya?ml|json|md):[0-9]+([:-][0-9]+)?\)'
NOTE_OVER_RE='Note over'
NOTE_SEMICOLON_RE='Note (right|left) of[^:]*:[^;]*;'

# Read a file's content for scanning, honouring the mode (working tree vs the
# staged blob from the index).
read_content() {
  local path="$1"
  if [[ "${MODE}" == "staged" ]]; then
    git show ":${path}" 2>/dev/null || true
  else
    cat "${path}"
  fi
}

# Blank out non-prose so a coordinate in example output is not read as prose.
# Toggles on backtick AND tilde fences; also blanks CommonMark indented code
# blocks (a line starting with 4 spaces or a tab). Line numbers are preserved
# (blanked lines become empty) so reporting stays accurate. Used for RULE 1.
strip_code() {
  awk '
    /^[[:space:]]*(```|~~~)/ { infence = !infence; print ""; next }
    infence                  { print ""; next }
    /^(    |\t)/             { print ""; next }   # indented code block
    { print }
  '
}

# Keep ONLY the lines inside a ```mermaid fence; blank everything else. This is
# the inverse of strip_code and is used for RULES 2 and 3: real Mermaid lives
# inside a mermaid fence, and restricting the match to that fence means the
# literal word "note" in ordinary prose can never trip the rule. The opening
# ```mermaid line and the closing fence are themselves blanked.
mermaid_only() {
  awk '
    !inmermaid && /^[[:space:]]*```[[:space:]]*mermaid[[:space:]]*$/ { inmermaid = 1; print ""; next }
    inmermaid && /^[[:space:]]*```[[:space:]]*$/                     { inmermaid = 0; print ""; next }
    inmermaid { print; next }
    { print "" }
  '
}

violations=0
report() {
  # $1 = file, $2 = rule label, $3 = newline-separated line numbers
  local file="$1" label="$2" linenos="$3"
  while IFS= read -r ln; do
    [[ -z "${ln}" ]] && continue
    echo "  ${file}:${ln}  [${label}]"
    violations=$((violations + 1))
  done <<< "${linenos}"
}

# Collect the tracked Markdown files. In --staged mode, only files staged in the
# index matter; in worktree mode, every tracked .md.
if [[ "${MODE}" == "staged" ]]; then
  mapfile -t md_files < <(git diff --cached --name-only --diff-filter=ACM -- '*.md')
else
  mapfile -t md_files < <(git ls-files '*.md')
fi

for f in "${md_files[@]}"; do
  [[ -z "${f}" ]] && continue
  if [[ "${MODE}" != "staged" && ! -f "${f}" ]]; then
    continue
  fi
  raw="$(read_content "${f}")"

  # Rule 1: line-number citation in prose (code blocks blanked).
  prose="$(printf '%s\n' "${raw}" | strip_code)"
  linenos="$(printf '%s\n' "${prose}" | grep -nE "${LINEREF_RE}" | cut -d: -f1 || true)"
  [[ -n "${linenos}" ]] && report "${f}" "line-ref-in-prose" "${linenos}"

  # Rules 2 and 3: Mermaid Note style, only inside a ```mermaid fence.
  mermaid="$(printf '%s\n' "${raw}" | mermaid_only)"
  linenos="$(printf '%s\n' "${mermaid}" | grep -nE "${NOTE_OVER_RE}" | cut -d: -f1 || true)"
  [[ -n "${linenos}" ]] && report "${f}" "mermaid-note-over" "${linenos}"
  linenos="$(printf '%s\n' "${mermaid}" | grep -nE "${NOTE_SEMICOLON_RE}" | cut -d: -f1 || true)"
  [[ -n "${linenos}" ]] && report "${f}" "mermaid-note-semicolon" "${linenos}"
done

if [[ ${violations} -gt 0 ]]; then
  echo "error: documentation anti-slop gate found ${violations} issue(s):" >&2
  echo "" >&2
  echo "  - line-ref-in-prose:      cite the identifier by NAME, not a (file.go:NN) coordinate." >&2
  echo "  - mermaid-note-over:      use 'Note right of' / 'Note left of' (this project's diagram voice)." >&2
  echo "  - mermaid-note-semicolon: replace the ';' inside the Note with a dash." >&2
  echo "" >&2
  echo "See the documenting-code standard: cite names, not line numbers." >&2
  exit 1
fi

echo "ok: no documentation slop tells in tracked Markdown."
