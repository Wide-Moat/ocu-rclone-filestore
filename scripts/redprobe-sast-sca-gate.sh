#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the SAST/SCA gate: prove semgrep and trivy redden on planted defects.
#
# Both are required contexts and neither has ever been shown to fail. This runs
# the commands sast.yml and sca.yml run -- same image references, same flags --
# against two trees and asserts opposite outcomes for each scanner:
#
#   clean = the committed tree at REF, untouched   -> expect a pass
#   dirty = that same tree plus planted defects    -> expect a failure
#
# Unlike the secrets gate, these two scanners read the CHECKED-OUT TREE rather
# than commit history, so reconstructing the tree with `git archive` is the
# faithful construction here -- it is exactly what the runner's checkout leaves
# on disk. (The secrets probe must clone real history instead, because its
# scanners walk diffs. The two gates need different constructions for the same
# reason: match what the scanner actually reads.)
#
# Planted defects, one per detector class:
#   semgrep -- a Go file using math/rand, MD5, and a non-constant exec.Command
#   trivy   -- a go.mod requiring a dependency with a known fixed HIGH advisory
#
# Usage: scripts/redprobe-sast-sca-gate.sh [--ref REF] [--keep]
# Exit 0 only when both scanners behaved correctly in both directions.

set -uo pipefail

REF="origin/main"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Image references byte-identical to the workflows. semgrep is referenced by
# tag there rather than by digest; the probe mirrors the gate exactly rather
# than hardening it silently, so the two cannot drift apart unnoticed.
SEMGREP_IMAGE='semgrep/semgrep:1.97.0'
TRIVY_IMAGE='ghcr.io/aquasecurity/trivy@sha256:de90a656e79b175a294abe85cb8b99670fab83ebf339cccd163e6f584846809a'

PLANTED_GO='probe_planted/weak.go'
PLANTED_MOD='probe_planted/go.mod'

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
git rev-parse --verify "$REF" >/dev/null 2>&1 || { echo "no such ref: $REF" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() { if [ "$KEEP" -eq 1 ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT

mkdir -p "$WORK/clean" "$WORK/dirty"
git archive "$REF" | tar -x -C "$WORK/clean"
cp -R "$WORK/clean/." "$WORK/dirty/"
echo "info scanned tree: $(find "$WORK/clean" -type f | wc -l | tr -d ' ') files from $REF"

plant() {
  mkdir -p "$WORK/dirty/probe_planted"
  cat > "$WORK/dirty/$PLANTED_GO" <<'GOEOF'
package planted

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"os/exec"
)

func WeakHash(s string) string { return fmt.Sprintf("%x", md5.Sum([]byte(s))) }
func WeakToken() int           { return rand.Int() }
func RunIt(userInput string) error {
	return exec.Command("sh", "-c", userInput).Run()
}
GOEOF
  cat > "$WORK/dirty/$PLANTED_MOD" <<'MODEOF'
module probeplanted

go 1.24

require github.com/gogo/protobuf v1.3.1
MODEOF
}
plant

run_semgrep() {
  docker run --rm --platform linux/amd64 -v "$WORK/$1:/src" -w /src "$SEMGREP_IMAGE" \
    semgrep scan --config=auto --config=p/golang --config=p/security-audit \
    --severity=ERROR --severity=WARNING --error --quiet > "$WORK/semgrep.$1.out" 2>&1
  echo $?
}
run_trivy() {
  docker run --rm --platform linux/amd64 -v "$WORK/$1:/repo" "$TRIVY_IMAGE" \
    filesystem --scanners vuln --severity CRITICAL,HIGH --exit-code 1 \
    --ignore-unfixed=false --no-progress /repo > "$WORK/trivy.$1.out" 2>&1
  echo $?
}

fail=0
note() { echo "$1"; }

# Delivery: assert the planted files are in the tree each scanner will read.
# Asserted directly rather than inferred from a scanned-size delta, which drifts
# for reasons unrelated to whether the payload arrived.
for p in "$PLANTED_GO" "$PLANTED_MOD"; do
  [ -f "$WORK/dirty/$p" ] || { note "FAIL delivery: $p missing from the dirty tree"; fail=1; }
done
[ "$fail" -eq 0 ] && note "ok   delivery: both planted defects present in the dirty tree"

# Invariant zero: each defect must be detectable ALONE before the legs mean
# anything. A defect can be dead because the rule is not in the ruleset, because
# the advisory was withdrawn, or because the scanner never parsed the file --
# each yields a green dirty leg that says nothing about the gate. An exit code
# outside {0,1} is the scanner failing to run, reported as such rather than
# counted as "not detected".
solo="$WORK/solo"; mkdir -p "$solo/probe_planted"
cp "$WORK/dirty/$PLANTED_GO" "$solo/$PLANTED_GO"
cp "$WORK/dirty/$PLANTED_MOD" "$solo/$PLANTED_MOD"

sg_solo_rc="$(run_semgrep solo)"
if [ "$sg_solo_rc" -ne 0 ] && [ "$sg_solo_rc" -ne 1 ]; then
  note "FAIL preflight: semgrep exited $sg_solo_rc -- it did not run (environment failure, not a defect result)"
  sed -n '1,10p' "$WORK/semgrep.solo.out"; fail=1
elif ! grep -qE "Code Finding" "$WORK/semgrep.solo.out"; then
  note "FAIL preflight: the planted Go defect is NOT detected in isolation -- a dead input"
  fail=1
else
  note "ok   preflight: planted Go defect detectable in isolation"
fi

tv_solo_rc="$(run_trivy solo)"
if [ "$tv_solo_rc" -ne 0 ] && [ "$tv_solo_rc" -ne 1 ]; then
  note "FAIL preflight: trivy exited $tv_solo_rc -- it did not run (environment failure)"
  sed -n '1,10p' "$WORK/trivy.solo.out"; fail=1
elif ! grep -qE "^Total: [1-9]" "$WORK/trivy.solo.out"; then
  note "FAIL preflight: the planted vulnerable dependency is NOT detected in isolation -- advisory withdrawn or file unparsed"
  fail=1
else
  note "ok   preflight: planted vulnerable dependency detectable in isolation"
fi

if [ "$fail" -ne 0 ]; then echo; echo "SAST/SCA RED-PROBE ABORTED (harness or dead input)"; exit 2; fi

sg_clean_rc="$(run_semgrep clean)"; sg_dirty_rc="$(run_semgrep dirty)"
tv_clean_rc="$(run_trivy clean)";   tv_dirty_rc="$(run_trivy dirty)"

# --- semgrep ----------------------------------------------------------------
if [ "$sg_clean_rc" -ne 0 ]; then
  note "FAIL semgrep clean: committed tree at $REF reports a blocking finding (exit $sg_clean_rc)"
  grep -E "Code Finding|❯❱" "$WORK/semgrep.clean.out" | head -10; fail=1
else
  note "ok   semgrep clean: committed tree at $REF is clean"
fi
if [ "$sg_dirty_rc" -eq 0 ]; then
  note "FAIL semgrep dirty: planted defect did NOT redden the gate -- fake green"; fail=1
elif [ "$sg_dirty_rc" -ne 1 ]; then
  note "FAIL semgrep dirty: exit $sg_dirty_rc -- the scanner failed rather than detected"
  sed -n '1,10p' "$WORK/semgrep.dirty.out"; fail=1
else
  # A non-zero exit is not detection: semgrep also exits non-zero when a ruleset
  # fails to load. Require a parsed finding count AND the planted file named, so
  # a finding from elsewhere in the tree cannot stand in for ours.
  n="$(sed -n 's/.*│ \([0-9]*\) Code Finding.*/\1/p' "$WORK/semgrep.dirty.out" | head -1)"
  if [ -z "$n" ] || [ "$n" -lt 1 ]; then
    note "FAIL semgrep dirty: exit 1 but no finding count parsed -- the scanner failed rather than detected"
    sed -n '1,10p' "$WORK/semgrep.dirty.out"; fail=1
  elif ! grep -qF "$PLANTED_GO" "$WORK/semgrep.dirty.out"; then
    note "FAIL semgrep dirty: $n finding(s) but $PLANTED_GO never named -- detection is not about our defect"
    fail=1
  else
    note "ok   semgrep dirty: reddened naming $PLANTED_GO ($n finding(s), exit 1)"
  fi
fi

# --- trivy ------------------------------------------------------------------
if [ "$tv_clean_rc" -ne 0 ]; then
  note "FAIL trivy clean: committed tree at $REF reports a CRITICAL/HIGH vulnerability (exit $tv_clean_rc)"
  grep -E "^Total:|CVE-" "$WORK/trivy.clean.out" | head -10; fail=1
else
  note "ok   trivy clean: committed tree at $REF has no CRITICAL/HIGH findings"
fi
if [ "$tv_dirty_rc" -eq 0 ]; then
  note "FAIL trivy dirty: planted vulnerable dependency did NOT redden the gate -- fake green"; fail=1
elif [ "$tv_dirty_rc" -ne 1 ]; then
  note "FAIL trivy dirty: exit $tv_dirty_rc -- the scanner failed rather than detected"
  sed -n '1,10p' "$WORK/trivy.dirty.out"; fail=1
else
  # Same rule: trivy exits non-zero when its vulnerability DB is unreachable.
  # Require a parsed total and the planted manifest named.
  n="$(sed -n 's/^Total: \([0-9]*\).*/\1/p' "$WORK/trivy.dirty.out" | sort -rn | head -1)"
  if [ -z "$n" ] || [ "$n" -lt 1 ]; then
    note "FAIL trivy dirty: exit 1 but no total parsed -- the scanner failed rather than detected"
    sed -n '1,10p' "$WORK/trivy.dirty.out"; fail=1
  elif ! grep -qF "probe_planted/go.mod" "$WORK/trivy.dirty.out"; then
    note "FAIL trivy dirty: $n finding(s) but probe_planted/go.mod never named -- detection is not about our defect"
    fail=1
  else
    note "ok   trivy dirty: reddened naming probe_planted/go.mod ($n finding(s), exit 1)"
  fi
fi

if [ "$fail" -ne 0 ]; then echo; echo "SAST/SCA GATE RED-PROBE FAILED"; exit 1; fi
echo; echo "SAST/SCA gate proven two-sided against $REF (semgrep + trivy)"
