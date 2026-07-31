#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the secrets gate: prove it reddens on a planted credential.
#
# A gate that has never been shown to fail is indistinguishable from a gate
# that cannot fail. This runs the exact commands .github/workflows/secrets.yml
# runs -- same pinned image digests, same flags -- against two trees, and
# asserts opposite outcomes for BOTH scanners in the gate:
#
#   clean = the committed tree at REF, untouched      -> expect a pass
#   dirty = that same tree plus planted credentials   -> expect a failure
#
# Both scanners walk git history rather than a working directory, so both legs
# scan a COMMITTED tree. An uncommitted planted secret is invisible to them and
# would produce a green dirty leg that says nothing about the gate.
#
# Payloads come from /dev/urandom, never from documentation. Every credential
# printed in a vendor's docs is in the scanner's allowlist by the time the
# scanner ships -- otherwise it would redden on the vendor's own README -- so a
# documentation-sourced payload is guaranteed not to fire. Three independent
# detector classes are planted so one allowlisted payload cannot leave the
# probe reading as vacuous.
#
# The images are pinned amd64 builds, so the run is pinned to that platform:
# on an arm64 host the emulation layer supplies it, and a silent architecture
# fallback cannot swap the binary under the probe.
#
# Usage: scripts/redprobe-secrets-gate.sh [--ref REF] [--keep]
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

# Pinned by digest, byte-identical to secrets.yml. A movable tag would let the
# probe and the gate drift apart silently.
GITLEAKS_IMAGE='ghcr.io/gitleaks/gitleaks@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb'
TRUFFLEHOG_IMAGE='ghcr.io/trufflesecurity/trufflehog@sha256:ce57a0504050b247c378e66ff5fa08f7ea97ee375d5a5e30a4ae0281566a987f'

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
git rev-parse --verify "$REF" >/dev/null 2>&1 || { echo "no such ref: $REF" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() { if [ "$KEEP" -eq 1 ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT

# The clean leg must carry the REAL history, not a replay of the tree into one
# synthetic commit. Both scanners walk commit DIFFS: replayed into a single
# commit, every line of every file arrives as freshly added, which is not what
# the gate sees and can invent findings the gate never reports. Clone the
# history and check out REF inside it.
SRC="$(git rev-parse --show-toplevel)"
git clone -q --no-local --no-checkout "$SRC" "$WORK/clean"
git -C "$WORK/clean" fetch -q "$SRC" "+$REF:refs/heads/probe-base"
git -C "$WORK/clean" checkout -q probe-base

cp -R "$WORK/clean/." "$WORK/dirty/" 2>/dev/null || { mkdir -p "$WORK/dirty"; cp -R "$WORK/clean/." "$WORK/dirty/"; }

# Scanned volume is printed for both legs: a leg that scanned one commit when
# the other scanned hundreds is measuring the harness, and the counters say so
# before any verdict does.
echo "info clean leg: $(git -C "$WORK/clean" rev-list --count HEAD) commits at $(git -C "$WORK/clean" rev-parse --short HEAD)"

rand() { LC_ALL=C tr -dc "$1" < /dev/urandom | head -c "$2"; }

# Payloads are generated, never copied from documentation: every credential a
# vendor prints in its docs is in the scanner's allowlist by the time the
# scanner ships. Each generator is a function so invariant zero can redraw it.
#
# Redrawing matters because a generated payload is not reliably detectable. The
# AWS rule applies an entropy threshold to the candidate secret, and a random
# 40-character draw falls under it roughly once in fifteen. A probe that failed
# on that draw would be a flaky gate check -- and a flaky check teaches people
# to re-run it, which is how a genuinely dead payload gets waved through.
gen_planted_aws() {
  printf 'aws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' \
    "$(rand 'A-Z0-9' 16)" "$(rand 'A-Za-z0-9/+' 40)" > "$WORK/dirty/planted_aws.txt"
}
gen_planted_pat() {
  printf 'GITHUB_TOKEN=ghp_%s\n' "$(rand 'A-Za-z0-9' 36)" > "$WORK/dirty/planted_pat.env"
}
gen_planted_key() {
  openssl genrsa 2048 2>/dev/null > "$WORK/dirty/planted_key.pem"
}
gen_planted_aws; gen_planted_pat; gen_planted_key

git -C "$WORK/dirty" add -A
git -C "$WORK/dirty" -c user.email=probe@local -c user.name=probe commit -qm "tree at $REF plus planted credentials"

# Invariant zero: every payload must be detectable by this scanner IN ISOLATION
# before the real legs run. A payload can be dead for reasons that look nothing
# alike -- an allowlisted vendor sample, a value one character short of the
# detected form, a rule that does not ship -- and each of them yields a dirty
# leg that is green for a reason having nothing to do with the gate. Checking
# the payloads first turns "the gate did not fire" into an unambiguous claim.
# solo_detects returns 0 when the scanner genuinely fires on this payload alone.
# It refuses to read a non-zero exit as detection: gitleaks exits non-zero when
# it cannot run at all, so an exit code outside {0,1} is an environment failure,
# reported as such and never retried. Retrying it would make a broken container
# look like five unlucky draws and earn the verdict "this class is
# undetectable" -- a fabricated finding standing in for a diagnosis.
# Detection also requires the payload file to be NAMED in the output; a count
# alone would let a finding from anything else stand in for ours.
SOLO_ENV_FAILURE=0
solo_detects() { # $1 = payload filename
  local p="$1" solo="$WORK/solo-$p" rc found
  rm -rf "$solo"; mkdir -p "$solo"
  cp "$WORK/dirty/$p" "$solo/"
  git -C "$solo" init -q .
  git -C "$solo" add -A
  git -C "$solo" -c user.email=probe@local -c user.name=probe commit -qm "solo $p"
  docker run --rm --platform linux/amd64 -v "$solo:/repo:ro" "$GITLEAKS_IMAGE" \
    detect --source=/repo --redact --verbose --exit-code=1 > "$WORK/solo.$p.out" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    echo "FAIL preflight: scanner exited $rc on $p -- it did not run. This is an environment failure, not a payload result."
    sed -n '1,10p' "$WORK/solo.$p.out"
    SOLO_ENV_FAILURE=1
    return 0   # stop the redraw loop; the caller aborts on SOLO_ENV_FAILURE
  fi
  [ "$rc" -eq 1 ] || return 1
  found="$(sed -n 's/.*leaks found: \([0-9]*\).*/\1/p' "$WORK/solo.$p.out" | head -1)"
  [ -n "$found" ] && [ "$found" -ge 1 ] || return 1
  grep -qE "^File:[[:space:]]+$p\$" "$WORK/solo.$p.out"
}

preflight_fail=0
for spec in "planted_aws.txt:gen_planted_aws" "planted_pat.env:gen_planted_pat" "planted_key.pem:gen_planted_key"; do
  p="${spec%%:*}"; gen="${spec##*:}"
  attempt=1
  until solo_detects "$p"; do
    if [ "$attempt" -ge 5 ]; then
      echo "FAIL preflight: payload $p undetectable after 5 draws -- this class is allowlisted or the rule is absent, not an unlucky draw"
      preflight_fail=1
      break
    fi
    attempt=$((attempt + 1))
    "$gen"
  done
  if [ "$SOLO_ENV_FAILURE" -ne 0 ]; then
    echo; echo "SECRETS GATE RED-PROBE ABORTED (scanner did not run)"; exit 2
  fi
  if [ "$preflight_fail" -eq 0 ]; then
    if [ "$attempt" -eq 1 ]; then
      echo "ok   preflight: payload $p is detectable in isolation"
    else
      echo "ok   preflight: payload $p is detectable in isolation (after $attempt draws)"
    fi
  fi
done
if [ "$preflight_fail" -ne 0 ]; then
  echo; echo "SECRETS GATE RED-PROBE FAILED (dead payload class)"; exit 1
fi

# Redrawn payloads must be re-committed, or the dirty leg would scan the draw
# that failed preflight rather than the one that passed it.
git -C "$WORK/dirty" add -A
git -C "$WORK/dirty" -c user.email=probe@local -c user.name=probe commit -q --amend --no-edit

run_gitleaks() {
  docker run --rm --platform linux/amd64 -v "$WORK/$1:/repo:ro" "$GITLEAKS_IMAGE" \
    detect --source=/repo --redact --verbose --exit-code=1 > "$WORK/gitleaks.$1.out" 2>&1
  echo $?
}
run_trufflehog() {
  docker run --rm --platform linux/amd64 -v "$WORK/$1:/repo:ro" "$TRUFFLEHOG_IMAGE" \
    git "file:///repo" --results=verified,unknown --fail > "$WORK/trufflehog.$1.out" 2>&1
  echo $?
}

gl_clean_rc="$(run_gitleaks clean)"; gl_dirty_rc="$(run_gitleaks dirty)"
th_clean_rc="$(run_trufflehog clean)"; th_dirty_rc="$(run_trufflehog dirty)"

fail=0
note() { echo "$1"; }

# Delivery first: a dirty leg that never received the payload produces a result
# about the harness, not the gate.
#
# This asserts the payloads are in the dirty leg's COMMITTED tree, not that its
# scanned-byte count grew. The byte delta is only a proxy and it drifts for
# unrelated reasons -- a mutation that left the payloads uncommitted still moved
# the count by a few hundred bytes and would have been waved through as
# delivered. Both scanners read history, so presence in HEAD is the property
# that actually matters, and it is checkable exactly.
delivered=0; undelivered=""
for p in planted_aws.txt planted_pat.env planted_key.pem; do
  if git -C "$WORK/dirty" cat-file -e "HEAD:$p" 2>/dev/null; then
    delivered=$((delivered + 1))
  else
    undelivered="$undelivered $p"
  fi
done
if [ -n "$undelivered" ]; then
  note "FAIL delivery: these payloads are absent from the dirty leg's committed tree:$undelivered"
  note "     Both scanners read git history, so an uncommitted payload is invisible and its green says nothing."
  fail=1
else
  gl_bytes() { sed -n 's/.*scanned ~\([0-9]*\) bytes.*/\1/p' "$WORK/gitleaks.$1.out" | head -1; }
  note "ok   delivery: all $delivered payloads present in the dirty leg's committed tree (scanned $(gl_bytes dirty) vs $(gl_bytes clean) bytes)"
fi

# --- gitleaks ---------------------------------------------------------------
if [ "$gl_clean_rc" -ne 0 ]; then
  note "FAIL gitleaks clean: committed tree at $REF reports a leak (exit $gl_clean_rc)"
  sed -n '1,20p' "$WORK/gitleaks.clean.out"; fail=1
else
  note "ok   gitleaks clean: committed tree at $REF is clean"
fi
if [ "$gl_dirty_rc" -eq 0 ]; then
  note "FAIL gitleaks dirty: planted credentials did NOT redden the gate -- fake green"
  fail=1
else
  # A non-zero exit alone is not detection: gitleaks also exits non-zero when it
  # cannot load a config or read the source. Require a parsed finding count, or
  # the probe would certify a scanner that never scanned.
  found="$(sed -n 's/.*leaks found: \([0-9]*\).*/\1/p' "$WORK/gitleaks.dirty.out" | head -1)"
  if [ -z "$found" ]; then
    note "FAIL gitleaks dirty: exit $gl_dirty_rc but no finding count -- the scanner failed rather than detected"
    sed -n '1,20p' "$WORK/gitleaks.dirty.out"; fail=1
  elif [ "$found" -lt 3 ]; then
    note "FAIL gitleaks dirty: only $found of 3 planted classes detected -- a detector is allowlisted or absent"
    fail=1
  else
    # A count proves the gate reddened, not that it reddened on OUR payload: a
    # pre-existing secret elsewhere in the tree would satisfy it while every
    # planted class went unseen. Require each planted file to be named.
    missing=""
    for p in planted_aws.txt planted_pat.env planted_key.pem; do
      grep -qE "^File:[[:space:]]+$p\$" "$WORK/gitleaks.dirty.out" || missing="$missing $p"
    done
    if [ -n "$missing" ]; then
      note "FAIL gitleaks dirty: $found finding(s) but these planted files were never named:$missing"
      fail=1
    else
      note "ok   gitleaks dirty: reddened naming all 3 planted files (exit $gl_dirty_rc, leaks found: $found)"
    fi
  fi
fi

# --- trufflehog -------------------------------------------------------------
if [ "$th_clean_rc" -ne 0 ]; then
  note "FAIL trufflehog clean: committed tree at $REF reports a finding (exit $th_clean_rc)"
  grep -iE "found|detector|file:" "$WORK/trufflehog.clean.out" | head -10; fail=1
else
  note "ok   trufflehog clean: committed tree at $REF is clean"
fi
if [ "$th_dirty_rc" -eq 0 ]; then
  note "FAIL trufflehog dirty: planted credentials did NOT redden the gate -- fake green"
  fail=1
else
  # Same rule as gitleaks: --fail exits non-zero on a scan error too, so a
  # non-zero code is not detection. Count the per-result banners rather than a
  # summary line: the summary wording moves between releases, while a reported
  # result always announces itself. Then require file-level attribution, so a
  # result fired by something already in the tree cannot stand in for the
  # payload we planted.
  found="$(grep -c '^Found .*result' "$WORK/trufflehog.dirty.out" 2>/dev/null)"
  attributed="$(grep -c '^File: planted_' "$WORK/trufflehog.dirty.out" 2>/dev/null)"
  if [ -z "$found" ] || [ "$found" -eq 0 ]; then
    note "FAIL trufflehog dirty: exit $th_dirty_rc but no result reported -- the scanner failed rather than detected"
    sed -n '1,20p' "$WORK/trufflehog.dirty.out"; fail=1
  elif [ "$attributed" -eq 0 ]; then
    note "FAIL trufflehog dirty: $found result(s) but none attributed to a planted file -- detection is not about our payload"
    fail=1
  else
    note "ok   trufflehog dirty: reddened with $found result(s), $attributed attributed to planted files (exit $th_dirty_rc)"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo; echo "SECRETS GATE RED-PROBE FAILED"; exit 1
fi
echo; echo "secrets gate proven two-sided against $REF (gitleaks + trufflehog)"
