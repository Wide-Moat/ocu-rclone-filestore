#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# In-sandbox orchestrator for the gVisor (runsc) end-to-end leg.
#
# WHY ONE PROCESS TREE. Under runsc each container is its own sentry sandbox.
# Two facts force the brokers, the mount, and the test runner into a SINGLE
# sandbox here rather than the separate-container topology the runc harness
# (docker-compose.yml) uses:
#
#   1. Peer credentials. The broker accepts a unix-socket peer only with the
#      SAME uid (SO_PEERCRED at Accept). A bind-mounted host unix socket dialled
#      ACROSS two runsc sandboxes is proxied by the gofer, which does NOT
#      preserve the peer uid — the broker sees uid (uid_t)-1 and rejects the
#      mount. An in-sentry unix socket (both peers in ONE sandbox) preserves the
#      peer uid, so the same-uid accept check passes exactly as under runc.
#   2. Teardown signalling. The exercise's graceful-teardown step signals the
#      real mount process by PID. Under runsc the sentry owns a private PID
#      namespace and ignores `--pid host`, so a separate runner container can
#      never see (let alone signal) the mount process. Co-located, the mount PID
#      is an ordinary sibling PID the runner resolves and signals directly.
#
# Both are exactly how the production gVisor session tier deploys (the session's
# broker and mount share the session sandbox); this orchestrator is faithful to
# that shape, not a concession to it. The runc harness stays multi-container
# because under a real/native kernel the host unix socket and `pid: host` both
# work across containers.
#
# WHAT runsc NEEDS (run-confirmed): plain `runsc` runtime with `--host-uds`
# (irrelevant here since the socket is in-sentry, but harmless) and the device
# `/dev/fuse` + `CAP_SYS_ADMIN`. The `--fuse` runsc flag is DEPRECATED and a
# no-op on current runsc; in-sandbox FUSE serving is available without it. The
# go-fuse DirectMountStrict server (the production mount mechanic — in-process
# mount(2), no fusermount helper) mounts and serves every opcode this exercise
# drives under the sentry; only go-fuse's in-process server.Unmount() does not
# return under the sentry, so teardown relies on SIGTERM -> process exit ->
# sandbox reclaiming the mount, which the exercise already drives.

set -eu

SOCK_DIR=/sock
# WORKSPACE is the brokers' backend engine-root (where the local-volume engine
# persists each scope's objects under <filesystem_id>/). It is NOT a mountpoint.
WORKSPACE=/workspace
# MOUNT_ROOT is the canonical parent of the FUSE mountpoints the guest config
# points at. It is a distinct namespace from the broker engine-root above.
MOUNT_ROOT=/mnt/user-data
AUDIT_DIR=/audit
READY_FILE=/run/ocu/mount-ready
MAX_FILE_SIZE=67108864

mkdir -p "$SOCK_DIR" "$WORKSPACE" "$MOUNT_ROOT" "$AUDIT_DIR" /run/ocu
# The mount destinations the guest config points at: the primary rw output, the
# rw cold-read second output, the throttle mount, and the ro input. The mount
# binary does not create them.
mkdir -p "$MOUNT_ROOT/outputs" "$MOUNT_ROOT/uploads" "$MOUNT_ROOT/outputs2" "$MOUNT_ROOT/throttle"

log() { echo "[runsc-aio] $*" >&2; }

# --- start the four broker scopes (one ocu-filestored per filesystem_id) ------
# Identical flags to docker-compose.yml; the only difference is they run as
# sibling processes in this sandbox instead of separate containers. uid is 0
# (the image runs as root for the mount's FUSE mount(2)); the brokers therefore
# accept this same-uid in-sentry peer.
# start_broker launches one broker scope in the BACKGROUND and records its pid
# in the global BROKER_PIDS list. It must NOT be called in a command
# substitution ($(...)): that runs the body in a subshell whose stdout is a
# captured pipe, and the broker — which logs to stdout — would take SIGPIPE and
# die when the subshell's pipe closes. Launching in the main shell keeps the
# broker's stdout wired to the container log and lets `$!` name it directly.
#
# -ops-listen "" and -north-listen "" disable the broker's loopback metrics and
# north-ingress binds. The separate-container runc harness lets each broker bind
# the defaults (127.0.0.1:9464 / :7080) in its own network namespace, but
# co-located in ONE sandbox the four brokers share one loopback and the second
# would fail "address already in use". The south unix socket is the only channel
# the harness uses, so the loopback binds are pure dead weight here — disabling
# them is the correct co-location posture, not a capability loss.
BROKER_PIDS=""
start_broker() {
  fsid="$1"; intents="$2"; prefixes="$3"; shift 3
  mkdir -p "$AUDIT_DIR/$fsid"
  /ocu-filestored \
    -filesystem-id "$fsid" \
    -granted-intents "$intents" \
    -engine local-volume \
    -engine-root "$WORKSPACE" \
    -audit-sink "$AUDIT_DIR/$fsid/audit.log" \
    -broker-max-file-size "$MAX_FILE_SIZE" \
    -downloadable-prefixes "$prefixes" \
    -south-socket-dir "$SOCK_DIR" \
    -ops-listen "" \
    -north-listen "" \
    "$@" &
  BROKER_PIDS="$BROKER_PIDS $!"
}

log "starting brokers"
start_broker fsrw       read,write /,/e2e
start_broker fsro       read       /
start_broker fsthrottle read,write /,/e2e -ops-per-second 2 -ops-burst 2
start_broker fsconf     read,write /,/e2e

# Wait for every broker socket to appear.
for s in fsrw fsro fsthrottle fsconf; do
  i=0
  while [ ! -S "$SOCK_DIR/$s.sock" ]; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      log "broker socket $SOCK_DIR/$s.sock never appeared within 120s"; exit 1
    fi
    sleep 1
  done
done
log "all broker sockets present"

# --- start the mount (the production binary, helper-free DirectMountStrict) ---
log "starting mount"
/ocu-rclone-filestore \
  --config /etc/ocu/guest-config.json \
  --broker-socket-dir "$SOCK_DIR" \
  --ready-file "$READY_FILE" &
MOUNT_PID=$!

# Wait for the mount to report ready (it creates the ready-file once every mount
# is up). Because we share this PID namespace with the mount, MOUNT_PID is the
# exact pid the teardown step will signal.
i=0
while [ ! -f "$READY_FILE" ]; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then
    log "mount never became ready within 120s"; exit 1
  fi
  if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
    log "mount process exited before becoming ready"; exit 1
  fi
  sleep 1
done
log "mount ready (pid $MOUNT_PID)"

# --- conformance first (socket-direct, no FUSE — de-risks the in-sentry UDS) --
# The conformance binary dials fsconf.sock directly and never touches the FUSE
# mount, so a green here proves the in-sentry broker channel independently of
# the FUSE path. It is the safe first green under runsc.
run_conformance() {
  log "running backend conformance suite (fsconf, socket-direct)"
  cd /work
  RCLONE_CONFIG=/etc/ocu/conformance-rclone.conf \
  OCU_FSTESTS_REMOTE="fsconf:e2e" \
    /conformance.test -test.v -test.run '^TestFstestsLiveBroker$' -test.count=1
}

# --- the full FUSE exercise, co-located so the teardown PID is resolvable -----
run_exercise() {
  log "running live exercise (pid $MOUNT_PID is the teardown target)"
  RCLONE_OCUFS_LIVE=1 \
  OCU_E2E_RW_MOUNT="$MOUNT_ROOT/outputs" \
  OCU_E2E_RO_MOUNT="$MOUNT_ROOT/uploads" \
  OCU_E2E_RW_MOUNT2="$MOUNT_ROOT/outputs2" \
  OCU_E2E_THROTTLE_MOUNT="$MOUNT_ROOT/throttle" \
  OCU_E2E_READY_FILE="$READY_FILE" \
  OCU_E2E_MOUNT_PID="$MOUNT_PID" \
  OCU_E2E_BROKER_RW_WORKSPACE="$WORKSPACE/fsrw" \
  OCU_E2E_BROKER_THROTTLE_WORKSPACE="$WORKSPACE/fsthrottle" \
    /e2e.test -test.v -test.run '^TestE2EExercise$' -test.count=1
}

rc=0
case "${OCU_RUNSC_STAGE:-all}" in
  conformance) run_conformance || rc=$? ;;
  exercise)    run_exercise    || rc=$? ;;
  all)         run_conformance && run_exercise || rc=$? ;;
  *)           log "unknown OCU_RUNSC_STAGE=${OCU_RUNSC_STAGE:-}"; rc=2 ;;
esac

# The exercise's teardown step already SIGTERMs the mount; if it ran, the mount
# is down. Best-effort reap of any still-live broker so the sandbox exits clean.
# shellcheck disable=SC2086 # intentional word-splitting of the pid list
kill $BROKER_PIDS 2>/dev/null || true
log "done (rc=$rc)"
exit "$rc"
