// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Teardown timing constants shared by the platform-specific mount seam and
// the platform-independent deploy guards. They live in this untagged file so
// the compose-grace invariant test references the REAL constants on every
// platform instead of hardcoded copies that would drift silently when either
// bound moves.

package mounter

import "time"

// writebackDrainTimeout bounds how long teardown waits for in-flight VFS
// write-back uploads to reach the broker before unmounting. A write-back
// cache holds dirty bytes locally and uploads them asynchronously; unmounting
// before that queue drains discards whatever has not yet been sent — the
// newest writes silently lost on a clean-looking exit (the cache tmpfs dies
// with the container).
//
// The bound is sized to the broker-throttle window the mount must tolerate
// (SEC-46): under a 429 window the write-back retry ladder runs 5/10/20/40s
// rungs, so a throttled item routinely waits ~75s for its next upload
// attempt, and the live gate's proven settle budget for a throttled burst is
// 120s. A clean teardown is unaffected — the wait returns as soon as active
// writers and in-use cache items reach zero; the bound only stretches the
// window in which throttled dirty bytes still land before detach.
//
// Named residuals: (a) an item sitting on a pathological >120s rung (near
// the 5m backoff cap) still loses its bytes on SIGTERM — an unbounded wait
// would wedge teardown forever and the runtime's SIGKILL would lose the same
// bytes, so the bound is the tolerance/termination tradeoff sized to the
// broker's actual throttle profile; (b) rclone's public VFS API exposes no
// dirty-only aggregate (an open-but-clean cache item holds the wait exactly
// like a dirty one), so a workload still holding a file open at SIGTERM
// stalls teardown to this full bound — session teardown order stops
// workloads before the mount, which makes that the exception, and a two-tier
// wait would need vfscache internals the fork discipline rules out.
const writebackDrainTimeout = 120 * time.Second

// unmountDetachGrace bounds how long teardown waits for the in-process kernel
// detach (server.Unmount) to RETURN before proceeding to let the process
// exit.
//
// On a native kernel the detach returns in well under this window, so the
// bound never fires and teardown is unchanged. On a userspace-kernel sandbox
// the in-process FUSE server's Unmount() does not return at all — the sentry
// services the unmount but the call never unblocks — so without a bound the
// teardown goroutine wedges forever, the orchestrator's run() never returns,
// and the ready-file is never retracted. Bounding only the detach (the drain
// above still runs to completion, so no write-back bytes are dropped) lets
// the process exit on SIGTERM; the sandbox then reclaims the still-served
// FUSE mount, which is the teardown contract on that tier (SIGTERM -> process
// exit -> sandbox reclaims the mount).
const unmountDetachGrace = 3 * time.Second
