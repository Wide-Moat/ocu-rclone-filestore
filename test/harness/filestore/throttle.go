// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package filestore

import (
	"net/http"
	"sync"
	"time"
)

// throttleRefusalStatus is the HTTP status the per-op throttle refuses an
// over-budget op with. It is deliberately an UNMAPPED status: the guest's
// status mapper routes every status outside its known table to a permanent,
// non-retryable error that surfaces as EIO at the FUSE boundary — not EACCES
// (which 401/403 give), not ENOENT (404), not a retryable backpressure signal
// (429/503, which the rclone pacer would transparently retry on the data path,
// swallowing the throttle on a metadata op). EIO-then-recover on caller backoff
// is exactly the SC2 throttle signature the e2e step asserts. 418 is a
// well-known unassigned-for-real-use status that no mapped branch claims.
const throttleRefusalStatus = http.StatusTeapot // 418

// tokenBucket is a simple monotonic-clock token bucket: it admits up to burst
// ops instantly and then refills at rate tokens per second. It is charged once
// per dispatched op BEFORE the op runs, mirroring a stage-0 per-op ceiling, so
// a rapid burst of separate ops overflows it and the excess ops are refused.
// Safe for concurrent use.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // bucket capacity
	tokens float64
	last   time.Time
	nowFn  func() time.Time
}

// newTokenBucket builds a bucket admitting burst ops instantly and refilling at
// rate per second. A non-positive rate or burst yields a bucket that never
// admits (it would refuse every op); callers pass sane positive values.
func newTokenBucket(rate, burst float64, nowFn func() time.Time) *tokenBucket {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &tokenBucket{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		last:   nowFn(),
		nowFn:  nowFn,
	}
}

// allow charges one token. It returns true when a token was available (the op
// is admitted) and false when the bucket is empty (the op is over budget and
// must be refused). It refills lazily from the elapsed wall time since the last
// call, capped at burst.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.nowFn()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// PerOpThrottle configures a per-op token-bucket ceiling on a single scope. When
// set on Options, every dispatched op against the named FilesystemID — metadata
// ops (createFile, readMetadata, listDirectory, makeDirectory, …) AND fileUpload
// — costs one token, charged at stage 0 before the op runs. A burst beyond Burst
// in under (Burst/Rate) seconds overflows the bucket and the excess ops are
// refused with the unmapped throttle status, which the guest surfaces as EIO. The
// bucket refills at Rate per second, so a caller that backs off recovers. Only
// the named scope is throttled; all other scopes are never charged.
type PerOpThrottle struct {
	// FilesystemID names the single scope this ceiling applies to.
	FilesystemID string
	// Rate is the steady-state tokens-per-second refill.
	Rate float64
	// Burst is the bucket capacity (instantaneous admission budget).
	Burst float64
	// Now, when set, fixes the bucket clock for deterministic tests.
	Now func() time.Time
}
