// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Environment contract the live harness exports. The mountpoints and socket are
// resolved here so 05-02 only sets these variables and flips the gate; the
// assertions below stay frozen.
const (
	// envGate is the master gate. Unset -> the whole exercise skips clean.
	envGate = "RCLONE_OCUFS_LIVE"
	// envRWMount is the read-write mountpoint the harness mounts the rw
	// filesystem at.
	envRWMount = "OCU_E2E_RW_MOUNT"
	// envRWMount2 is a SECOND read-write mountpoint of the SAME rw filesystem
	// scope, mounted at a distinct destination. Each mount entry gets its own
	// independent VFS cache, so this mount never holds the object written
	// through envRWMount: a read here can only be served by traversing the
	// broker fileDownload path, which is exactly the cold-read proof of the read
	// data path (step 11).
	envRWMount2 = "OCU_E2E_RW_MOUNT2"
	// envROMount is the read-only mountpoint the harness mounts the ro
	// filesystem at.
	envROMount = "OCU_E2E_RO_MOUNT"
	// envThrottleMount is a read-write mountpoint of a separate filesystem scope
	// whose broker runs with a small per-second token bucket (ops-per-second 2,
	// burst 2). A burst of separate write operations against it drives the broker
	// over budget so it refuses the over-budget ops with the throttle class
	// (resource_exhausted, deny_class throttle). Under SEC-46 that refusal is a
	// uniform per-op fail-closed ceiling: a throttled metadata op surfaces EIO to
	// the caller, which is correct, not a bug. Step 12 (SC2) proves (a) the
	// throttle fires (a write is refused under the burst), and (b) a caller that
	// backs off and retries recovers the write byte-identical broker-side
	// (eventual success). It does NOT claim the pacer transparently completes
	// every op, nor does it itself prove broker-side atomicity (the
	// no-partial-stage property is the broker's, asserted broker-side). The guest
	// never simulates the throttle (SEC-46 is broker-side).
	envThrottleMount = "OCU_E2E_THROTTLE_MOUNT"
	// envReadyFile is the ready-file path the mount process creates once all
	// mounts are up and removes on teardown.
	envReadyFile = "OCU_E2E_READY_FILE"
	// envMountPID is the PID of the running mount process the SIGTERM step
	// signals. The harness writes it once the process is up.
	envMountPID = "OCU_E2E_MOUNT_PID"
	// envAllowPartial is the explicit escape hatch for a partial live run: with
	// the gate set, a missing live input — OCU_E2E_RW_MOUNT2,
	// OCU_E2E_THROTTLE_MOUNT, OCU_E2E_BROKER_THROTTLE_WORKSPACE,
	// OCU_E2E_MOUNT_PID, or OCU_E2E_BROKER_RW_WORKSPACE — is a hard failure
	// (fail-closed — a release must never publish with the cold-read, SC2
	// throttle, teardown, or broker-persistence assertions silently skipped)
	// UNLESS this is set to a truthy value (e.g. 1/true), which opts into
	// skipping those steps on purpose.
	envAllowPartial = "OCU_E2E_ALLOW_PARTIAL"
	// envBrokerRWWorkspace is the broker-rw engine-root workspace, mounted
	// READ-ONLY into the runner. Asserting against the bytes the broker actually
	// persisted here — not the bytes read back through the FUSE mount, which the
	// local VFS write-back cache can serve without any upload ever reaching the
	// broker — is what makes the write steps prove the broker data path rather
	// than the cache. The relative path under the rw mount maps 1:1 to the path
	// under this workspace root (both are filesystem-relative to the same scope).
	envBrokerRWWorkspace = "OCU_E2E_BROKER_RW_WORKSPACE"
	// envBrokerThrottleWorkspace is the throttle broker's engine-root workspace,
	// mounted READ-ONLY into the runner. The SC2 throttle step hashes the bytes
	// the throttled broker actually persisted here after the pacer's retries —
	// not the FUSE read-back, which the local cache can serve — so the proof is
	// "a throttled write still lands byte-identical broker-side", not merely "the
	// gate fails closed". The relative path under the throttle mount maps 1:1 to
	// the path under this workspace root (same scope).
	envBrokerThrottleWorkspace = "OCU_E2E_BROKER_THROTTLE_WORKSPACE"
)

// allowPartial reports whether the operator explicitly opted into a partial
// live run via the escape hatch. Only an explicit truthy value counts; unset,
// empty, or non-boolean values keep the gate fail-closed.
func allowPartial() bool {
	v, err := strconv.ParseBool(os.Getenv(envAllowPartial))
	return err == nil && v
}

// largeFileSize exceeds the ~4MiB RPC ceiling so the write exercises chunked
// upload and the read exercises ranged reassembly.
const largeFileSize = 9 << 20 // 9 MiB

// settleTimeout bounds the polling helpers that wait for the FUSE path to
// reflect a mutation (the VFS is eventually consistent through the cache).
const settleTimeout = 30 * time.Second

// throttleSettleTimeout is the broker-landing budget for the SC2 throttle step
// ALONE. A write under vfs_cache_mode:writes returns from the syscall once the
// bytes are durably in the local cache; the real fileUpload runs asynchronously
// in rclone's VFS writeback queue (vfs_write_back default 5s). When that upload
// is refused by the per-session throttle, rclone's writeback retries it with a
// coarse exponential backoff (5s, then doubling 10/20/40s, capped at the rclone
// maxUploadDelay of 5m), with no jitter and no Retry-After consumption, while up
// to Transfers (default 4) uploads race the 2-ops/s, burst-2 bucket. The bytes
// always land — rclone's writeback re-queues a dirty item indefinitely and only
// drops it on success — but the last of a 6-write burst can sit on a 20–40s
// backoff rung, well past the 30s settleTimeout the unthrottled steps use. 120s
// amply bounds that worst case for six small single-op uploads while still
// failing closed: it widens ONLY the wait, never the byte-identity check or the
// throttle-must-fire guard, so genuine data loss still fatals the step.
//
// A follow-up could shrink this worst case by exposing vfs_write_back as a
// per-mount config knob so the throttle mount fires its first upload promptly;
// that is out of scope here and not required for the gate to be correct.
const throttleSettleTimeout = 120 * time.Second

// liveEnv carries the resolved harness contract for a single run.
type liveEnv struct {
	rwMount                 string
	rwMount2                string
	roMount                 string
	throttleMount           string
	readyFile               string
	mountPID                int
	brokerRWWorkspace       string
	brokerThrottleWorkspace string
}

// requireLive resolves the env contract or skips the whole exercise. With the
// gate unset (the 05-01 default) this skips cleanly, so building with -tags e2e
// and running without a harness is green.
func requireLive(t *testing.T) liveEnv {
	t.Helper()
	if os.Getenv(envGate) == "" {
		t.Skipf("%s not set — the live broker harness is wired in wave 05-02 "+
			"(compose up with /dev/fuse + SYS_ADMIN against the broker socket); "+
			"this exercise skips clean until then", envGate)
	}

	rw := os.Getenv(envRWMount)
	ro := os.Getenv(envROMount)
	if rw == "" || ro == "" {
		t.Fatalf("live gate set but mountpoints missing: %s=%q %s=%q "+
			"(the harness must export both to prove multimount)",
			envRWMount, rw, envROMount, ro)
	}

	pid := 0
	if p := os.Getenv(envMountPID); p != "" {
		v, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("invalid %s=%q: %v", envMountPID, p, err)
		}
		pid = v
	}

	return liveEnv{
		rwMount:                 rw,
		rwMount2:                os.Getenv(envRWMount2),
		roMount:                 ro,
		throttleMount:           os.Getenv(envThrottleMount),
		readyFile:               os.Getenv(envReadyFile),
		mountPID:                pid,
		brokerRWWorkspace:       os.Getenv(envBrokerRWWorkspace),
		brokerThrottleWorkspace: os.Getenv(envBrokerThrottleWorkspace),
	}
}

// TestE2EExercise drives the full 10-step exercise sequence over the FUSE
// mountpoints via ordinary os file operations. It imports no broker client: the
// whole point is to prove the kernel mount path, and the guest holds no second
// transport (SEC-25). Each step is a subtest with its assertion fully written;
// 05-02 supplies the live endpoint and the throttle test-mode without changing
// any assertion.
// e2eDirName is the single top-level directory under the rw mount that the
// exercise operates within. Cold reads and listings of any path are authorized
// broker-side only when the path lies under a configured downloadable prefix
// (SEC-73, broker-resolved and default-deny); the bare root "/" is a sentinel
// that authorizes only itself, not the tree beneath it. So the harness
// enumerates this one prefix as downloadable and the exercise confines its
// objects to it, exercising real cold reads/lists rather than only warm-cache
// hits. The mount itself never enforces this — it sends no downloadable flag.
const e2eDirName = "e2e"

func TestE2EExercise(t *testing.T) {
	env := requireLive(t)

	// rwBase is the downloadable working directory under the rw mount; rel()
	// joins a name under it, and scopeRel() yields the filesystem-scope-relative
	// path used for the broker-side persistence assertion.
	rwBase := filepath.Join(env.rwMount, e2eDirName)
	rel := func(name string) string { return filepath.Join(rwBase, name) }
	scopeRel := func(name string) string { return e2eDirName + "/" + name }

	// Step 1 — multimount: at least two mounts (rw + ro) must be present and
	// distinct, proving the multimount harness brought up >=2 filesystems. The
	// rw working directory is created here so every later step operates under
	// the downloadable prefix.
	t.Run("01_multimount_present", func(t *testing.T) {
		for name, p := range map[string]string{envRWMount: env.rwMount, envROMount: env.roMount} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatalf("%s mountpoint %q not present: %v", name, p, err)
			}
			if !info.IsDir() {
				t.Fatalf("%s mountpoint %q is not a directory", name, p)
			}
		}
		if env.rwMount == env.roMount {
			t.Fatalf("rw and ro mountpoints must be distinct, both are %q", env.rwMount)
		}
		if err := os.Mkdir(rwBase, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			t.Fatalf("create rw working directory %q: %v", rwBase, err)
		}
	})

	// Step 2 — write a small file then read it back byte-identical
	// (createFile/fileUpload + readFile).
	smallName := "small.txt"
	smallPath := rel(smallName)
	smallData := []byte("end-to-end small payload\n")
	t.Run("02_write_read_small", func(t *testing.T) {
		if err := os.WriteFile(smallPath, smallData, 0o644); err != nil {
			t.Fatalf("write small file: %v", err)
		}
		got := readBackEventually(t, smallPath, len(smallData))
		if !bytes.Equal(got, smallData) {
			t.Fatalf("small file round-trip mismatch: got %d bytes, want %d", len(got), len(smallData))
		}
		// De-vacuum: prove the bytes reached the broker's workspace, not just
		// the local VFS write-back cache (a cache-served read-back passes the
		// assertion above while no fileUpload ever succeeded).
		assertBrokerPersisted(t, env, scopeRel(smallName), smallData)
	})

	// Step 3 — list a directory and assert the union (the written file and a
	// created subdir both appear: listDirectory unions files + subdirs).
	subDir := "listed-subdir"
	t.Run("03_list_union", func(t *testing.T) {
		if err := os.Mkdir(rel(subDir), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			t.Fatalf("mkdir for list union: %v", err)
		}
		names := listEventually(t, rwBase, smallName, subDir)
		assertContains(t, names, smallName)
		assertContains(t, names, subDir)
		// De-vacuum the listing: the union the mount reports must reflect
		// broker-side reality (the makeDirectory landed, the earlier upload
		// landed), not just the local dir cache. The file's bytes were already
		// proven in step 2; here assert both names exist in the broker workspace.
		assertBrokerPresent(t, env, scopeRel(subDir))
		assertBrokerPresent(t, env, scopeRel(smallName))
	})

	// Step 4 — mkdir then rmdir (makeDirectory/removeDirectory): create, assert
	// present, remove, assert absent.
	t.Run("04_mkdir_rmdir", func(t *testing.T) {
		const dirName = "transient-dir"
		dir := rel(dirName)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("created dir not present: %v", err)
		}
		// De-vacuum: the makeDirectory must reach the broker, not just the cache.
		assertBrokerPresent(t, env, scopeRel(dirName))
		if err := os.Remove(dir); err != nil {
			t.Fatalf("rmdir: %v", err)
		}
		waitGone(t, dir)
		// De-vacuum: the removeDirectory must take effect broker-side.
		assertBrokerAbsent(t, env, scopeRel(dirName))
	})

	// Step 5 — rename a file and a dir (moveFile/moveDirectory): old path gone,
	// new path present.
	t.Run("05_rename_file_and_dir", func(t *testing.T) {
		// File rename.
		const srcFileName, dstFileName = "rename-src.txt", "rename-dst.txt"
		srcFile := rel(srcFileName)
		dstFile := rel(dstFileName)
		// Nonce the payload per run (mirror the large.bin rand.Read pattern): the
		// broker-side byte assertion on the renamed file would otherwise false-pass
		// against a stale byte-identical leftover from a prior run on a dirty
		// workspace. Random bytes make any leftover mismatch, so the assertion
		// proves THIS run's moveFile landed, not that some same-named file exists.
		payload := []byte("rename payload\n")
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("generate rename payload nonce: %v", err)
		}
		payload = append(payload, nonce...)
		if err := os.WriteFile(srcFile, payload, 0o644); err != nil {
			t.Fatalf("write rename source: %v", err)
		}
		if err := os.Rename(srcFile, dstFile); err != nil {
			t.Fatalf("rename file: %v", err)
		}
		waitGone(t, srcFile)
		got := readBackEventually(t, dstFile, len(payload))
		if !bytes.Equal(got, payload) {
			t.Fatalf("renamed file content mismatch")
		}
		// De-vacuum the moveFile: the object's BYTES must survive the move at the
		// broker (hash at the new workspace path), and the old path must be gone
		// broker-side — a FUSE read-back of the destination can be cache-served.
		assertBrokerPersisted(t, env, scopeRel(dstFileName), payload)
		assertBrokerAbsent(t, env, scopeRel(srcFileName))

		// Dir rename.
		const srcDirName, dstDirName = "rename-src-dir", "rename-dst-dir"
		srcDir := rel(srcDirName)
		dstDir := rel(dstDirName)
		if err := os.Mkdir(srcDir, 0o755); err != nil {
			t.Fatalf("mkdir rename source dir: %v", err)
		}
		if err := os.Rename(srcDir, dstDir); err != nil {
			t.Fatalf("rename dir: %v", err)
		}
		waitGone(t, srcDir)
		if _, err := os.Stat(dstDir); err != nil {
			t.Fatalf("renamed dir not present: %v", err)
		}
		// De-vacuum the moveDirectory: namespace change must reach the broker.
		assertBrokerPresent(t, env, scopeRel(dstDirName))
		assertBrokerAbsent(t, env, scopeRel(srcDirName))
	})

	// Step 6 — large file over the RPC ceiling: write, read back byte-identical,
	// proving chunked upload + ranged reassembly.
	largePath := rel("large.bin")
	largeData := make([]byte, largeFileSize)
	t.Run("06_large_file_chunked", func(t *testing.T) {
		if _, err := rand.Read(largeData); err != nil {
			t.Fatalf("generate large payload: %v", err)
		}
		if err := os.WriteFile(largePath, largeData, 0o644); err != nil {
			t.Fatalf("write large file: %v", err)
		}
		got := readBackEventually(t, largePath, len(largeData))
		if !bytes.Equal(got, largeData) {
			t.Fatalf("large file round-trip mismatch over the RPC ceiling")
		}
		// De-vacuum: the chunked upload must land byte-identical broker-side,
		// not merely round-trip through the local cache.
		assertBrokerPersisted(t, env, scopeRel("large.bin"), largeData)
	})

	// Step 7 — ranged read: read a byte range mid-file and assert exact bytes
	// (proves the backend serves a correct ranged read, not a full re-fetch).
	t.Run("07_ranged_read", func(t *testing.T) {
		const off = 5 << 20 // 5 MiB into the file, past the first chunk
		const n = 4096
		if off+n > len(largeData) {
			t.Fatalf("test setup: range %d+%d exceeds file size %d", off, n, len(largeData))
		}
		f, err := os.Open(largePath)
		if err != nil {
			t.Fatalf("open large file for ranged read: %v", err)
		}
		defer f.Close()
		buf := make([]byte, n)
		got, err := f.ReadAt(buf, off)
		if err != nil {
			t.Fatalf("ranged read at %d: %v", off, err)
		}
		if got != n {
			t.Fatalf("ranged read short: got %d want %d", got, n)
		}
		if !bytes.Equal(buf, largeData[off:off+n]) {
			t.Fatalf("ranged read bytes mismatch at offset %d", off)
		}
	})

	// Step 8 — read-only violation: a write on the read-only mount must fail
	// with EROFS or EACCES (the broker scope/intent deny maps to a FUSE
	// permission error). SC2.
	t.Run("08_readonly_violation", func(t *testing.T) {
		roFile := filepath.Join(env.roMount, "must-not-write.txt")
		err := os.WriteFile(roFile, []byte("nope"), 0o644)
		if err == nil {
			_ = os.Remove(roFile)
			t.Fatalf("write to read-only mount %q unexpectedly succeeded", roFile)
		}
		if !errors.Is(err, syscall.EROFS) && !errors.Is(err, syscall.EACCES) {
			t.Fatalf("read-only violation surfaced wrong error: got %v, want EROFS or EACCES", err)
		}
	})

	// Step 9 — throttle (thin alias): the real SC2 throttle proof moved to step 12,
	// which drives a genuine over-budget burst against a broker-throttled scope and
	// proves the SEC-46 invariants — the throttle fires, and a caller that backs
	// off and retries recovers the write byte-identical (eventual success).
	// The earlier path-named broker test-mode is retired (the broker drives
	// throttling from daemon flags, needing no coordination file). This step is
	// kept as a stable, named pointer so a localized failure still reads in step
	// order; it carries no assertion of its own.
	t.Run("09_throttle_no_data_loss", func(t *testing.T) {
		t.Skip("SC2 throttle is proven in step 12 (12_throttle_retry_no_loss): a " +
			"flag-driven broker throttle drives an over-budget burst; the test asserts " +
			"the throttle fires and that a caller backing off and retrying recovers " +
			"byte-identical bytes broker-side (eventual success). The throttle is a " +
			"uniform per-op fail-closed ceiling — a throttled metadata op EIO'ing is " +
			"expected, not the pacer transparently completing every op (SEC-46).")
	})

	// Step 11 — cold read across a SECOND mount of the same scope: write a
	// nonce'd payload through mount A (the primary rw mount), confirm it
	// persisted broker-side, then read the SAME scope-relative path through
	// mount B (a distinct mount of the same filesystem_id at another
	// destination). Each mount entry has its own VFS cache, so mount B never
	// holds these bytes in cache — a successful read there can only come from
	// the broker's fileDownload path. This is the load-bearing proof of the read
	// data path: the bytes traverse the broker, not a warm write-back cache.
	// Both paths stay under the /e2e downloadable prefix (SEC-73, broker-resolved).
	//
	// Steps 11 and 12 are declared before step 10 because step 10 SIGTERMs the
	// mount process and asserts every mountpoint unmounts; subtests run in source
	// order, so the data-path proofs must execute while the mounts are still live.
	// The names carry the logical step numbers (the teardown is logically last).
	t.Run("11_cold_read_second_mount", func(t *testing.T) {
		if env.rwMount2 == "" {
			if allowPartial() {
				t.Skipf("%s unset and partial mode explicitly opted into via %s — "+
					"skipping the cold-read proof; without a second mount of the same "+
					"scope a read cannot be shown to traverse the broker fileDownload "+
					"path rather than a warm cache", envRWMount2, envAllowPartial)
			}
			t.Fatalf("%s is required under the live gate (%s): it names a second mount "+
				"of the same scope whose independent VFS cache is cold, so a read there "+
				"proves the broker fileDownload data path; set %s=1 only to opt into a "+
				"partial run on purpose", envRWMount2, envGate, envAllowPartial)
		}

		// A fresh nonce'd name and payload so neither mount could have cached it
		// from an earlier step.
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("generate cold-read nonce: %v", err)
		}
		coldName := "cold-" + hex.EncodeToString(nonce) + ".bin"
		coldData := make([]byte, 64<<10) // 64 KiB, distinct random content
		if _, err := rand.Read(coldData); err != nil {
			t.Fatalf("generate cold-read payload: %v", err)
		}

		// Write through mount A under the downloadable working prefix.
		if err := os.WriteFile(rel(coldName), coldData, 0o644); err != nil {
			t.Fatalf("write cold-read payload through mount A: %v", err)
		}
		// Prove it reached the broker so the cross-mount read has something to
		// download (not merely something cached in mount A's write-back cache).
		assertBrokerPersisted(t, env, scopeRel(coldName), coldData)

		// Read the SAME scope-relative path through mount B. Mount B never wrote
		// this object and has its own cold VFS cache, so the bytes can only come
		// from the broker fileDownload path. Poll for eventual consistency.
		mountBPath := filepath.Join(env.rwMount2, e2eDirName, coldName)
		got := readBackEventually(t, mountBPath, len(coldData))
		if !bytes.Equal(got, coldData) {
			t.Fatalf("cold read through second mount %q mismatched: got %d bytes, want %d "+
				"(the bytes must have traversed the broker fileDownload path, not a cache)",
				mountBPath, len(got), len(coldData))
		}
	})

	// Step 12 — throttle fires, caller-retry recovers byte-identical (SC2).
	//
	// SEC-46 framing (the only canon-true invariant this step may prove). The
	// broker throttle is a fail-closed DoS-containment ceiling and it is UNIFORM
	// PER-OP: nothing trusts the request body before dispatch, so the broker
	// cannot throttle "uploads only" — every dispatched op (List, Stat, Mkdir,
	// fileUpload) costs exactly one token, charged at stage 0 before the body is
	// decoded. The rclone pacer retries only the DATA-TRANSFER path; it does NOT
	// retry VFS METADATA ops (List / Dir.Stat / Mkdir / open-create). A throttled
	// metadata op therefore surfaces resource_exhausted straight to EIO at the
	// caller — and under SEC-46 that EIO is CORRECT, spec-compliant behaviour, not
	// a bug. There is NO "an op always completes under throttle" guarantee. The
	// guarantee that DOES hold is ATOMICITY: a throttled or refused fileUpload
	// never partially stages, so no torn or corrupt object is left behind.
	//
	// This step proves exactly three things and nothing that contradicts SEC-46:
	//   (a) THE THROTTLE FIRES — an over-budget burst makes the broker refuse
	//       excess ops with the throttle / resource_exhausted class. Observed from
	//       the guest side: at least one os.WriteFile in the saturating burst
	//       returns an error (a throttled metadata op surfacing EIO is the expected
	//       signal). If no throttle is ever observed the bucket was too loose and
	//       the test FAILS — it did not actually exercise the ceiling.
	//   (b) THE RECOVERED WRITE LANDS BYTE-IDENTICAL (eventual success) — every
	//       name is asserted by byte-identity broker-side, so a throttled-then-
	//       retried write must match exactly once it succeeds. (This proves the
	//       recovered object is whole; it does NOT by itself prove atomicity of a
	//       mid-throttle partial — a partial stage would be overwritten by the
	//       clean retry and still hash-match. The atomic-no-partial-stage property
	//       is the broker's, asserted broker-side, not by this guest read.)
	//   (c) RECOVERY ONCE TOKENS REFILL — the TEST ITSELF backs off and retries the
	//       EIO'd write at the file-op level (sleep ~600ms so the 2/s bucket
	//       refills, then retry), bounded by settleTimeout. This models a
	//       well-behaved client backing off; it is the CALLER's responsibility per
	//       SEC-46, NOT a guest-pacer guarantee. After recovery the bytes are
	//       asserted byte-identical broker-side.
	//
	// What this step deliberately does NOT claim: that the pacer transparently
	// completes every op under throttle. It does not — metadata-EIO is expected.
	//
	// Each separate file write is ONE client-streaming fileUpload = ONE throttled
	// op at dispatch stage 0 (a chunked upload is a SINGLE op, not one op per
	// chunk frame — so a large file would NOT generate the burst). The pressure
	// comes from issuing N=6 SEPARATE small writes as fast as possible: that, plus
	// the per-write VFS dir-stat the open-create path issues, blows past the 2/2
	// bucket and forces resource_exhausted on the over-budget ops. The setup mkdir
	// (plus its parent-dir list) must fit the burst budget and succeed first.
	t.Run("12_throttle_retry_no_loss", func(t *testing.T) {
		if env.throttleMount == "" {
			if allowPartial() {
				t.Skipf("%s unset and partial mode explicitly opted into via %s — "+
					"skipping the SC2 throttle-no-data-loss assertion; the throttle is "+
					"broker-driven via daemon flags and the guest never simulates it "+
					"(SEC-46)", envThrottleMount, envAllowPartial)
			}
			t.Fatalf("%s is required under the live gate (%s): it names a mount of the "+
				"broker-throttled scope so the SC2 throttle-no-data-loss assertion drives "+
				"a real over-budget burst; set %s=1 only to opt into a partial run on "+
				"purpose", envThrottleMount, envGate, envAllowPartial)
		}

		// Setup: the working subtree must exist under the downloadable prefix on
		// the throttled scope before the burst writes into it. This single mkdir
		// (and its parent-dir list) must fit inside the broker's burst budget and
		// succeed — it is NOT part of the throttle proof. VFS Mkdir is not retried
		// by the pacer, so if setup were throttled it would surface EIO here.
		throttleBase := filepath.Join(env.throttleMount, e2eDirName)
		if err := os.Mkdir(throttleBase, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			t.Fatalf("create throttle working directory %q: %v", throttleBase, err)
		}

		// Fire a burst of N separate small writes as fast as possible. Each
		// os.WriteFile is its own single-op fileUpload (the 4 KiB payload stays
		// well under the ~4 MiB RPC ceiling so it is exactly one op, keeping the op
		// accounting clean). Issued back-to-back in well under a second, the burst
		// blows past the 2/2 bucket: the broker refuses the over-budget ops with
		// the throttle / resource_exhausted class. A refused metadata op (the
		// dir-stat the open-create path issues) surfaces EIO straight to the
		// WriteFile here — that is the EXPECTED throttle signal, not a bug.
		const burstWrites = 6
		const throttlePayloadSize = 4 << 10 // 4 KiB: small, single-op, fast.
		// throttleBackoff lets the 2/s token bucket refill before a caller retry;
		// at 2 ops/s a single token returns in ~500ms, so 600ms clears it with a
		// margin. This is the CALLER backing off (SEC-46), not a pacer guarantee.
		const throttleBackoff = 600 * time.Millisecond
		type throttledFile struct {
			scopeRelPath string
			data         []byte
		}
		written := make([]throttledFile, 0, burstWrites)
		// recoveredAfterThrottle records whether at least one write FAILED under
		// the burst and then SUCCEEDED after the caller backed off. That
		// fail-then-recover-on-backoff pattern is the throttle discriminator: the
		// per-session ops/s ceiling refuses an over-budget op (surfacing an opaque
		// EIO at the FUSE syscall boundary — the broker's resource_exhausted text
		// stays in its stderr slog and does not cross the kernel, and this ceiling
		// denies before the audit stage so it is not in the audit sink either), but
		// the op SUCCEEDS once a token refills. A genuine, unrelated fault would NOT
		// be cured by waiting — it would keep failing to settleTimeout and fatal
		// below — so recovery-after-backoff cannot be a non-throttle EIO in
		// disguise. If NO write ever has to recover, the bucket was too loose and
		// SC2 proved nothing, so the test fails at the end.
		recoveredAfterThrottle := false
		deadline := time.Now().Add(settleTimeout)
		for i := 0; i < burstWrites; i++ {
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				t.Fatalf("generate throttle burst nonce %d: %v", i, err)
			}
			name := "throttled-" + hex.EncodeToString(nonce) + ".bin"
			data := make([]byte, throttlePayloadSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("generate throttle burst payload %d: %v", i, err)
			}
			path := filepath.Join(throttleBase, name)

			// Write with caller-side back-off-and-retry. A throttled op EIOs here;
			// per SEC-46 retrying it is the CALLER's job, so the TEST sleeps for the
			// bucket to refill and tries the SAME write again, bounded by
			// settleTimeout. (b) below asserts the recovered write is byte-identical
			// broker-side — eventual success; the broker's no-partial-stage
			// atomicity is its own property, not something this guest read proves.
			failedAtLeastOnce := false
			for {
				err := os.WriteFile(path, data, 0o644)
				if err == nil {
					if failedAtLeastOnce {
						// Failed under the burst with EIO, then succeeded after
						// backoff: the signature of a per-session throttle clearing on
						// refill (see the errno discrimination below).
						recoveredAfterThrottle = true
					}
					break
				}
				// Discriminate the refusal by errno. The per-session ops/s ceiling
				// surfaces at the FUSE syscall boundary as EIO (the broker's
				// resource_exhausted text stays in its stderr slog and never crosses
				// the kernel). Any OTHER errno — EROFS, ENOSPC, EACCES — is NOT a
				// throttle and fails the test immediately, so a real data-path
				// regression can never masquerade as "throttle observed". Only EIO
				// is eligible for the back-off-and-retry recovery path.
				if !errors.Is(err, syscall.EIO) {
					t.Fatalf("throttle burst write %d (%q) failed with a non-EIO error, "+
						"which is not the per-session throttle signal (a throttle surfaces as "+
						"EIO at the FUSE boundary); this is a real fault, not backpressure: %v",
						i, name, err)
				}
				failedAtLeastOnce = true
				if time.Now().After(deadline) {
					t.Fatalf("throttle burst write %d (%q) never recovered within %s: "+
						"the caller retried on backoff but the write kept failing with EIO, so "+
						"this is not a transient throttle but a stuck fault: %v",
						i, name, settleTimeout, err)
				}
				// Back off so the token bucket refills, then retry the same write.
				// Recovery is the caller's responsibility under SEC-46, not the
				// guest pacer's: metadata ops are not retried by the pacer.
				t.Logf("throttle burst write %d (%q) refused with EIO (expected under the "+
					"per-op ceiling); backing off %s and retrying: %v",
					i, name, throttleBackoff, err)
				time.Sleep(throttleBackoff)
			}
			written = append(written, throttledFile{scopeRelPath: scopeRel(name), data: data})
		}

		// (a) The throttle MUST have fired AND been recovered from. At least one
		// write had to be refused under the burst and then succeed after the
		// caller backed off. If nothing ever had to recover, the bucket was too
		// loose and this step did not exercise SC2 at all — fail rather than pass a
		// test that proved nothing. (A persistent non-throttle fault cannot reach
		// here: it would have fatalled in the retry loop above on settleTimeout.)
		if !recoveredAfterThrottle {
			t.Fatalf("no write was refused-then-recovered across %d back-to-back writes "+
				"against the throttled scope: the per-session ceiling (ops-per-second 2 / "+
				"burst 2) was too loose to exercise SC2 — the throttle never fired, so this "+
				"step proved nothing", burstWrites)
		}

		// (b) RECOVERY LANDED BYTE-IDENTICAL (eventual success): every write that
		// recovered to success is byte-identical broker-side. This proves the
		// recovered object is whole; it does not by itself prove mid-throttle
		// atomicity (a partial stage would be overwritten by the clean retry and
		// still hash-match — that no-partial-stage property is the broker's).
		// Fail-closed like the rw workspace.
		for i, f := range written {
			t.Logf("asserting throttle burst write %d/%d recovered byte-identical: %s",
				i+1, burstWrites, f.scopeRelPath)
			assertBrokerThrottlePersisted(t, env, f.scopeRelPath, f.data)
		}
	})

	// Step 10 — graceful teardown: SIGTERM the running mount process; every
	// mountpoint unmounts and the ready-file is gone afterward. This step targets
	// the process the harness runs; the PID and ready-file come from the harness.
	// It is declared last so the data-path proofs (steps 11 and 12) run while the
	// mounts are live; the teardown then verifies the process exits cleanly.
	t.Run("10_sigterm_teardown", func(t *testing.T) {
		// 05-02: the harness exports the mount process PID and the ready-file
		// path; on the live host this signals the process and asserts teardown.
		if env.mountPID == 0 {
			if allowPartial() {
				t.Skipf("%s unset and partial mode explicitly opted into via %s — "+
					"skipping the graceful-teardown assertion", envMountPID, envAllowPartial)
			}
			t.Fatalf("%s is required under the live gate (%s): the graceful-teardown "+
				"assertion must signal the real mount process; set %s=1 only to opt "+
				"into a partial run on purpose", envMountPID, envGate, envAllowPartial)
		}
		proc, err := os.FindProcess(env.mountPID)
		if err != nil {
			t.Fatalf("find mount process %d: %v", env.mountPID, err)
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("SIGTERM mount process %d: %v", env.mountPID, err)
		}
		// After graceful unmount the mountpoints no longer back a live FUSE
		// filesystem and the ready-file is removed.
		if env.readyFile != "" {
			waitGone(t, env.readyFile)
		}
		deadline := time.Now().Add(settleTimeout)
		for {
			_, rwErr := os.Stat(smallPath)
			if rwErr != nil {
				return // the mount no longer serves the path: torn down
			}
			if time.Now().After(deadline) {
				t.Fatalf("mountpoint %q still served after SIGTERM teardown", env.rwMount)
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
}

// assertBrokerPersisted proves that the bytes written through the rw mount
// actually reached the broker's engine-root workspace, hashing the file as it
// sits in that workspace volume (mounted read-only into the runner) rather than
// reading it back through the FUSE mount — a FUSE read-back can be served from
// the local VFS write-back cache without any fileUpload ever succeeding, which
// is exactly how the earlier gate passed while the broker workspace stayed
// empty. relPath is the path under the rw mount; it maps 1:1 to the path under
// the workspace root (both filesystem-relative to the same scope).
//
// It is fail-closed under the live gate: with the workspace env unset it fatals
// unless the operator explicitly opted into a partial run, so a release can
// never go green with the broker-persistence assertion silently skipped. The
// poll tolerates the asynchronous write-back delay before the bytes appear.
func assertBrokerPersisted(t *testing.T, env liveEnv, relPath string, want []byte) {
	t.Helper()
	if env.brokerRWWorkspace == "" {
		if allowPartial() {
			t.Logf("%s unset and partial mode explicitly opted into via %s — "+
				"skipping the broker-side persistence assertion for %q (the FUSE "+
				"read-back alone does not prove the upload reached the broker)",
				envBrokerRWWorkspace, envAllowPartial, relPath)
			return
		}
		t.Fatalf("%s is required under the live gate (%s): it names the broker-rw "+
			"engine-root workspace (mounted read-only into the runner) so the write "+
			"steps assert the bytes reached the broker, not just the local VFS cache; "+
			"set %s=1 only to opt into a partial run on purpose",
			envBrokerRWWorkspace, envGate, envAllowPartial)
	}
	assertWorkspaceHasBytes(t, env.brokerRWWorkspace, relPath, want, settleTimeout)
}

// assertBrokerThrottlePersisted is the throttle-scope analogue of
// assertBrokerPersisted: it proves the throttled write reached the throttle
// broker's engine-root workspace byte-identical AFTER the pacer's retries, so
// the SC2 proof is "a throttled write still lands without loss" rather than
// "the gate fails closed". It is fail-closed under the live gate on the same
// terms — a missing workspace env fatals unless a partial run was explicitly
// opted into. relPath maps 1:1 to the path under the throttle workspace root.
func assertBrokerThrottlePersisted(t *testing.T, env liveEnv, relPath string, want []byte) {
	t.Helper()
	if env.brokerThrottleWorkspace == "" {
		if allowPartial() {
			t.Logf("%s unset and partial mode explicitly opted into via %s — "+
				"skipping the throttle-scope persistence assertion for %q (the FUSE "+
				"read-back alone does not prove the throttled upload reached the broker)",
				envBrokerThrottleWorkspace, envAllowPartial, relPath)
			return
		}
		t.Fatalf("%s is required under the live gate (%s): it names the throttle "+
			"broker's engine-root workspace (mounted read-only into the runner) so the "+
			"SC2 step asserts the throttled, retried write landed byte-identical broker-"+
			"side, not just in the local VFS cache; set %s=1 only to opt into a partial "+
			"run on purpose", envBrokerThrottleWorkspace, envGate, envAllowPartial)
	}
	// The throttle step gets the wider landing budget: a throttled upload's
	// writeback backoff (5/10/20/40s) can outlast the 30s the unthrottled steps
	// use. The byte-identity check below is unchanged, so the SC2 proof (the
	// throttled, retried write landed byte-identical broker-side) is preserved —
	// only the wait is widened, never what is asserted.
	assertWorkspaceHasBytes(t, env.brokerThrottleWorkspace, relPath, want, throttleSettleTimeout)
}

// assertWorkspaceHasBytes polls the file at relPath under a broker engine-root
// workspace (mounted read-only into the runner) until its content hashes
// byte-identical to want or the given budget elapses. Reading the workspace
// volume directly — never the FUSE mount — is what makes the assertion prove
// the broker data path: a FUSE read-back can be served from the local VFS
// write-back cache without any upload ever reaching the broker. The poll
// tolerates the asynchronous write-back delay before the bytes appear.
//
// within is the landing budget: the unthrottled write steps pass settleTimeout
// (30s); the SC2 throttle step passes throttleSettleTimeout (120s) because a
// throttled upload's writeback backoff can outlast the 30s window. The
// byte-identity (sha256) check is the same regardless of budget, so widening
// the wait never weakens what the assertion proves.
func assertWorkspaceHasBytes(t *testing.T, workspace, relPath string, want []byte, within time.Duration) {
	t.Helper()
	wantSum := sha256.Sum256(want)
	brokerPath := filepath.Join(workspace, filepath.FromSlash(relPath))
	deadline := time.Now().Add(within)
	var lastErr error
	var lastLen int
	for {
		b, err := os.ReadFile(brokerPath)
		if err == nil {
			lastLen = len(b)
			if sha256.Sum256(b) == wantSum {
				return // byte-identical broker-side: the upload landed.
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker-side persistence of %q never matched: broker path %q "+
				"(last read %d bytes, want %d, err %v) — the bytes written through the "+
				"mount did not reach the broker workspace byte-identical",
				relPath, brokerPath, lastLen, len(want), lastErr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// assertBrokerPresent proves that a namespace mutation (mkdir, or the
// destination of a rename) actually reached the broker's engine-root workspace,
// stat-ing the path as it sits in that workspace volume rather than through the
// FUSE mount — a FUSE stat can be served from the local dir cache without the
// makeDirectory/moveDirectory RPC ever succeeding, the same vacuum class the
// write steps already close by hashing broker-side. relPath is the path under
// the rw mount; it maps 1:1 to the path under the workspace root.
//
// Fail-closed under the live gate via the SAME partial hatch as
// assertBrokerPersisted: with the workspace env unset it fatals unless the
// operator explicitly opted into a partial run. The poll tolerates the
// asynchronous delay before the entry appears.
func assertBrokerPresent(t *testing.T, env liveEnv, relPath string) {
	t.Helper()
	if env.brokerRWWorkspace == "" {
		if allowPartial() {
			t.Logf("%s unset and partial mode explicitly opted into via %s — "+
				"skipping the broker-side presence assertion for %q (the FUSE view "+
				"alone does not prove the mutation reached the broker)",
				envBrokerRWWorkspace, envAllowPartial, relPath)
			return
		}
		t.Fatalf("%s is required under the live gate (%s): the mutating steps assert "+
			"the namespace change reached the broker, not just the local dir cache; "+
			"set %s=1 only to opt into a partial run on purpose",
			envBrokerRWWorkspace, envGate, envAllowPartial)
	}

	brokerPath := filepath.Join(env.brokerRWWorkspace, filepath.FromSlash(relPath))
	deadline := time.Now().Add(settleTimeout)
	var lastErr error
	for {
		if _, err := os.Stat(brokerPath); err == nil {
			return // the mutation landed in the broker workspace.
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker-side presence of %q never appeared: broker path %q (err %v) "+
				"— the mutation made through the mount did not reach the broker workspace",
				relPath, brokerPath, lastErr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// assertBrokerAbsent proves that a removal (rmdir, or the source of a rename)
// actually took effect in the broker's engine-root workspace, polling until the
// path is gone from that workspace volume — a FUSE stat can report a removed
// entry as gone from the dir cache without the removeDirectory/moveFile RPC ever
// reaching the broker. Same fail-closed partial hatch as the present/persisted
// assertions.
func assertBrokerAbsent(t *testing.T, env liveEnv, relPath string) {
	t.Helper()
	if env.brokerRWWorkspace == "" {
		if allowPartial() {
			t.Logf("%s unset and partial mode explicitly opted into via %s — "+
				"skipping the broker-side absence assertion for %q",
				envBrokerRWWorkspace, envAllowPartial, relPath)
			return
		}
		t.Fatalf("%s is required under the live gate (%s): the removal steps assert the "+
			"namespace change reached the broker, not just the local dir cache; set %s=1 "+
			"only to opt into a partial run on purpose",
			envBrokerRWWorkspace, envGate, envAllowPartial)
	}

	brokerPath := filepath.Join(env.brokerRWWorkspace, filepath.FromSlash(relPath))
	deadline := time.Now().Add(settleTimeout)
	for {
		_, err := os.Stat(brokerPath)
		if errors.Is(err, fs.ErrNotExist) {
			return // the removal took effect broker-side.
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker-side absence of %q never took effect: broker path %q still "+
				"present (err %v) — the removal made through the mount did not reach the "+
				"broker workspace",
				relPath, brokerPath, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// readBackEventually reads path, polling until it reaches the wanted length or
// the settle timeout elapses (the VFS cache is eventually consistent).
func readBackEventually(t *testing.T, path string, wantLen int) []byte {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	var last []byte
	for {
		b, err := os.ReadFile(path)
		if err == nil {
			last = b
			if len(b) == wantLen {
				return b
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("read-back of %q never reached %d bytes (last %d, err %v)", path, wantLen, len(last), err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// listEventually lists dir, polling until every wanted name appears or the
// settle timeout elapses. Returns the final entry names.
func listEventually(t *testing.T, dir string, want ...string) []string {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	for {
		entries, err := os.ReadDir(dir)
		if err == nil {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if allPresent(names, want) {
				return names
			}
			if time.Now().After(deadline) {
				return names
			}
		} else if time.Now().After(deadline) {
			t.Fatalf("list of %q failed: %v", dir, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitGone polls until path no longer exists or the settle timeout elapses.
func waitGone(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	for {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%q still present after removal", path)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// allPresent reports whether every want is in names.
func allPresent(names, want []string) bool {
	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// assertContains fails the test if name is absent from names.
func assertContains(t *testing.T, names []string, name string) {
	t.Helper()
	for _, n := range names {
		if n == name {
			return
		}
	}
	t.Fatalf("directory listing missing %q; got %v", name, names)
}
