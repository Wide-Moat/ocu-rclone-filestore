// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeReadOnlyAt_WritableSurface drives the read-only arm against a writable
// directory: the create succeeds, so the arm reports the surface is NOT read-only.
// This is the negative of the EROFS expectation — it proves the arm distinguishes a
// writable surface from a read-only one. The real EROFS arm (a genuine read_only
// rootfs mount) is the amd64/arm64 e2e binding proof, since a unit test cannot
// synthesize a kernel EROFS without an actual read-only mount.
func TestProbeReadOnlyAt_WritableSurface(t *testing.T) {
	dir := t.TempDir()
	ok, detail := probeReadOnlyAt(dir)
	if ok {
		t.Fatalf("probeReadOnlyAt(%q) on a writable dir = ok; want not-ok (writable surface)", dir)
	}
	if detail != "writable(create-succeeded)" {
		t.Fatalf("probeReadOnlyAt(%q) detail = %q; want %q", dir, detail, "writable(create-succeeded)")
	}
	// The probe must clean up after itself: the probe file must not survive.
	if _, err := os.Stat(filepath.Join(dir, rootfsProbe)); !os.IsNotExist(err) {
		t.Fatalf("probe file left behind under %q: stat err = %v; want IsNotExist", dir, err)
	}
}

// TestProbeReadOnlyAt_NonErofsErrno drives the arm down its errno-not-erofs branch:
// a create that fails with an errno OTHER than EROFS is a failure with a detail
// naming the errno, never the read-only proof. We force ENOENT by pointing at a
// non-existent nested parent. The real EROFS arm is the e2e binding proof.
func TestProbeReadOnlyAt_NonErofsErrno(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent-parent", "still-absent")
	ok, detail := probeReadOnlyAt(dir)
	if ok {
		t.Fatalf("probeReadOnlyAt(%q) with an absent parent = ok; want not-ok", dir)
	}
	if !strings.HasPrefix(detail, "errno-not-erofs(") {
		t.Fatalf("probeReadOnlyAt(%q) detail = %q; want errno-not-erofs(...) prefix", dir, detail)
	}
}

// TestProbeWritableAt_RoundTrip drives the writable arm down its success path: a
// write followed by a byte-identical read-back returns (true, "ok"), and the probe
// file is cleaned up.
func TestProbeWritableAt_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	ok, detail := probeWritableAt(dir)
	if !ok {
		t.Fatalf("probeWritableAt(%q) = not-ok (%q); want ok", dir, detail)
	}
	if detail != "ok" {
		t.Fatalf("probeWritableAt(%q) detail = %q; want %q", dir, detail, "ok")
	}
	if _, err := os.Stat(filepath.Join(dir, tmpfsProbe)); !os.IsNotExist(err) {
		t.Fatalf("probe file left behind under %q: stat err = %v; want IsNotExist", dir, err)
	}
}

// TestProbeWritableAt_WriteFailed drives the writable arm down its write-failed
// branch: pointing at a non-existent nested directory makes the create fail.
func TestProbeWritableAt_WriteFailed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent-parent")
	ok, detail := probeWritableAt(dir)
	if ok {
		t.Fatalf("probeWritableAt(%q) with an absent parent = ok; want not-ok", dir)
	}
	if !strings.HasPrefix(detail, "write-failed(") {
		t.Fatalf("probeWritableAt(%q) detail = %q; want write-failed(...) prefix", dir, detail)
	}
}

// TestProbeWritableAt_TruncatesStaleFile pre-seeds the probe path with stale content
// of a different length, then asserts probeWritableAt truncates and rewrites it to
// the canonical bytes and reads them back byte-identical (true, "ok"). This proves
// the write does not append to or partially overwrite a pre-existing file — the
// read-back equality holds against an exact replacement, not a stale tail.
func TestProbeWritableAt_TruncatesStaleFile(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(dir, tmpfsProbe)
	if err := os.WriteFile(probe, []byte("stale-different-length-content\n"), 0o600); err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	ok, detail := probeWritableAt(dir)
	if !ok || detail != "ok" {
		t.Fatalf("probeWritableAt(%q) over a stale file = (%v,%q); want (true,\"ok\") after truncating rewrite", dir, ok, detail)
	}
}

// TestProbeWritableAt_ReadbackMismatch drives the byte-count-mismatch arm: the probe
// path is a symlink to /dev/null, so the write is accepted (and discarded) while the
// read-back returns zero bytes — a deterministic divergence from the 28-byte want.
// This exercises the defensive byte-count guard against a torn write under the live
// tmpfs, which a same-bytes round-trip can never reach.
func TestProbeWritableAt_ReadbackMismatch(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skipf("/dev/null unavailable (%v); the byte-count-mismatch arm needs a discard sink", err)
	}
	dir := t.TempDir()
	probe := filepath.Join(dir, tmpfsProbe)
	if err := os.Symlink("/dev/null", probe); err != nil {
		t.Fatalf("symlink probe to /dev/null: %v", err)
	}
	ok, detail := probeWritableAt(dir)
	if ok {
		t.Fatalf("probeWritableAt over a /dev/null sink = ok; want not-ok (zero bytes read back)")
	}
	if !strings.HasPrefix(detail, "readback-mismatch(") {
		t.Fatalf("probeWritableAt detail = %q; want readback-mismatch(...) prefix", detail)
	}
}

// TestProbeWritableAt_ReadbackFailed drives the read-back-failed arm: the probe path
// is a symlink to a pre-existing write-only (0o200) file, so the write is accepted
// while the subsequent read-back is denied with EACCES. As root the mode bits do not
// deny, so the arm is non-root-only and guarded accordingly; CI runs as non-root.
func TestProbeWritableAt_ReadbackFailed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0o200 file does not deny read-back; the readback-failed arm is non-root only")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "write-only-target")
	if err := os.WriteFile(target, []byte("seed"), 0o200); err != nil {
		t.Fatalf("seed write-only target: %v", err)
	}
	probe := filepath.Join(dir, tmpfsProbe)
	if err := os.Symlink(target, probe); err != nil {
		t.Fatalf("symlink probe to write-only target: %v", err)
	}
	ok, detail := probeWritableAt(dir)
	if ok {
		t.Fatalf("probeWritableAt over a write-only sink = ok; want not-ok (read-back denied)")
	}
	if !strings.HasPrefix(detail, "readback-failed(") {
		t.Fatalf("probeWritableAt detail = %q; want readback-failed(...) prefix", detail)
	}
}

// TestProbeRootfsReadOnly_ProductionWrapper drives the production wrapper that binds
// the read-only arm to the rootfsProbeDir constant. The unit/CI host's rootfs
// writability is environment-dependent (a plain dev host has a writable root; a
// sandboxed or container build host may itself surface EROFS at /), so the wrapper's
// boolean is not asserted here — that is the e2e binding proof. The contract under
// test is that the wrapper binds to the constant, returns a well-formed non-empty
// detail, and never panics.
func TestProbeRootfsReadOnly_ProductionWrapper(t *testing.T) {
	_, detail := probeRootfsReadOnly()
	if detail == "" {
		t.Fatal("probeRootfsReadOnly() returned an empty detail; want a short reason")
	}
}

// TestProbeTmpfsWritable_ProductionWrapper drives the production wrapper that binds
// the writable arm to tmpfsProbeDir. The unit host may not have /root/.cache, so the
// wrapper may report write-failed; the contract under test is that the wrapper
// returns a well-formed (bool, non-empty detail) and never panics, exercising the
// constant-binding path.
func TestProbeTmpfsWritable_ProductionWrapper(t *testing.T) {
	_, detail := probeTmpfsWritable()
	if detail == "" {
		t.Fatal("probeTmpfsWritable() returned an empty detail; want a short reason")
	}
}

// TestWriteVerdict_CreateTempFails drives writeVerdict down its CreateTemp-error
// branch: the verdict path's parent already exists as a regular file, so MkdirAll on
// filepath.Dir(path) is a no-op-success when dir IS that file? No — instead we make
// the parent a path that MkdirAll yields but CreateTemp cannot write into by
// removing write permission. As root this may not deny; guard accordingly.
func TestWriteVerdict_CreateTempFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0o500 directory does not deny CreateTemp; the deny path is non-root only")
	}
	base := t.TempDir()
	roDir := filepath.Join(base, "ro")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("mkdir ro dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
	path := filepath.Join(roDir, "verdict")
	if err := writeVerdict(path, "x\n"); err == nil {
		t.Fatalf("writeVerdict(%q) into a 0o500 dir = nil; want a CreateTemp error", path)
	}
}

// arm returns a probeFn stub that yields the given (ok, detail), so run's verdict and
// exit-code wiring can be driven deterministically without the host's real surfaces.
func arm(ok bool, detail string) probeFn {
	return func() (bool, string) { return ok, detail }
}

// TestRun_BothArmsOK drives run's happy path: both arms report ok, so run writes a
// both-ok verdict, returns exit code 0, and stays silent on stderr.
func TestRun_BothArmsOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "verdict")
	var stderr bytes.Buffer

	code := run(path, &stderr, arm(true, "ok"), arm(true, "ok"))
	if code != 0 {
		t.Fatalf("run with both arms ok = %d; want 0", code)
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: path is a test-local TempDir join, not user input.
	if err != nil {
		t.Fatalf("verdict file not written: %v", err)
	}
	if want := "ROOTFS_EROFS=ok TMPFS_WRITABLE=ok\n"; string(got) != want {
		t.Fatalf("verdict = %q; want %q", string(got), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("a passing run wrote to stderr: %q", stderr.String())
	}
}

// TestRun_ArmFails drives run's an-arm-failed path: one arm reports a failing detail,
// so run writes the failing verdict, returns exit code 1, and emits FAIL to stderr.
// The failing detail is threaded verbatim into the verdict line.
func TestRun_ArmFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdict")
	var stderr bytes.Buffer

	code := run(path, &stderr, arm(false, "writable(create-succeeded)"), arm(true, "ok"))
	if code != 1 {
		t.Fatalf("run with a failing arm = %d; want 1", code)
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: path is a test-local TempDir join, not user input.
	if err != nil {
		t.Fatalf("verdict file not written: %v", err)
	}
	if want := "ROOTFS_EROFS=writable(create-succeeded) TMPFS_WRITABLE=ok\n"; string(got) != want {
		t.Fatalf("verdict = %q; want %q", string(got), want)
	}
	if !strings.Contains(stderr.String(), "posture-probe: FAIL") {
		t.Fatalf("failing run did not emit FAIL to stderr; got %q", stderr.String())
	}
}

// TestRun_VerdictUnwritable drives run down its verdict-unwritable branch by pointing
// the verdict at a path whose parent traverses a regular file, so MkdirAll inside
// writeVerdict fails. run must return exit code 2 and name the unwritable verdict on
// stderr — before the arm verdict is ever considered.
func TestRun_VerdictUnwritable(t *testing.T) {
	base := t.TempDir()
	fileAsDir := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed regular file: %v", err)
	}
	path := filepath.Join(fileAsDir, "child", "verdict")
	var stderr bytes.Buffer

	if code := run(path, &stderr, arm(true, "ok"), arm(true, "ok")); code != 2 {
		t.Fatalf("run with an unwritable verdict path = %d; want 2", code)
	}
	if !strings.Contains(stderr.String(), "write verdict") {
		t.Fatalf("unwritable run did not name the verdict on stderr; got %q", stderr.String())
	}
}

// TestWriteVerdict_AtomicWrite asserts writeVerdict writes the verdict byte-for-byte
// and creates an absent parent directory on the way.
func TestWriteVerdict_AtomicWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent", "parent", "chain")
	path := filepath.Join(dir, "verdict")
	want := "ROOTFS_EROFS=ok TMPFS_WRITABLE=ok\n"

	if err := writeVerdict(path, want); err != nil {
		t.Fatalf("writeVerdict(%q) = %v; want nil", path, err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: path is a test-local TempDir join, not user input.
	if err != nil {
		t.Fatalf("read back verdict %q: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("verdict content = %q; want %q", string(got), want)
	}

	// MkdirAll must have created the absent parent chain.
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		t.Fatalf("writeVerdict did not create parent dir %q: info=%v err=%v", dir, info, statErr)
	}

	// No stray temp file must survive the rename.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %q: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".verdict-") {
			t.Fatalf("temp file %q left behind in %q after rename", e.Name(), dir)
		}
	}
}

// TestWriteVerdict_MkdirFails drives writeVerdict down its MkdirAll-error branch by
// pointing the parent at a path whose component is an existing regular file.
func TestWriteVerdict_MkdirFails(t *testing.T) {
	base := t.TempDir()
	fileAsDir := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed regular file: %v", err)
	}
	// path's parent now traverses through a regular file → MkdirAll fails.
	path := filepath.Join(fileAsDir, "child", "verdict")
	if err := writeVerdict(path, "x\n"); err == nil {
		t.Fatalf("writeVerdict(%q) = nil; want an error (parent traverses a regular file)", path)
	}
}
