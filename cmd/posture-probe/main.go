// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command posture-probe is a one-shot runtime-posture witness for the live e2e
// harness. It is built into the SAME image as the mount binary and run in a
// container that carries the IDENTICAL hardening posture as the mount service
// (read_only rootfs + a tmpfs at /root/.cache, cap_drop:[ALL]+cap_add:[SYS_ADMIN],
// no-new-privileges, the same AppArmor and seccomp profiles).
//
// Because the probe runs INSIDE its own mount namespace and uid, the kernel's
// read_only-rootfs and tmpfs semantics apply to its own syscalls directly: a
// create under the image root really surfaces EROFS and a write under the tmpfs
// really succeeds. This avoids the cross-container /proc/<pid>/root write trick,
// which the kernel denies with EACCES when a test-runner in a different
// namespace/uid attempts a write through another container's procfs root before
// the target's mount-table semantics ever apply.
//
// The probe writes a single-line verdict to the path named by OCU_E2E_PROBE_VERDICT
// (default /run/probe/verdict) on a volume shared with the test-runner. The
// runner reads the verdict instead of performing the write itself. The probe
// exits 0 only when BOTH arms pass; otherwise it writes the failing detail to
// the verdict file and stderr and exits non-zero.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// envVerdictPath names the file the probe writes its verdict to, on a volume
	// shared with the test-runner. Defaults to /run/ocu/posture-verdict — under
	// /run/ocu because the IDENTICAL hardening posture includes the narrow
	// AppArmor profile, whose only permitted runtime-write surfaces are
	// /root/.cache, /run/ocu, and /mnt/user-data. The verdict rides the same
	// /run/ocu volume the ready-file handoff uses, with a distinct filename, so
	// the verdict write stays inside the profile's allowance without widening it.
	envVerdictPath = "OCU_E2E_PROBE_VERDICT"
	defaultVerdict = "/run/ocu/posture-verdict"

	// rootfsProbeDir is the image-root directory the probe attempts to create a
	// file under; read_only:true must make the create fail with EROFS. The mount
	// binary lives at /, so / (the image root) is the natural read-only surface.
	rootfsProbeDir = "/"
	rootfsProbe    = "ocu-rootfs-probe"

	// tmpfsProbeDir is the single declared writable surface — the VFS-cache tmpfs
	// at /root/.cache. A write+read-back here must succeed byte-identical.
	tmpfsProbeDir = "/root/.cache"
	tmpfsProbe    = "ocu-tmpfs-probe"
)

func main() {
	verdictPath := os.Getenv(envVerdictPath)
	if verdictPath == "" {
		verdictPath = defaultVerdict
	}

	rootfsOK, rootfsDetail := probeRootfsReadOnly()
	tmpfsOK, tmpfsDetail := probeTmpfsWritable()

	// One line, space-separated key=value tokens. Each token is "ok" on success
	// or a short failing detail. The test-runner asserts ROOTFS_EROFS=ok and
	// TMPFS_WRITABLE=ok.
	verdict := fmt.Sprintf("ROOTFS_EROFS=%s TMPFS_WRITABLE=%s\n", rootfsDetail, tmpfsDetail)

	if werr := writeVerdict(verdictPath, verdict); werr != nil {
		// A verdict the runner can never read is itself a hard failure; surface it
		// loudly so the absent-verdict path in the test does not mask a probe that
		// could not report.
		fmt.Fprintf(os.Stderr, "posture-probe: write verdict %q: %v\n", verdictPath, werr)
		os.Exit(2)
	}

	if rootfsOK && tmpfsOK {
		return
	}
	fmt.Fprintf(os.Stderr, "posture-probe: FAIL %s", verdict)
	os.Exit(1)
}

// probeRootfsReadOnly attempts to create a file under the image root. read_only:
// true must make the create fail with EROFS. A successful create (rootfs is
// writable) or any errno OTHER than EROFS is a failure; only EROFS is the
// read-only proof. Returns (ok, detail) where detail is "ok" on success or a
// short reason otherwise.
func probeRootfsReadOnly() (bool, string) {
	probe := filepath.Join(rootfsProbeDir, rootfsProbe)
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		_ = f.Close()
		_ = os.Remove(probe)
		return false, "writable(create-succeeded)"
	}
	if !errors.Is(err, syscall.EROFS) {
		return false, fmt.Sprintf("errno-not-erofs(%v)", err)
	}
	return true, "ok"
}

// probeTmpfsWritable writes a byte string under the tmpfs and reads it back,
// asserting byte-identity. A failed create or a read-back mismatch is a failure;
// success requires both write and identical read-back. Returns (ok, detail).
func probeTmpfsWritable() (bool, string) {
	probe := filepath.Join(tmpfsProbeDir, tmpfsProbe)
	want := []byte("ocu tmpfs writability probe\n")

	if err := os.WriteFile(probe, want, 0o644); err != nil {
		return false, fmt.Sprintf("write-failed(%v)", err)
	}
	defer func() { _ = os.Remove(probe) }()

	got, err := os.ReadFile(probe)
	if err != nil {
		return false, fmt.Sprintf("readback-failed(%v)", err)
	}
	if string(got) != string(want) {
		return false, fmt.Sprintf("readback-mismatch(%d!=%d bytes)", len(got), len(want))
	}
	return true, "ok"
}

// writeVerdict creates the parent directory if absent and writes the verdict
// atomically enough for a single one-shot reader: a temp file in the same
// directory renamed into place, so the runner never reads a half-written line.
func writeVerdict(path, verdict string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".verdict-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.WriteString(tmp, verdict); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
