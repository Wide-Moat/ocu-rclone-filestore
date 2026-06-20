// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// This file pins the RUNTIME (kernel-enforced) hardening posture of the guest
// mount CONTAINER, as observed against the live mount process. The compose
// content pins in test/posture assert what the YAML says; this asserts what the
// kernel actually did with it at run time, so a posture that is silently NOT
// applied (a runtime that ignores read_only, a capability set wider than
// declared) goes red here even though the YAML still reads correctly.
//
// HOW THE ASSERTION REACHES THE MOUNT CONTAINER. The mount image is distroless
// (no shell, no tooling), so `docker compose exec mount sh -c ...` cannot run
// inside it. Instead the test-runner service already runs in the HOST PID
// namespace (pid: "host" in the compose graph) and resolves the mount process's
// host-side PID into OCU_E2E_MOUNT_PID. From the host PID namespace the runner
// can observe the mount process through procfs:
//   - /proc/<pid>/status carries the process's effective capability mask
//     (CapEff), the kernel's own accounting of what cap_drop/cap_add produced;
//   - /proc/<pid>/root is the mount process's mount-namespace root, so a write
//     attempted through that path is mediated by the mount CONTAINER's own
//     mount table (its read-only rootfs, its /root/.cache tmpfs), not the
//     runner's. This is the procfs equivalent of executing inside the mount
//     container, and it works precisely because the runner is host-PID-ns.
//
// arch binding. CapEff (c) and the read-only-rootfs EROFS (a) are KERNEL
// enforced and therefore CANNOT be verified on the Lima arm64 dev host the
// authoring happened on — there is no running Linux mount container there. They
// are AMD64-BINDING: the authoritative red-able proof is the amd64 CI live-e2e
// job (ci.yml "live e2e (data path)"), which brings the container up under a
// real Linux kernel and runs this test. The tmpfs-writability arm (b) is the
// positive companion: it proves the single declared writable surface really is
// writable, so (a) cannot pass merely because the whole filesystem is broken.
//
// The compile + logic of every arm is exercised by `go vet`/`go build -tags
// e2e` and by a dry reading of the asserted errno/mask; only the live kernel
// outcome is amd64-bound.

const (
	// envMountRoot names a path the mount process's image rootfs is expected to
	// expose as read-only. It is resolved THROUGH /proc/<pid>/root so the probe
	// lands in the mount container's filesystem, not the runner's. The probe
	// file name is appended by the test; the directory must exist in the image.
	// The mount binary lives at /ocu-rclone-filestore, so / (the image root) is
	// the natural read-only surface to probe.
	envMountImageRootProbeDir = "OCU_E2E_MOUNT_IMAGE_ROOT_PROBE_DIR"
	// envMountTmpfsProbeDir names the single declared writable surface inside the
	// mount container — the VFS-cache tmpfs at /root/.cache — resolved THROUGH
	// /proc/<pid>/root as well. A write+read-back here must succeed.
	envMountTmpfsProbeDir = "OCU_E2E_MOUNT_TMPFS_PROBE_DIR"
)

// capSysAdmin is the effective-capability mask the hardened mount process must
// carry and NOTHING ELSE: bit 21 (CAP_SYS_ADMIN), value 0x200000. cap_drop:
// [ALL] + cap_add: [SYS_ADMIN] in the compose graph must reduce CapEff to
// exactly this. Any other bit set means a capability leaked past the drop.
const capSysAdmin uint64 = 1 << 21 // 0x0000000000200000

// mountImageRootProbeDir returns the in-mount-container directory to probe for
// read-only-ness, defaulting to the image root "/" when the harness leaves it
// unset. The binary sits at /, so / is read-only in the hardened image.
func mountImageRootProbeDir() string {
	if v := os.Getenv(envMountImageRootProbeDir); v != "" {
		return v
	}
	return "/"
}

// mountTmpfsProbeDir returns the in-mount-container writable tmpfs directory to
// probe, defaulting to the declared VFS-cache tmpfs mountpoint.
func mountTmpfsProbeDir() string {
	if v := os.Getenv(envMountTmpfsProbeDir); v != "" {
		return v
	}
	return "/root/.cache"
}

// procRootPath joins an in-mount-container absolute path onto the mount
// process's mount-namespace root as seen from the host PID namespace, so the
// returned path, when opened by the runner, is mediated by the MOUNT
// container's mount table (its read-only rootfs, its tmpfs).
func procRootPath(pid int, inContainer string) string {
	// filepath.Join cleans the leading slash off inContainer so it nests under
	// the proc root path rather than escaping to the host root.
	return filepath.Join("/proc", strconv.Itoa(pid), "root", inContainer)
}

// readCapEff parses the CapEff hex mask out of /proc/<pid>/status. CapEff is the
// kernel's own record of the process's effective capabilities, so it reflects
// what the runtime actually applied from cap_drop/cap_add — not what the YAML
// declared.
func readCapEff(t *testing.T, pid int) uint64 {
	t.Helper()
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	f, err := os.Open(statusPath)
	if err != nil {
		t.Fatalf("open %s (the mount process must be visible in the host PID "+
			"namespace the runner joins): %v", statusPath, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		const prefix = "CapEff:"
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		hexField := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		v, perr := strconv.ParseUint(hexField, 16, 64)
		if perr != nil {
			t.Fatalf("parse CapEff %q from %s: %v", hexField, statusPath, perr)
		}
		return v
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", statusPath, err)
	}
	t.Fatalf("no CapEff line in %s", statusPath)
	return 0
}

// TestMountRuntimePosture asserts the live mount container's kernel-enforced
// hardening posture through procfs from the host-PID-namespace runner. It runs
// only under the live gate; on a host build (gate unset) it skips clean.
//
// LIMA-HONEST vs AMD64-BINDING (also marked per subtest):
//   - capeff_only_sys_admin   — AMD64-BINDING (kernel capability accounting).
//   - image_rootfs_read_only  — AMD64-BINDING (kernel read_only-rootfs EROFS).
//   - tmpfs_cache_writable    — positive companion; the write/read-back logic is
//     Lima-honest, but it too only runs inside the live harness because it needs
//     the running mount container's tmpfs. The amd64 CI job is authoritative.
func TestMountRuntimePosture(t *testing.T) {
	if os.Getenv(envGate) == "" {
		t.Skipf("%s not set — the mount runtime-posture assertion runs only against the "+
			"live container under a real Linux kernel (compose run test-runner); it skips "+
			"clean on a host build", envGate)
	}

	pidStr := os.Getenv(envMountPID)
	if pidStr == "" {
		if allowPartial() {
			t.Skipf("%s unset and partial mode explicitly opted into via %s — skipping the "+
				"mount runtime-posture assertion (it needs the live mount process's host PID "+
				"to read its CapEff and probe its rootfs through procfs)",
				envMountPID, envAllowPartial)
		}
		t.Fatalf("%s is required under the live gate (%s): the runtime-posture assertion "+
			"reads the mount process's CapEff and probes its read-only rootfs through "+
			"/proc/<pid>/; set %s=1 only to opt into a partial run on purpose",
			envMountPID, envGate, envAllowPartial)
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		t.Fatalf("invalid %s=%q: %v", envMountPID, pidStr, err)
	}

	// (c) CapEff must be EXACTLY CAP_SYS_ADMIN — AMD64-BINDING.
	//
	// cap_drop:[ALL] + cap_add:[SYS_ADMIN] must collapse the effective set to the
	// single bit the FUSE mount(2)/umount2(2) path needs. Any other bit set means
	// a capability survived the drop (a weakened posture), so the mask must equal
	// 0x200000 and nothing more. Dry logic: bits other than CAP_SYS_ADMIN are
	// isolated with (eff &^ capSysAdmin); a non-zero remainder is a leak, and a
	// missing CAP_SYS_ADMIN bit is an over-tightening that would break mount(2).
	t.Run("capeff_only_sys_admin", func(t *testing.T) {
		eff := readCapEff(t, pid)
		if eff&capSysAdmin == 0 {
			t.Fatalf("mount process CapEff=0x%016x is missing CAP_SYS_ADMIN (0x%016x): the "+
				"FUSE mount(2)/umount2(2) path needs it; cap_add dropped too much",
				eff, capSysAdmin)
		}
		if extra := eff &^ capSysAdmin; extra != 0 {
			t.Fatalf("mount process CapEff=0x%016x carries capabilities BEYOND CAP_SYS_ADMIN "+
				"(extra bits 0x%016x): cap_drop:[ALL]+cap_add:[SYS_ADMIN] must reduce the "+
				"effective set to exactly 0x%016x — a wider set is a weakened posture",
				eff, extra, capSysAdmin)
		}
		if eff != capSysAdmin {
			t.Fatalf("mount process CapEff=0x%016x, want exactly 0x%016x (only CAP_SYS_ADMIN)",
				eff, capSysAdmin)
		}
		t.Logf("AMD64-BINDING: mount process CapEff=0x%016x is exactly CAP_SYS_ADMIN", eff)
	})

	// (a) The image rootfs must be READ-ONLY — AMD64-BINDING.
	//
	// A write attempted THROUGH /proc/<pid>/root is mediated by the mount
	// container's mount table, so read_only:true makes the create fail with
	// EROFS. Dry logic: a successful create (err == nil) proves the rootfs is
	// writable — fatal, and the stray probe is removed; any errno OTHER than
	// EROFS (e.g. EACCES, ENOENT) is NOT the read-only signal and also fails, so
	// the pin cannot pass on an unrelated denial. Only EROFS is the read-only
	// proof.
	t.Run("image_rootfs_read_only", func(t *testing.T) {
		probe := procRootPath(pid, filepath.Join(mountImageRootProbeDir(), "ocu-rootfs-probe"))
		f, werr := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644)
		if werr == nil {
			_ = f.Close()
			_ = os.Remove(probe)
			t.Fatalf("created %q inside the mount container's rootfs: the image root is "+
				"WRITABLE, but read_only:true must make it read-only (the mount process "+
				"writes nothing to the image)", probe)
		}
		if !errors.Is(werr, syscall.EROFS) {
			t.Fatalf("write to the mount container rootfs probe %q failed with %v, not EROFS: "+
				"a read-only root must surface EROFS; a different errno is not the "+
				"read-only-rootfs signal", probe, werr)
		}
		t.Logf("AMD64-BINDING: mount container rootfs probe %q is read-only (EROFS)", probe)
	})

	// (b) The VFS-cache tmpfs must be WRITABLE — positive companion (logic
	// Lima-honest; runs live).
	//
	// /root/.cache is the single declared writable surface (tmpfs). Writing a
	// nonce'd probe through /proc/<pid>/root and reading it back byte-identical
	// proves the surface the rclone VFS cache needs is genuinely writable, so the
	// read-only-rootfs arm above is not passing merely because the whole
	// filesystem is unusable. Dry logic: a failed create or a read-back mismatch
	// fails; success requires both write and identical read-back.
	t.Run("tmpfs_cache_writable", func(t *testing.T) {
		nonce := make([]byte, 16)
		if _, nerr := rand.Read(nonce); nerr != nil {
			t.Fatalf("generate tmpfs probe nonce: %v", nerr)
		}
		name := "ocu-tmpfs-probe-" + hex.EncodeToString(nonce)
		probe := procRootPath(pid, filepath.Join(mountTmpfsProbeDir(), name))
		want := []byte(fmt.Sprintf("ocu tmpfs writability probe %s\n", hex.EncodeToString(nonce)))

		if werr := os.WriteFile(probe, want, 0o644); werr != nil {
			t.Fatalf("write to the mount container tmpfs probe %q failed: %v — the declared "+
				"writable VFS-cache tmpfs (%s) must accept writes",
				probe, werr, mountTmpfsProbeDir())
		}
		defer func() { _ = os.Remove(probe) }()

		got, rerr := os.ReadFile(probe)
		if rerr != nil {
			t.Fatalf("read back the tmpfs probe %q failed: %v", probe, rerr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("tmpfs probe %q read back %d bytes, want %d byte-identical: the writable "+
				"surface did not persist the bytes", probe, len(got), len(want))
		}
		t.Logf("the mount container tmpfs %q is writable (probe round-tripped byte-identical)",
			mountTmpfsProbeDir())
	})
}
