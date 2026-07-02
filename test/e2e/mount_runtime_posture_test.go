// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This file pins the RUNTIME (kernel-enforced) hardening posture of the guest
// mount CONTAINER, as observed live. The compose content pins in test/posture
// assert what the YAML says; this asserts what the kernel actually did with it
// at run time, so a posture that is silently NOT applied (a runtime that ignores
// read_only, a capability set wider than declared) goes red here even though the
// YAML still reads correctly.
//
// HOW EACH ARM REACHES THE KERNEL OUTCOME. The mount image is distroless (no
// shell, no tooling), so `docker compose exec mount sh -c ...` cannot run inside
// it. Two mechanisms cover the three arms:
//
//   - CapEff (the effective-capability mask). The test-runner runs in the HOST
//     PID namespace (pid: "host") and resolves the mount process's host-side PID
//     into OCU_E2E_MOUNT_PID. From the host PID namespace the runner reads
//     /proc/<pid>/status, which carries CapEff — the kernel's own accounting of
//     what cap_drop/cap_add produced. A cross-namespace procfs READ is permitted,
//     so this arm stays a direct procfs observation.
//
//   - read_only-rootfs (EROFS) and tmpfs-writability. A cross-namespace procfs
//     WRITE through /proc/<pid>/root is denied by the kernel with EACCES (a
//     different container's uid/namespace) BEFORE the target's mount-table
//     EROFS/tmpfs semantics ever apply, so the write cannot witness the posture.
//     Instead a one-shot sibling service (mount-posture-probe) runs from the SAME
//     image with the IDENTICAL hardening posture (read_only rootfs + tmpfs
//     /root/.cache, cap_drop:[ALL]+cap_add:[SYS_ADMIN], the same AppArmor/seccomp/
//     no-new-privileges). Running inside its OWN namespace and uid, the kernel
//     applies the same read_only and tmpfs semantics to its own syscalls: a
//     create under the image root surfaces EROFS and a write under /root/.cache
//     round-trips. The probe writes a verdict line to a shared volume; this test
//     READS the verdict instead of doing the write itself.
//
// arch binding. CapEff is KERNEL enforced and therefore cannot be witnessed on
// the Lima arm64 dev host the authoring happened on — there is no running Linux
// mount container there. It is AMD64-BINDING: the authoritative red-able proof is
// the amd64 CI live-e2e job (ci.yml "live e2e (data path)"). The read_only-rootfs
// EROFS arm IS witnessable on the arm64 dev host through the probe, because the
// kernel enforces read_only rootfs on arm64 too (it is AppArmor INET mediation,
// not read_only, that the arm64 dev host does not enforce). The tmpfs arm is the
// positive companion: it proves the single declared writable surface really is
// writable, so the EROFS arm cannot pass merely because the whole filesystem is
// broken.

// The hardened-posture constants (capSysAdmin, seccompModeFilter,
// noNewPrivsEnabled) and the /proc/<pid>/status parsers and predicates live in
// the untagged procstatus.go, so their two-sided non-vacuity proof runs on every
// PR. The live arms below bind those same predicates to the real running mount.

const (
	// envProbeVerdict names the file the one-shot mount-posture-probe wrote its
	// verdict line to, on the shared /run/ocu volume. Defaults to
	// /run/ocu/posture-verdict.
	envProbeVerdict     = "OCU_E2E_PROBE_VERDICT"
	defaultProbeVerdict = "/run/ocu/posture-verdict"
)

// probeVerdictPath returns the path the runner reads the posture probe's verdict
// from, defaulting to the shared-volume location the probe writes by default.
func probeVerdictPath() string {
	if v := os.Getenv(envProbeVerdict); v != "" {
		return v
	}
	return defaultProbeVerdict
}

// readProbeVerdict reads the single-line verdict the posture probe wrote and
// returns its space-separated KEY=value tokens as a map. Under the live gate the
// verdict file MUST exist (the one-shot probe service ran before the runner), so
// an absent file is a hard failure, not a skip.
func readProbeVerdict(t *testing.T) map[string]string {
	t.Helper()
	path := probeVerdictPath()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open posture-probe verdict %q: %v — under the live gate the one-shot "+
			"mount-posture-probe service must have run and written its verdict before the "+
			"runner reads it (compose depends_on service_completed_successfully)", path, err)
	}
	defer func() { _ = f.Close() }()

	tokens := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		for _, field := range strings.Fields(line) {
			k, v, ok := strings.Cut(field, "=")
			if !ok {
				t.Fatalf("malformed posture-probe verdict token %q in %q (want KEY=value)",
					field, path)
			}
			tokens[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan posture-probe verdict %q: %v", path, err)
	}
	if len(tokens) == 0 {
		t.Fatalf("posture-probe verdict %q is empty: the probe must write a verdict line", path)
	}
	return tokens
}

// procStatus is the kernel's own record of the mount process's runtime posture,
// read from /proc/<pid>/status: the effective and bounding capability masks, the
// no-new-privileges flag, and the seccomp mode. Each reflects what the runtime
// actually applied from the compose posture — not what the YAML declared — so an
// unenforced lever surfaces here as a wrong value.
type procStatus struct {
	capEff     uint64
	capBnd     uint64
	noNewPrivs int
	seccomp    int
}

// readProcStatus reads /proc/<pid>/status once and extracts the four posture
// fields via the shared (untagged, unit-tested) parsers. A missing field is a
// hard failure: the kernel always emits all four for a live process, so an
// absent field means the wrong process or an unreadable status, not a pass.
func readProcStatus(t *testing.T, pid int) procStatus {
	t.Helper()
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	raw, err := os.ReadFile(statusPath) //nolint:gosec // G304: statusPath is /proc/<pid>/status for the resolved mount PID, not user input.
	if err != nil {
		t.Fatalf("read %s (the mount process must be visible in the host PID "+
			"namespace the runner joins): %v", statusPath, err)
	}

	capEff, ok := parseStatusHex(bytes.NewReader(raw), "CapEff")
	if !ok {
		t.Fatalf("no parseable CapEff line in %s", statusPath)
	}
	capBnd, ok := parseStatusHex(bytes.NewReader(raw), "CapBnd")
	if !ok {
		t.Fatalf("no parseable CapBnd line in %s", statusPath)
	}
	nnp, ok := parseStatusInt(bytes.NewReader(raw), "NoNewPrivs")
	if !ok {
		t.Fatalf("no parseable NoNewPrivs line in %s", statusPath)
	}
	seccomp, ok := parseStatusInt(bytes.NewReader(raw), "Seccomp")
	if !ok {
		t.Fatalf("no parseable Seccomp line in %s", statusPath)
	}
	return procStatus{capEff: capEff, capBnd: capBnd, noNewPrivs: nnp, seccomp: seccomp}
}

// TestMountRuntimePosture asserts the live mount container's kernel-enforced
// hardening posture: CapEff through procfs from the host-PID-namespace runner,
// and the read_only-rootfs/tmpfs arms through the one-shot posture probe's
// verdict. It runs only under the live gate; on a host build (gate unset) it
// skips clean.
//
// The four capability/seccomp arms nest under a proc_status_posture parent that
// performs the single /proc/<pid>/status read, so a read failure isolates to that
// group and the independent probe-verdict arms below still run.
//
// LIMA-HONEST vs AMD64-BINDING (also marked per subtest):
//   - proc_status_posture      — AMD64-BINDING (kernel capability/NNP/seccomp
//     accounting), holding capeff_only_sys_admin, capbnd_only_sys_admin,
//     no_new_privileges, and seccomp_filter_loaded.
//   - image_rootfs_read_only  — witnessed via the probe; the probe's EROFS arm
//     is enforced on arm64 too, so the verdict is Lima-honest, but it runs inside
//     the live harness.
//   - tmpfs_cache_writable    — positive companion read from the same verdict.
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
				"to read its CapEff)",
				envMountPID, envAllowPartial)
		}
		t.Fatalf("%s is required under the live gate (%s): the runtime-posture assertion "+
			"reads the mount process's CapEff through /proc/<pid>/; set %s=1 only to opt "+
			"into a partial run on purpose",
			envMountPID, envGate, envAllowPartial)
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		t.Fatalf("invalid %s=%q: %v", envMountPID, pidStr, err)
	}

	// The four capability/seccomp arms share one read of /proc/<pid>/status, so
	// they are grouped under a single parent subtest that performs that read. The
	// read is scoped HERE, inside the parent subtest — not on the outer T — so a
	// parse failure (t.Fatalf -> runtime.Goexit) tears down only this group and
	// leaves the independent rootfs/tmpfs arms below (which read the probe verdict,
	// not procfs) free to run and report. A shared read on the outer T would let a
	// single procfs hiccup swallow every arm's diagnostic.
	t.Run("proc_status_posture", func(t *testing.T) {
		st := readProcStatus(t, pid)

		// (c) CapEff must be EXACTLY CAP_SYS_ADMIN — AMD64-BINDING.
		//
		// cap_drop:[ALL] + cap_add:[SYS_ADMIN] must collapse the effective set to the
		// single bit the FUSE mount(2)/umount2(2) path needs. Any other bit set means
		// a capability survived the drop (a weakened posture), so the mask must equal
		// 0x200000 and nothing more. Dry logic: bits other than CAP_SYS_ADMIN are
		// isolated with (eff &^ capSysAdmin); a non-zero remainder is a leak, and a
		// missing CAP_SYS_ADMIN bit is an over-tightening that would break mount(2).
		t.Run("capeff_only_sys_admin", func(t *testing.T) {
			eff := st.capEff
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

		// (d) The BOUNDING capability set must ALSO be exactly CAP_SYS_ADMIN —
		// AMD64-BINDING. CapEff (arm c) is what the process holds now; CapBnd is the
		// ceiling on what any later execve could ever regain. cap_drop:[ALL]+cap_add:
		// [SYS_ADMIN] reduces both, so pinning the bounding set catches a drop
		// regression that leaves CapEff narrow but re-widens the ceiling. The predicate
		// is unit-proven two-sided in procstatus_test.go.
		t.Run("capbnd_only_sys_admin", func(t *testing.T) {
			if !capIsExactlySysAdmin(st.capBnd) {
				t.Fatalf("mount process CapBnd=0x%016x, want exactly 0x%016x (only CAP_SYS_ADMIN): "+
					"the bounding set is the ceiling on any capability a later execve could regain; "+
					"a wider bounding set is a weakened posture even if CapEff stayed narrow",
					st.capBnd, capSysAdmin)
			}
			t.Logf("AMD64-BINDING: mount process CapBnd=0x%016x is exactly CAP_SYS_ADMIN", st.capBnd)
		})

		// (e) no-new-privileges MUST be enforced at run time — AMD64-BINDING. The
		// compose posture sets no-new-privileges:true; the kernel records it as
		// NoNewPrivs:1 in the process status. Asserting the live value closes the
		// regression gap where a future edit removes the lever from the compose posture
		// and no test notices — this arm goes RED the moment NoNewPrivs reads 0. The
		// predicate is unit-proven two-sided in procstatus_test.go.
		t.Run("no_new_privileges", func(t *testing.T) {
			if !noNewPrivsSet(st.noNewPrivs) {
				t.Fatalf("mount process NoNewPrivs=%d, want %d: no-new-privileges:true must be "+
					"enforced so execve can gain no new privileges; a 0 here means the lever was "+
					"dropped from the compose posture and is not applied to the live mount",
					st.noNewPrivs, noNewPrivsEnabled)
			}
			t.Logf("AMD64-BINDING: mount process NoNewPrivs=%d (no-new-privileges enforced)", st.noNewPrivs)
		})

		// (f) A seccomp BPF filter MUST be loaded at run time — AMD64-BINDING. The
		// narrow mount-fuse.json profile puts the process in SECCOMP_MODE_FILTER, which
		// the kernel records as Seccomp:2. A 0 (disabled) means the profile did not
		// attach, so the whole narrow-seccomp lever is inert on the live mount. This
		// asserts the mode is loaded; the profile's default-deny stance and the narrow
		// allow set are content-pinned in test/posture/seccomp_test.go. The predicate
		// is unit-proven two-sided in procstatus_test.go.
		t.Run("seccomp_filter_loaded", func(t *testing.T) {
			if !seccompFilterLoaded(st.seccomp) {
				t.Fatalf("mount process Seccomp=%d, want %d (SECCOMP_MODE_FILTER): the narrow "+
					"mount-fuse.json profile must be loaded; a 0 means seccomp is disabled on the "+
					"live mount and the content-pinned allow set is enforcing nothing at run time",
					st.seccomp, seccompModeFilter)
			}
			t.Logf("AMD64-BINDING: mount process Seccomp=%d (SECCOMP_MODE_FILTER: a BPF filter is loaded)", st.seccomp)
		})
	})

	// (a) The image rootfs must be READ-ONLY — witnessed via the posture probe.
	//
	// The one-shot mount-posture-probe ran from the SAME image with the IDENTICAL
	// hardening posture and attempted a create under its own image root. With
	// read_only:true the create surfaces EROFS, and the probe records
	// ROOTFS_EROFS=ok only on that exact errno (a successful create, or any errno
	// other than EROFS, records a failing detail instead). This test asserts the
	// recorded verdict. Reading the probe's verdict — rather than the runner
	// attempting a cross-namespace procfs-root write the kernel denies with EACCES
	// — is what makes the arm witnessable on amd64 CI and on the arm64 dev host.
	t.Run("image_rootfs_read_only", func(t *testing.T) {
		verdict := readProbeVerdict(t)
		got := verdict["ROOTFS_EROFS"]
		if got != "ok" {
			t.Fatalf("posture-probe ROOTFS_EROFS=%q, want \"ok\": the probe's create under its "+
				"own image root did NOT surface EROFS, so read_only:true is not enforced on the "+
				"mount image rootfs (full verdict: %v)", got, verdict)
		}
		t.Logf("mount image rootfs is read-only (probe ROOTFS_EROFS=ok: create surfaced EROFS)")
	})

	// (b) The VFS-cache tmpfs must be WRITABLE — positive companion read from the
	// same probe verdict.
	//
	// /root/.cache is the single declared writable surface (tmpfs). The probe
	// wrote a nonce'd file there and read it back byte-identical, recording
	// TMPFS_WRITABLE=ok only on a successful round-trip. This proves the surface
	// the rclone VFS cache needs is genuinely writable, so the read-only-rootfs arm
	// above is not passing merely because the whole filesystem is unusable.
	t.Run("tmpfs_cache_writable", func(t *testing.T) {
		verdict := readProbeVerdict(t)
		got := verdict["TMPFS_WRITABLE"]
		if got != "ok" {
			t.Fatalf("posture-probe TMPFS_WRITABLE=%q, want \"ok\": the declared writable "+
				"VFS-cache tmpfs (/root/.cache) did not accept a write+read-back round-trip "+
				"(full verdict: %v)", got, verdict)
		}
		t.Logf("mount tmpfs /root/.cache is writable (probe TMPFS_WRITABLE=ok: round-trip " +
			"byte-identical)")
	})
}
