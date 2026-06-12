// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
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
	// envROMount is the read-only mountpoint the harness mounts the ro
	// filesystem at.
	envROMount = "OCU_E2E_RO_MOUNT"
	// envReadyFile is the ready-file path the mount process creates once all
	// mounts are up and removes on teardown.
	envReadyFile = "OCU_E2E_READY_FILE"
	// envMountPID is the PID of the running mount process the SIGTERM step
	// signals. The harness writes it once the process is up.
	envMountPID = "OCU_E2E_MOUNT_PID"
	// envThrottleFile, when the broker test-mode is enabled by the peer in
	// 05-02, names a path whose write the broker throttles once
	// (resource_exhausted) before succeeding. The guest never simulates the
	// throttle (SEC-46 is broker-side); it only drives the write and asserts no
	// data loss.
	envThrottleFile = "OCU_E2E_THROTTLE_FILE"
)

// largeFileSize exceeds the ~4MiB RPC ceiling so the write exercises chunked
// upload and the read exercises ranged reassembly.
const largeFileSize = 9 << 20 // 9 MiB

// settleTimeout bounds the polling helpers that wait for the FUSE path to
// reflect a mutation (the VFS is eventually consistent through the cache).
const settleTimeout = 30 * time.Second

// liveEnv carries the resolved harness contract for a single run.
type liveEnv struct {
	rwMount      string
	roMount      string
	readyFile    string
	mountPID     int
	throttleFile string
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
		rwMount:      rw,
		roMount:      ro,
		readyFile:    os.Getenv(envReadyFile),
		mountPID:     pid,
		throttleFile: os.Getenv(envThrottleFile),
	}
}

// TestE2EExercise drives the full 10-step exercise sequence over the FUSE
// mountpoints via ordinary os file operations. It imports no broker client: the
// whole point is to prove the kernel mount path, and the guest holds no second
// transport (SEC-25). Each step is a subtest with its assertion fully written;
// 05-02 supplies the live endpoint and the throttle test-mode without changing
// any assertion.
func TestE2EExercise(t *testing.T) {
	env := requireLive(t)

	// Step 1 — multimount: at least two mounts (rw + ro) must be present and
	// distinct, proving the multimount harness brought up >=2 filesystems.
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
	})

	// Step 2 — write a small file then read it back byte-identical
	// (createFile/fileUpload + readFile).
	smallName := "small.txt"
	smallPath := filepath.Join(env.rwMount, smallName)
	smallData := []byte("end-to-end small payload\n")
	t.Run("02_write_read_small", func(t *testing.T) {
		if err := os.WriteFile(smallPath, smallData, 0o644); err != nil {
			t.Fatalf("write small file: %v", err)
		}
		got := readBackEventually(t, smallPath, len(smallData))
		if !bytes.Equal(got, smallData) {
			t.Fatalf("small file round-trip mismatch: got %d bytes, want %d", len(got), len(smallData))
		}
	})

	// Step 3 — list a directory and assert the union (the written file and a
	// created subdir both appear: listDirectory unions files + subdirs).
	subDir := "listed-subdir"
	t.Run("03_list_union", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(env.rwMount, subDir), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			t.Fatalf("mkdir for list union: %v", err)
		}
		names := listEventually(t, env.rwMount, smallName, subDir)
		assertContains(t, names, smallName)
		assertContains(t, names, subDir)
	})

	// Step 4 — mkdir then rmdir (makeDirectory/removeDirectory): create, assert
	// present, remove, assert absent.
	t.Run("04_mkdir_rmdir", func(t *testing.T) {
		dir := filepath.Join(env.rwMount, "transient-dir")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("created dir not present: %v", err)
		}
		if err := os.Remove(dir); err != nil {
			t.Fatalf("rmdir: %v", err)
		}
		waitGone(t, dir)
	})

	// Step 5 — rename a file and a dir (moveFile/moveDirectory): old path gone,
	// new path present.
	t.Run("05_rename_file_and_dir", func(t *testing.T) {
		// File rename.
		srcFile := filepath.Join(env.rwMount, "rename-src.txt")
		dstFile := filepath.Join(env.rwMount, "rename-dst.txt")
		payload := []byte("rename payload\n")
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

		// Dir rename.
		srcDir := filepath.Join(env.rwMount, "rename-src-dir")
		dstDir := filepath.Join(env.rwMount, "rename-dst-dir")
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
	})

	// Step 6 — large file over the RPC ceiling: write, read back byte-identical,
	// proving chunked upload + ranged reassembly.
	largePath := filepath.Join(env.rwMount, "large.bin")
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

	// Step 9 — throttle: a write completes without data loss when the broker
	// injects resource_exhausted once and then succeeds. The injection is a
	// broker test-mode the peer coordinates in 05-02; the guest never simulates
	// it. This assertion runs only when the harness names the throttle file.
	t.Run("09_throttle_no_data_loss", func(t *testing.T) {
		// 05-02: the broker test-mode (a peer-coordinated env/flag) makes the
		// first write of this path return resource_exhausted, then succeed. The
		// retryable closed-code is handled with backoff by the backend and the
		// VFS cache holds the data, so the write completes without loss.
		if env.throttleFile == "" {
			t.Skipf("%s unset — broker throttle test-mode is coordinated with the "+
				"peer in 05-02; the guest never simulates throttling (SEC-46)", envThrottleFile)
		}
		path := filepath.Join(env.rwMount, env.throttleFile)
		payload := []byte("throttled write must survive the retry without loss\n")
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			t.Fatalf("throttled write failed: %v", err)
		}
		got := readBackEventually(t, path, len(payload))
		if !bytes.Equal(got, payload) {
			t.Fatalf("throttled write lost data: got %d bytes, want %d", len(got), len(payload))
		}
	})

	// Step 10 — graceful teardown: SIGTERM the running mount process; every
	// mountpoint unmounts and the ready-file is gone afterward. This step targets
	// the process the harness runs; the PID and ready-file come from the harness.
	t.Run("10_sigterm_teardown", func(t *testing.T) {
		// 05-02: the harness exports the mount process PID and the ready-file
		// path; on the live host this signals the process and asserts teardown.
		if env.mountPID == 0 {
			t.Skipf("%s unset — the harness exports the mount process PID in 05-02; "+
				"the teardown assertion targets that process", envMountPID)
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
			_, rwErr := os.Stat(filepath.Join(env.rwMount, smallName))
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
