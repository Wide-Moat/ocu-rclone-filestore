// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/cmd/mountlib"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// TestMountAndWaitReadyFailurePathDoesNotHang pins F-62: when readiness times
// out after a successful Mount(), the best-effort teardown of the half-started
// mount must go through the same bounded detach discipline doUnmount applies —
// a bare mp.Unmount() never returns on the tier whose in-process detach
// blocks, wedging run() forever with the ready-file lifecycle stuck behind it.
//
// The fake MountFn's unmount blocks forever; the servesProbe is pinned false
// and the readyTimeout tiny, so mountAndWaitReady must return the readiness
// error within the detach grace plus margin instead of hanging on the
// blocking unmount.
func TestMountAndWaitReadyFailurePathDoesNotHang(t *testing.T) {
	if !mountlib.CanCheckMountReady {
		t.Skip("readiness polling unavailable on this leg; the failure path under test is unreachable")
	}

	// A never-closed stop channel makes the fake's unmount block forever —
	// the userspace-kernel detach shape.
	r := &realPointMounter{
		mountFn:      blockingUnmountMountFn(make(chan struct{})),
		readyTimeout: 10 * time.Millisecond,
		servesProbe:  func(string) bool { return false },
	}
	fsid := "session_failpath_fs"
	spec := mountSpec{
		mount: mountcfg.Mount{
			Destination:     t.TempDir(),
			AuthToken:       "tok",
			FilesystemID:    &fsid,
			VfsCacheMode:    "writes",
			VfsCacheMaxSize: "256M",
			DirPerms:        "0755",
			FilePerms:       "0644",
		},
		readOnly:   false,
		serviceURL: "https://broker.internal",
		caCertPEM:  validCAPEM(t),
	}

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		_, err := r.mountAndWaitReady(context.Background(), spec)
		done <- result{err: err}
	}()

	// Watchdog: the bounded path is readiness timeout (~10ms) + detach grace
	// (unmountDetachGrace) + margin. A bare blocking Unmount() never reaches
	// the channel and the watchdog fires instead.
	select {
	case res := <-done:
		if res.err == nil {
			t.Fatal("mountAndWaitReady returned nil; want the readiness error from the failure path")
		}
		if !strings.Contains(res.err.Error(), "wait for mount ready") {
			t.Fatalf("mountAndWaitReady error = %q; want the readiness-stage error", res.err)
		}
	case <-time.After(unmountDetachGrace + 5*time.Second):
		t.Fatal("mountAndWaitReady did not return: the readiness-failure teardown hangs on the blocking in-process detach (bare mp.Unmount() without the bounded discipline)")
	}
}
