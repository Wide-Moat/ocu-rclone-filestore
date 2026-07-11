// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux || (darwin && amd64)

package mounter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// guardSpec builds a mountSpec over dest for the shadow-guard tests.
func guardSpec(t *testing.T, dest string) mountSpec {
	t.Helper()
	fsid := "session_guard_fs"
	return mountSpec{
		mount: mountcfg.Mount{
			Destination:     dest,
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
}

// TestMountRefusesToShadowRealContent pins F-31/F-32: a FUSE mount over a
// destination holding a regular file silently shadows it (perceived data
// loss while mounted, split-brain after unmount). With AllowNonEmpty pinned
// true — required, because rclone's own entry-counting gate would refuse the
// baked dirs-only scaffold — the seam itself must supply the refusal: the
// mount must fail loudly, name the offending path, and never invoke the
// MountFn.
func TestMountRefusesToShadowRealContent(t *testing.T) {
	dest := t.TempDir()
	offending := filepath.Join(dest, "outputs", "report.txt")
	if err := os.MkdirAll(filepath.Dir(offending), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(offending, []byte("user bytes"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var invoked bool
	r := &realPointMounter{
		mountFn:      fakeMountFn(&invoked),
		readyTimeout: 10 * time.Millisecond,
		servesProbe:  func(string) bool { return false },
	}

	_, err := r.mountAndWaitReady(context.Background(), guardSpec(t, dest))
	if err == nil {
		t.Fatal("mountAndWaitReady = nil error over a destination holding a regular file; want a loud shadow-refusal")
	}
	if !strings.Contains(err.Error(), "report.txt") {
		t.Errorf("error %q does not name the offending path", err.Error())
	}
	if invoked {
		t.Error("MountFn was invoked over real content: the FUSE mount would have shadowed it before the guard fired")
	}
}

// TestMountToleratesEmptyScaffold is the two-sided companion: the baked
// scaffold shape (a dirs-only tree, e.g. empty outputs/ and uploads/) must
// still mount — that tolerance is the reason AllowNonEmpty is pinned true,
// and regressing it reintroduces the boot-child failure the pin fixed.
func TestMountToleratesEmptyScaffold(t *testing.T) {
	dest := t.TempDir()
	for _, d := range []string{"outputs", "uploads"} {
		if err := os.Mkdir(filepath.Join(dest, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	var invoked bool
	r := &realPointMounter{
		mountFn:      fakeMountFn(&invoked),
		readyTimeout: 10 * time.Millisecond,
		servesProbe:  func(string) bool { return false },
	}

	// On the polling leg readiness times out over the fake mount — that error
	// is fine; the guard property under test is that the MountFn ran.
	_, _ = r.mountAndWaitReady(context.Background(), guardSpec(t, dest))
	if !invoked {
		t.Fatal("MountFn was never invoked over the dirs-only scaffold: the shadow guard regressed the empty-scaffold tolerance the AllowNonEmpty pin exists for")
	}
}
