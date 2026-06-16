// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/vfs/vfscommon"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// ptrInt returns a pointer to the given int so test mounts can carry the
// pointer-typed cache_duration_s field the loader produces.
func ptrInt(v int) *int { return &v }

// ptrStr returns a pointer to the given string for the pointer-typed scope
// fields (filesystem_id / memory_store_id).
func ptrStr(v string) *string { return &v }

// writableMount returns a representative writable mount entry with the knobs
// the mapping consumes.
func writableMount() mountcfg.Mount {
	return mountcfg.Mount{
		Destination:     "/mnt/work",
		FilesystemID:    ptrStr("fs-123"),
		VfsCacheMode:    "writes",
		CacheDurationS:  ptrInt(300),
		VfsCacheMaxSize: "256M",
		DirPerms:        "0755",
		FilePerms:       "0644",
	}
}

func TestBuildVFSOptionsWritable(t *testing.T) {
	m := writableMount()
	opt, err := buildVFSOptions(m, false)
	if err != nil {
		t.Fatalf("buildVFSOptions: %v", err)
	}
	if opt.CacheMode != vfscommon.CacheModeWrites {
		t.Errorf("CacheMode = %v; want CacheModeWrites", opt.CacheMode)
	}
	if want := fs.SizeSuffix(256 * 1024 * 1024); opt.CacheMaxSize != want {
		t.Errorf("CacheMaxSize = %v; want %v", opt.CacheMaxSize, want)
	}
	if want := fs.Duration(300 * time.Second); opt.DirCacheTime != want {
		t.Errorf("DirCacheTime = %v; want %v", opt.DirCacheTime, want)
	}
	if opt.ReadOnly {
		t.Errorf("ReadOnly = true; want false for a writable mount")
	}
}

func TestBuildVFSOptionsReadOnly(t *testing.T) {
	m := writableMount()
	opt, err := buildVFSOptions(m, true)
	if err != nil {
		t.Fatalf("buildVFSOptions: %v", err)
	}
	if !opt.ReadOnly {
		t.Errorf("ReadOnly = false; want true for a readonly mount")
	}
}

// TestDefaultsSurvive proves the option structs are built from a copy of the
// registered defaults: CachePollInterval (the vfscache cleaner interval that
// enforces CacheMaxSize) keeps its non-zero default. Building from a zero
// Options{} literal would disable the cleaner and make the cache cap inert.
func TestDefaultsSurvive(t *testing.T) {
	opt, err := buildVFSOptions(writableMount(), false)
	if err != nil {
		t.Fatalf("buildVFSOptions: %v", err)
	}
	if opt.CachePollInterval == 0 {
		t.Fatalf("CachePollInterval = 0; want non-zero (cache cleaner disabled => cache cap inert)")
	}
	if opt.CachePollInterval != vfscommon.Opt.CachePollInterval {
		t.Errorf("CachePollInterval = %v; want vfscommon.Opt.CachePollInterval %v",
			opt.CachePollInterval, vfscommon.Opt.CachePollInterval)
	}

	mopt, err := buildMountOptions(writableMount())
	if err != nil {
		t.Fatalf("buildMountOptions: %v", err)
	}
	if mopt.AttrTimeout == 0 {
		t.Errorf("AttrTimeout = 0; want the registered mountlib.Opt default to survive")
	}
}

func TestBuildVFSOptionsCacheModes(t *testing.T) {
	cases := map[string]vfscommon.CacheMode{
		"off":     vfscommon.CacheModeOff,
		"minimal": vfscommon.CacheModeMinimal,
		"writes":  vfscommon.CacheModeWrites,
		"full":    vfscommon.CacheModeFull,
	}
	for in, want := range cases {
		m := writableMount()
		m.VfsCacheMode = in
		opt, err := buildVFSOptions(m, false)
		if err != nil {
			t.Fatalf("buildVFSOptions(%q): %v", in, err)
		}
		if opt.CacheMode != want {
			t.Errorf("CacheMode for %q = %v; want %v", in, opt.CacheMode, want)
		}
	}

	m := writableMount()
	m.VfsCacheMode = "bogus"
	if _, err := buildVFSOptions(m, false); err == nil {
		t.Errorf("buildVFSOptions with bogus cache mode = nil error; want a typed error")
	}
}

func TestBuildVFSOptionsSizeForms(t *testing.T) {
	// Assert the CONCRETE resulting cap, not merely no-error: a unitless integer
	// must be read as BYTES, not KiB (WR-03). fs.SizeSuffix.Set would otherwise
	// read "1048576" as 1048576 KiB (1 GiB), a 1024x-too-large per-mount cap.
	cases := map[string]fs.SizeSuffix{
		"1048576": 1048576,       // unitless -> bytes, NOT 1048576 KiB
		"1M":      1 << 20,       // 1 MiB
		"1G":      1 << 30,       // 1 GiB
		"256M":    256 * 1 << 20, // 256 MiB
	}
	for in, want := range cases {
		m := writableMount()
		m.VfsCacheMaxSize = in
		opt, err := buildVFSOptions(m, false)
		if err != nil {
			t.Errorf("buildVFSOptions size %q: %v", in, err)
			continue
		}
		if opt.CacheMaxSize != want {
			t.Errorf("CacheMaxSize for %q = %d; want %d", in, opt.CacheMaxSize, want)
		}
	}

	m := writableMount()
	m.VfsCacheMaxSize = "not-a-size"
	if _, err := buildVFSOptions(m, false); err == nil {
		t.Errorf("buildVFSOptions with malformed size = nil error; want error")
	}
}

func TestBuildVFSOptionsCacheDurationZero(t *testing.T) {
	m := writableMount()
	m.CacheDurationS = ptrInt(0)
	opt, err := buildVFSOptions(m, false)
	if err != nil {
		t.Fatalf("buildVFSOptions: %v", err)
	}
	if opt.DirCacheTime != fs.Duration(0) {
		t.Errorf("DirCacheTime = %v; want 0 for cache_duration_s 0", opt.DirCacheTime)
	}
}

// TestUmaskSurvival proves the configured perms survive vfscommon.Init()'s
// umask masking: the mapping sets Umask=0 so Init masks nothing away. We assert
// the low 0777 bits equal the configured octal value (ignoring the os.ModeDir
// bit Init ORs into DirPerms).
func TestUmaskSurvival(t *testing.T) {
	opt, err := buildVFSOptions(writableMount(), false)
	if err != nil {
		t.Fatalf("buildVFSOptions: %v", err)
	}
	ctx := context.Background()
	opt.Init(ctx)

	if got := os.FileMode(opt.DirPerms) & os.ModePerm; got != 0o755 {
		t.Errorf("DirPerms after Init = %o; want 0755 (umask masked bits away)", got)
	}
	if got := os.FileMode(opt.FilePerms) & os.ModePerm; got != 0o644 {
		t.Errorf("FilePerms after Init = %o; want 0644 (umask masked bits away)", got)
	}
}

func TestBuildMountOptionsAllowOther(t *testing.T) {
	mopt, err := buildMountOptions(writableMount())
	if err != nil {
		t.Fatalf("buildMountOptions: %v", err)
	}
	if !mopt.AllowOther {
		t.Errorf("AllowOther = false; want true")
	}
}

func TestBuildOcufsConfigmap(t *testing.T) {
	m := writableMount()
	cm, err := buildOcufsConfigmap(m, false, "/run/x.sock")
	if err != nil {
		t.Fatalf("buildOcufsConfigmap: %v", err)
	}
	if v, _ := cm.Get("socket_path"); v != "/run/x.sock" {
		t.Errorf("socket_path = %q; want /run/x.sock", v)
	}
	if v, _ := cm.Get("filesystem_id"); v != "fs-123" {
		t.Errorf("filesystem_id = %q; want fs-123", v)
	}
	if v, _ := cm.Get("read_only"); v != "false" {
		t.Errorf("read_only = %q; want false", v)
	}

	ro, err := buildOcufsConfigmap(m, true, "/run/x.sock")
	if err != nil {
		t.Fatalf("buildOcufsConfigmap readonly: %v", err)
	}
	if v, _ := ro.Get("read_only"); v != "true" {
		t.Errorf("read_only = %q; want true for a readonly entry", v)
	}
}

func TestBuildOcufsConfigmapMemoryStoreIsHardError(t *testing.T) {
	m := mountcfg.Mount{
		Destination:   "/mnt/mem",
		MemoryStoreID: ptrStr("mem-9"),
	}
	if _, err := buildOcufsConfigmap(m, true, "/run/x.sock"); err == nil {
		t.Fatalf("buildOcufsConfigmap with memory_store_id = nil error; want a hard error")
	}
}
