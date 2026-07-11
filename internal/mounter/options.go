// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"fmt"
	"time"

	"github.com/rclone/rclone/cmd/mountlib"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/vfs/vfscommon"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
)

// buildVFSOptions maps one config mount and its read-only posture to the VFS
// options that drive its cache and permissions.
//
// The result starts from a copy of the package-level registered defaults
// (vfscommon.Opt) and overrides ONLY the five mapped knobs plus Umask. Building
// from a zero vfscommon.Options{} literal would zero CachePollInterval, which
// disables the vfscache cleaner — the only thing that enforces CacheMaxSize —
// making the configured vfs_cache_max_size decorative. Keeping the registered
// defaults preserves that cleaner and every other non-mapped sane default.
//
// Umask is set to 0 so a later Options.Init masks no bits off the configured
// dir_perms / file_perms; UID and GID stay at the registered default for the
// production seam to fill from process defaults.
func buildVFSOptions(m mountcfg.Mount, readOnly bool) (vfscommon.Options, error) {
	opt := vfscommon.Opt // copy of the registered defaults

	var mode vfscommon.CacheMode
	if err := mode.Set(m.VfsCacheMode); err != nil {
		return vfscommon.Options{}, fmt.Errorf("vfs_cache_mode %q: %w", m.VfsCacheMode, err)
	}
	opt.CacheMode = mode

	// Normalize a unitless value to BYTES before parsing. fs.SizeSuffix.Set
	// treats a trailing digit as the KiB multiplier, so a bare integer like
	// "1048576" would parse as 1048576 KiB (1 GiB) — a 1024x-too-large per-mount
	// cap, which matters under per-session ceilings (SEC-46). The contract
	// ByteSize pattern admits a unitless integer, so append "B" when the value is
	// all digits to force a bytes interpretation; values that already carry a
	// B/K/M/G/T suffix pass through unchanged.
	rawSize := m.VfsCacheMaxSize
	if isAllDigits(rawSize) {
		rawSize += "B"
	}
	var size fs.SizeSuffix
	if err := size.Set(rawSize); err != nil {
		return vfscommon.Options{}, fmt.Errorf("vfs_cache_max_size %q: %w", m.VfsCacheMaxSize, err)
	}
	opt.CacheMaxSize = size

	seconds := 0
	if m.CacheDurationS != nil {
		seconds = *m.CacheDurationS
	}
	opt.DirCacheTime = fs.Duration(time.Duration(seconds) * time.Second)

	var dirPerms vfscommon.FileMode
	if err := dirPerms.Set(m.DirPerms); err != nil {
		return vfscommon.Options{}, fmt.Errorf("dir_perms %q: %w", m.DirPerms, err)
	}
	opt.DirPerms = dirPerms

	var filePerms vfscommon.FileMode
	if err := filePerms.Set(m.FilePerms); err != nil {
		return vfscommon.Options{}, fmt.Errorf("file_perms %q: %w", m.FilePerms, err)
	}
	opt.FilePerms = filePerms

	// Umask 0 so a later Init() preserves the configured perms verbatim.
	opt.Umask = 0

	opt.ReadOnly = readOnly

	return opt, nil
}

// buildMountOptions maps one config mount to the FUSE mount options. The result
// starts from a copy of the registered defaults (mountlib.Opt) so AttrTimeout,
// MaxReadAhead, AsyncRead and the rest keep their sane defaults; AllowOther and
// AllowNonEmpty are overridden.
//
// AllowOther is set true so a non-root process serving the VFS can let other
// uids read the mount.
//
// AllowNonEmpty is set true because the co-located guest image bakes the mount
// destination as an empty scaffold (e.g. /mnt/user-data with empty outputs/ and
// uploads/ subdirs). rclone's CheckAllowNonEmpty gate otherwise refuses to mount
// over any non-empty directory to avoid shadowing data — but the scaffold holds
// no files, so the FUSE mount shadows nothing. Without this the guest's managed
// mount boot-child exits before its ready-file appears and the whole session
// fails to serve. The shadow protection the rclone gate provided is NOT lost:
// the runtime guard lives in mountAndWaitReady (ensureMountpointShadowsNoContent),
// which tolerates exactly the dirs-only scaffold and refuses real content.
// No config field controls either flag today; both are pinned here and in the
// test.
func buildMountOptions(_ mountcfg.Mount) (mountlib.Options, error) {
	opt := mountlib.Opt // copy of the registered defaults
	opt.AllowOther = true
	opt.AllowNonEmpty = true
	return opt, nil
}

// buildOcufsConfigmap builds the configmap the ocufs backend reads via
// configstruct.Set: service_url, auth_token, ca_cert_pem, filesystem_id,
// read_only. The filesystem_id is the mount's sole scope handle; read_only
// matches the posture. The transport triplet (service_url + ca_cert_pem from the
// top-level config, auth_token from this mount) is what the backend threads into
// brokerrpc.New.
//
// A memory-store mount (MemoryStoreID set, FilesystemID absent) is a hard error
// here — there is no memory scope axis on the backend today, so such a mount is
// never silently skipped or mounted unscoped.
func buildOcufsConfigmap(m mountcfg.Mount, readOnly bool, serviceURL, caCertPEM string) (configmap.Simple, error) {
	if m.MemoryStoreID != nil {
		return nil, fmt.Errorf("mount %q: memory-store mounts are not yet supported (no memory scope axis)", m.Destination)
	}
	if m.FilesystemID == nil || *m.FilesystemID == "" {
		return nil, fmt.Errorf("mount %q: filesystem_id is required", m.Destination)
	}

	cm := configmap.Simple{}
	cm.Set("service_url", serviceURL)
	cm.Set("auth_token", m.AuthToken)
	cm.Set("ca_cert_pem", caCertPEM)
	cm.Set("filesystem_id", *m.FilesystemID)
	if readOnly {
		cm.Set("read_only", "true")
	} else {
		cm.Set("read_only", "false")
	}
	return cm, nil
}

// isAllDigits reports whether s is non-empty and made up entirely of ASCII
// digits, i.e. a unitless ByteSize value that fs.SizeSuffix would otherwise
// misread as KiB. An empty string is not all-digits (it must not gain a "B"
// suffix and parse as a bare unit).
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
