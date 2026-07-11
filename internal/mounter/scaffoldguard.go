// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mounter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// scaffoldWalkEntryCeiling bounds the pre-mount walk over the mount
// destination. The tolerated state is the baked scaffold — a handful of empty
// directories — so a tree with more entries than this is real content by
// volume alone, and the walk fails closed without reading further.
const scaffoldWalkEntryCeiling = 4096

// ensureMountpointShadowsNoContent refuses to mount over real content.
//
// AllowNonEmpty is pinned true on every mount because the guest image bakes
// the destination as a dirs-only scaffold (empty outputs/ and uploads/), which
// rclone's own entry-counting gate would refuse. Pinning the flag removed
// rclone's shadow protection entirely: a FUSE mount over a destination holding
// real files silently hides them while mounted (perceived data loss) and
// resurfaces stale copies after unmount while the broker-side tree diverges
// (split-brain). This guard restores the protection with the tolerated state
// widened to exactly the scaffold shape: every entry under dest must be a
// directory. The first regular file, symlink, or other non-directory node
// fails the mount loudly with the offending path and the remedy; so does a
// tree wider than the entry ceiling (real content by volume).
//
// A missing destination is the opposite condition (nothing can be shadowed —
// the mount would fail later anyway) and gets its own message; any other read
// error fails closed, because an unreadable tree cannot be proven safe to
// shadow.
func ensureMountpointShadowsNoContent(dest string) error {
	seen := 0
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return classifyDestReadError(dest, dir, err)
		}
		for _, e := range entries {
			seen++
			if seen > scaffoldWalkEntryCeiling {
				return fmt.Errorf("refusing to shadow existing content at %q: more than %d entries under the mount destination; empty the destination and restart the mount", dir, scaffoldWalkEntryCeiling)
			}
			p := filepath.Join(dir, e.Name())
			if !e.IsDir() {
				return fmt.Errorf("refusing to shadow existing content at %q: the mount destination must hold only empty directories (the baked scaffold); remove the entry and restart the mount", p)
			}
			if err := walk(p); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(dest)
}

// classifyDestReadError words a failed ReadDir during the pre-mount walk.
// Three states are distinguishable and each gets its own remedy:
//
//   - a missing destination is the OPPOSITE of the shadow condition (nothing
//     can be shadowed) and is never worded as a refusal;
//   - ENOTCONN means a STALE disconnected FUSE mount is still attached at the
//     path — the previous mount instance died without a clean detach — and the
//     remedy is a lazy unmount, not entry removal;
//   - anything else fails closed with the walk error, because an unreadable
//     tree cannot be proven safe to shadow.
func classifyDestReadError(dest, dir string, err error) error {
	if dir == dest && os.IsNotExist(err) {
		return fmt.Errorf("mount destination %q does not exist", dest)
	}
	if errors.Is(err, syscall.ENOTCONN) {
		return fmt.Errorf("a stale disconnected mount is still attached at %q (a previous mount instance exited without a clean detach); lazy-unmount it (umount -l) and restart the mount: %w", dir, err)
	}
	return fmt.Errorf("inspecting mount destination %q: %w", dest, err)
}
