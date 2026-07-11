// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package posture declares the deploy-posture filesystem facts the mount
// image is built around, so the binaries that depend on them state each fact
// exactly once.
//
// The hardened container posture is: a read-only root filesystem whose single
// writable surface is a tmpfs mounted at CacheTmpfs, with HOME set to Home so
// the global cache-dir default (os.UserCacheDir -> $HOME/.cache) resolves
// onto that tmpfs and the VFS disk cache — the SEC-46
// hold-data-across-throttle mechanism — stays enabled. The same two values
// are hand-synced into the image and deploy layers (Dockerfile ENV HOME, the
// compose tmpfs declarations, the AppArmor write grants); the binding test in
// this package pins those copies to these constants so a posture change that
// misses a layer fails at test time instead of surfacing as a runtime
// cache-degrade at live bringup.
//
// This is a leaf package with no imports: the posture-probe binary is a
// deliberately tiny static image companion and must be able to import these
// facts without pulling any dependency tree behind them.
package posture

// Home is the runtime user's home directory under the deploy posture. The
// image sets ENV HOME=Home so the global cache-dir default resolves under it;
// bare Home itself stays read-only (traversal only) — the writable surface is
// the tmpfs below.
const Home = "/root"

// CacheTmpfs is the single writable surface of the hardened posture: the
// tmpfs the compose posture mounts over the read-only rootfs. The VFS disk
// cache lives beneath it (…/rclone), and the posture witness probes it for
// writability. Everything outside this subtree (and the ready-file and mount
// destinations granted separately) is read-only at runtime.
const CacheTmpfs = Home + "/.cache"
