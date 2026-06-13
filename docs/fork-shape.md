<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Fork shape: a thin wrapper module over rclone

This binary builds on [rclone](https://github.com/rclone/rclone) (MIT). There are two
ways to do that, and this document records which we chose and why.

## The choice

**A — true source fork.** Import rclone's tree (or a squashed snapshot) into this
repository, add our backend package in-tree, and periodically rebase onto upstream tags.

**B — thin wrapper module (chosen).** Keep our own small Go module. rclone is a pinned
dependency in `go.mod` / `go.sum` at an exact tagged release. Our backend registers
itself through rclone's public backend registry (`fs.Register`) in package `init()`, and
our own `main` drives rclone's mount machinery for multiple concurrent mounts. The diff
against upstream rclone is zero; a "rebase" is a dependency version bump whose proof is a
green CI run.

We chose **B**.

## Why

- **Smallest possible diff, cheapest rebases.** The fork-discipline rule for this binary
  is "one backend package plus the smallest possible diff elsewhere, so rebases stay
  cheap and the diff is auditable." A wrapper module is the limit case: the diff against
  upstream is zero and the only thing to keep current is one pinned version.
- **The audit surface is only our code.** This repository is public and runs strict CI
  from the first commit (secrets, SAST, SCA, naming denylist, conventional commits). In a
  source fork those gates would scan the entire upstream tree — permanent noise that we
  cannot fix upstream and that buries real findings in our own code. In a wrapper module
  every scanned line is ours.
- **No unused transport is linked into the guest.** rclone's own entrypoint links every
  backend; ours links only our backend plus the mount machinery. The shipped guest binary
  therefore contains no object-store client of any kind. This is a load-bearing security
  property of the guest (no second transport, no backend client), and as a wrapper it is
  checkable mechanically — a CI test asserts the dependency graph (`go list -deps`)
  contains no foreign backend or object-store SDK — rather than being a review promise.
- **Licensing stays clean.** Every file in this tree is ours and carries the
  FSL-1.1-Apache-2.0 header; rclone is an unmodified upstream dependency recorded in
  `NOTICE`. There is no per-directory license split to audit.

## The seams we rely on

A wrapper is only viable if the machinery we need is reachable as a library. We rely on:

- the backend registry (`fs.Register`) for registering our backend out-of-tree;
- rclone's mount machinery, driven through its remote-control surface, to mount several
  filesystems in one process with per-mount VFS options and read-only enforcement;
- the VFS option set (cache mode, cache size cap, directory cache duration, file and
  directory permissions, read-only);
- the pacer / retry helpers for backpressure handling.

Exact API signatures and the precise mount entry point are pinned and verified against
the chosen rclone release during the phases that build the backend and the mounter, not
asserted here.

### The mount symbols, pinned

The mounter relies on these exported rclone symbols, all reachable as library calls with
zero upstream diff:

- A first-party direct-mount function is the mount function the mounter drives. It serves
  the VFS over go-fuse's direct `mount(2)` path (`DirectMountStrict`), so the kernel mount
  needs only `/dev/fuse` and `CAP_SYS_ADMIN` and never execs a fusermount helper
  subprocess — the load-bearing property in a minimal static guest image that carries no
  such helper. The rclone↔FUSE node tree is built from `cmd/mount2`'s exported surface
  (`mount2.NewFS`, `(*FS).Root`), blank-imported for that surface only, so every file
  operation maps exactly as rclone's mount2 frontend maps it and the diff to upstream
  rclone stays zero; only the server assembly is ours. The mounter does not resolve a
  mount function from rclone's registry: the registry-resolved `"mount2"` function leaves
  `DirectMount` unset and so falls back to exec'ing a fusermount helper, which the guest
  image does not provide.
- `cmd/mountlib.NewMountPoint(fn, mountpoint, fs, mountOpt, vfsOpt)` — assembles a mount
  from that mount function, the ocufs Fs, and the mapped options.
- `(*cmd/mountlib.MountPoint).Mount()` — starts the live mount. It constructs the VFS
  itself from the Fs and the VFS options; the wrapper never constructs a VFS separately, so
  no second VFS is leaked into the package-level active cache.
- `cmd/mountlib.CanCheckMountReady` / `cmd/mountlib.CheckMountReady(mountpoint)` — the
  nil-safe readiness primitives the mounter polls itself to confirm the kernel reports the
  mountpoint live before the mount is treated as ready. The mounter does not call
  `cmd/mountlib.WaitMountReady`: that helper reads the daemon process pid unconditionally
  on every poll, and a non-daemon mount returns a nil daemon, so it would dereference nil
  on the first not-ready poll. The self-rolled bounded poll uses the same kernel check with
  zero upstream diff (and on a leg where `CanCheckMountReady` is false, readiness is
  blind-trusted rather than checked).
- `(*cmd/mountlib.MountPoint).Wait()` / `.Unmount()` — bridged into the orchestrator's
  per-point lifecycle for spontaneous-exit detection and teardown.

These calls are build-tagged to the platforms the kernel mount method supports
(`linux || (darwin && amd64)`); on any other target a fail-closed stub returns a typed
"mount method unavailable" error so the binary refuses to mount rather than mis-mounting.

## Recovery path

If a future rclone release removes a seam we depend on, the backend package moves into a
true source fork (option A) unchanged — the wrapper is recoverable to a fork with no
wasted work. The reverse is not true, which is another reason to start as a wrapper.
