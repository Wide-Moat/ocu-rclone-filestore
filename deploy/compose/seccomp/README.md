<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Seccomp profiles for the guest mount

The seccomp JSON files in this directory cannot carry a license header inline
(seccomp JSON has no comment syntax and the loader rejects unknown top-level
keys). The FSL-1.1-Apache-2.0 / Copyright (c) 2025 Open Computer Use
Contributors header for the authored profiles lives here instead. Each profile
does carry a machine-readable `comment` on its first syscall group describing
its intent (a field the loader accepts and ignores).

Both profiles begin from the container runtime's published default seccomp
allowlist (`defaultAction: SCMP_ACT_ERRNO`) and add only what the in-process
FUSE direct mount needs. The mount mechanism is go-fuse `DirectMountStrict`: the
guest performs `mount(2)` itself onto the mountpoint and `umount2(2)` on
teardown — there is no `fusermount` helper subprocess. Opening `/dev/fuse` and
the read/write/poll traffic that serves the filesystem over that fd are ordinary
syscalls the default profile already allows; the only privileged additions the
mount path needs from seccomp are `mount` and `umount2`.

## `mount-fuse.json` — the profile in use (narrower than default)

The runtime default allows a broad set of privileged admin syscalls whenever
`CAP_SYS_ADMIN` is in the bounding set (one cap-gated group covering `bpf`,
`setns`, `unshare`, the new mount API `fsopen`/`fsconfig`/`fsmount`/`fspick`/
`move_mount`/`open_tree`/`mount_setattr`, the legacy `umount`, `quotactl`,
`set{host,domain}name`, `fanotify_init`, `lookup_dcookie`, and the thread
syscalls `clone`/`clone3`). The guest holds `CAP_SYS_ADMIN` solely to satisfy
the kernel mount permission check, and of that whole set it exercises only
`mount(2)` and `umount2(2)`.

This profile therefore removes that broad cap-gated group and adds back, as an
unconditional allow, only:

- `mount`, `umount2` — the FUSE direct-mount path.
- `clone`, `clone3` — the language runtime's OS-thread creation. These must be
  kept: the default profile's masked-`clone` fallback (the allowance used by
  containers without `CAP_SYS_ADMIN`) rejects the runtime's thread-creation
  `clone` once the unconditional cap-gated allowance is removed, which crashes
  the process at startup with `failed to create new OS thread (errno=1)`.

Net result vs. the default at this posture (`CAP_SYS_ADMIN` held): sixteen
admin syscalls are now denied that the default would have permitted —
`fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree`,
`mount_setattr`, `setns`, `unshare`, `umount` (legacy), `quotactl`,
`quotactl_fd`, `setdomainname`, `sethostname`, `fanotify_init`,
`lookup_dcookie`. `bpf`, `perf_event_open`, and `syslog` fall back to their
own dedicated capability gates (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYSLOG`),
which the guest does not hold.

## `mount-fuse-floor.json` — the safe floor (default + mount/umount2)

The conservative fallback: the runtime default profile unchanged, plus a single
unconditional allow for `mount` and `umount2`. It does not remove anything, so
it cannot regress any syscall the runtime needs; it only guarantees the FUSE
mount path is permitted regardless of how the default's cap-gating evaluates.
Use this only if a future syscall regression makes the narrower
`mount-fuse.json` unworkable; otherwise prefer `mount-fuse.json`.

## Independence of the gates

Seccomp and Linux capabilities are independent gates. With either profile, a
container that does NOT hold `CAP_SYS_ADMIN` still cannot mount: the syscall is
permitted by seccomp but the kernel rejects it at the capability check
(`EPERM`). Likewise, dropping the `mount`/`umount2` allowance from the profile
blocks the mount at the seccomp layer even with `CAP_SYS_ADMIN` held. Neither
gate alone is sufficient; both must permit the mount.
