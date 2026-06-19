# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Narrow AppArmor profile for the guest FUSE mount service.
#
# The container's default AppArmor profile denies the `mount` rule outright, so
# even with CAP_SYS_ADMIN the in-process mount(2) the guest performs is refused.
# The usual relaxation is `apparmor=unconfined`, which removes ALL mandatory
# access control. This profile instead grants the single thing the mount path
# needs — mounting and unmounting a `fuse.*` superblock — and keeps the rest of
# the confinement (no raw block-device mounts, no remount of the host rootfs, no
# ptrace out, no arbitrary capabilities).
#
# What the guest mount actually does on the kernel (all proven against the live
# DirectMountStrict path):
#   - open("/dev/fuse", O_RDWR) to obtain the FUSE channel fd;
#   - mount(source, mountpoint, "fuse.rclone", MS_NOSUID|MS_NODEV[|MS_RDONLY],
#     "fd=,rootmode=,user_id=,group_id=,allow_other,max_read=") — a fuse.*
#     superblock onto each mountpoint dir; no path is bind-mounted;
#   - umount2(mountpoint, 0) on teardown;
#   - ordinary read/write/poll over the /dev/fuse fd to serve the filesystem;
#   - write the rclone VFS disk cache under /root/.cache/rclone (the runtime
#     sets HOME=/root, so os.UserCacheDir() resolves there), the ready-file
#     under /run/ocu, and (as the mount target) the files under /mnt/user-data.
#
# Load it into the kernel before `up`:
#     sudo apparmor_parser -r -W deploy/compose/apparmor/ocu-mount.profile
# then point the mount service at it:
#     security_opt: [ "apparmor=ocu-mount" ]
#
# Tightening notes (kept as deliberate, minimal allowances):
#   - The mount rule is scoped to `fstype=fuse.*` only; no other filesystem type
#     can be mounted. The mountpoint targets are scoped to /mnt/user-data/**.
#   - `umount` is unscoped by path because the kernel applies the umount check
#     against the mounted-superblock label, and pinning it to the same target
#     set is sufficient; it is restricted to this profile's processes.
#   - capability is reduced to sys_admin alone (the mount path's only cap); the
#     default container capability set is not granted.

#include <tunables/global>

profile ocu-mount flags=(attach_disconnected,mediate_deleted) {

  # ---- capabilities ---------------------------------------------------------
  # The mount/umount syscalls are gated by CAP_SYS_ADMIN; it is the sole cap the
  # mount path exercises. No other capability is permitted.
  capability sys_admin,

  # ---- intra-process signals ------------------------------------------------
  # The Go runtime preempts its own goroutines with SIGURG and delivers
  # SIGTERM/SIGINT to itself; allow this profile's processes to signal one
  # another. The container-orchestrator's stop signal (from a process OUTSIDE
  # this profile) is mediated by the SENDER's profile, not this one.
  signal (send,receive) peer=ocu-mount,
  signal (receive) set=(term,int,kill),

  # ---- the FUSE mount, and nothing else -------------------------------------
  # Allow mounting a fuse.* superblock onto a mountpoint under the canonical
  # mount root. The mount DATA string (fd=,rootmode=,user_id=,group_id=,
  # allow_other,max_read=) is not path-bearing, so only the fstype and the
  # target need naming. MS_RDONLY/MS_NOSUID/MS_NODEV ride the flags and need no
  # extra rule.
  mount fstype=fuse.* -> /mnt/user-data/**,
  mount fstype=fuse.* -> /mnt/user-data/,

  # Teardown of the FUSE mounts.
  umount /mnt/user-data/**,
  umount /mnt/user-data/,

  # ---- the FUSE device ------------------------------------------------------
  # The character device that backs the FUSE channel. r/w over this fd is how
  # the filesystem is served.
  /dev/fuse rw,

  # ---- device nodes the serve path and Go runtime use -----------------------
  # The zero-copy splice read path discards bytes through /dev/null; the runtime
  # seeds its RNG from /dev/urandom. These are the only two device nodes the live
  # mount path was observed to touch; the other standard nodes are not granted.
  /dev/null rw,
  /dev/urandom r,

  # ---- the binary -----------------------------------------------------------
  # Exec of the static mount binary; the image carries only this one binary.
  /ocu-rclone-filestore mr,

  # ---- runtime writes the mount process makes -------------------------------
  # The rclone VFS disk cache. The container runtime sets HOME=/root for the root
  # user (a runtime default, not an image env entry), so rclone's os.UserCacheDir()
  # resolves to /root/.cache and rclone builds its on-disk cache under
  # /root/.cache/rclone. The write surface is scoped to that cache subtree (bare
  # /root is read-only traversal only). Removing the /root/.cache write grant
  # disables the VFS cache (mkdir /root/.cache: permission denied) and breaks the
  # SEC-46 hold-data-across-throttle path, so it is load-bearing, not optional.
  # No /tmp write grant: with HOME=/root the cache lives under /root/.cache and
  # the live full exercise (cold read + throttle + teardown) completes with the
  # container's /tmp left empty, so the mount path writes nothing under /tmp.
  /root/ r,
  /root/.cache/ rw,
  /root/.cache/** rwk,
  # The ready-file handoff directory (a named volume in the compose graph). Bare
  # /run is traversal-only; the write surface is the /run/ocu subtree.
  /run/ r,
  /run/ocu/ rw,
  /run/ocu/** rwk,
  # The mount destinations themselves (the FUSE superblock is mounted here and
  # files are written through it on the RW mounts). Bare /mnt is traversal-only;
  # writes are scoped to the /mnt/user-data subtree. Create permission on
  # /mnt/user-data covers the compose graph creating outputs2/ throttle/ at bringup.
  /mnt/ r,
  /mnt/user-data/ rw,
  /mnt/user-data/** rwk,
  # The read-only guest config and the bringup artifacts.
  /shared/ r,
  /shared/** r,

  # ---- process basics -------------------------------------------------------
  # The exact /proc, /sys and /etc reads the mount makes, enumerated by running
  # the real binary under a complain-mode copy of this profile and recording
  # every access. Nothing broader is granted.
  #   - Go runtime: cgroup CPU quota (GOMAXPROCS), THP page size, auxv;
  #   - go-fuse splice: the pipe max-size used to size the splice pipe;
  #   - the mount readiness check: its own mountinfo;
  #   - rclone: the system MIME-type table;
  #   - the TLS trust store for the outbound HTTPS connection to the egress edge.
  # @{PROC} expands to /proc; @{pid}/@{tid} match the process's own ids whether
  # it runs as pid 1 (private pid ns) or a host pid (the e2e graph's pid:host).
  @{PROC}/sys/fs/pipe-max-size r,
  @{PROC}/sys/kernel/ r,
  @{PROC}/sys/kernel/* r,
  @{PROC}/sys/vm/overcommit_memory r,
  @{PROC}/@{pid}/auxv r,
  @{PROC}/@{pid}/cgroup r,
  @{PROC}/@{pid}/mountinfo r,
  @{PROC}/@{pid}/task/ r,
  @{PROC}/@{pid}/task/@{tid}/mountinfo r,
  /sys/kernel/mm/transparent_hugepage/hpage_pmd_size r,
  /sys/fs/cgroup/cpu.max r,
  /etc/mime.types r,
  # The CA trust store the outbound HTTPS connection chains against (the image
  # sets SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt; the per-mount edge CA
  # arrives in the config under /shared, granted above).
  /etc/ssl/certs/ r,
  /etc/ssl/certs/** r,
  /etc/ssl/openssl.cnf r,
  /etc/nsswitch.conf r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/host.conf r,
  /etc/passwd r,
  /etc/group r,

  # Default-deny does the rest: any mount/umount whose fstype is not fuse.* is
  # refused because no rule permits it, and any path not granted above is
  # refused. These explicit denies harden the high-value escape targets so they
  # cannot be re-granted by accident.
  deny /proc/sys/kernel/** w,
  deny /sys/kernel/security/** rwklx,
  deny ptrace,
}
