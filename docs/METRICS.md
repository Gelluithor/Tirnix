# Metrics: sources, meaning and limitations

Every number Tirnix shows comes from a kernel interface listed below. If a
source cannot be read, the value is shown as `n/a` (or the panel says the
source is not available) – Tirnix never substitutes a guess.

Rates (per second values, percentages of CPU time) are computed from the
difference between two samples, so they appear after the second sample
(about half a second after start).

## CPU

| Value | Source | Notes |
|---|---|---|
| user, nice, system, irq, iowait, steal, idle | `/proc/stat` (`cpu` line) | Share of all CPU time in the interval. `irq` = hardware + soft interrupts. |
| busy | derived | `100 % − idle − iowait`. |
| per-core busy | `/proc/stat` (`cpuN` lines) | |
| context switches, forks | `/proc/stat` (`ctxt`, `processes`) | per second |
| running / blocked on I/O | `/proc/stat` (`procs_running`, `procs_blocked`) | instantaneous counts |
| load average | `/proc/loadavg` | On Linux it includes tasks in uninterruptible sleep (usually waiting for I/O), not only runnable ones. |
| pressure (PSI) | `/proc/pressure/cpu` | Linux 4.20+ with `CONFIG_PSI`; some distributions need the `psi=1` boot parameter. |

`iowait` is idle time during which some I/O was outstanding. It is a hint,
not a measure of disk load: an idle CPU with a busy disk shows high iowait,
a busy CPU with the same disk does not.

`steal` is time the hypervisor ran something else while this VM was ready to
run. It is always 0 on bare metal.

## Memory

| Value | Source | Notes |
|---|---|---|
| total, free, available, buffers, cached, shmem, dirty, writeback | `/proc/meminfo` | |
| used | derived | `MemTotal − MemAvailable` (memory that is *not* available to new workloads). On kernels older than 3.14 without `MemAvailable`: `total − free − buffers − cached − SReclaimable`. |
| swap used | `/proc/meminfo` | `SwapTotal − SwapFree` |
| swap in / out | `/proc/vmstat` (`pswpin`, `pswpout`) | pages per second |
| major faults | `/proc/vmstat` (`pgmajfault`) | page reads from disk per second |
| OOM kills | `/proc/vmstat` (`oom_kill`) | since boot; Linux 4.13+ |
| pressure (PSI) | `/proc/pressure/memory` | |
| file handles | `/proc/sys/fs/file-nr` | allocated / maximum |

Low *free* memory is normal on Linux – free RAM is used as page cache.
Tirnix therefore bases memory warnings on `MemAvailable`.

Memory limits of cgroups (containers, systemd units) are not evaluated; the
figures are system-wide. Inside a container, `/proc/meminfo` usually shows
the host's memory.

## Disks

| Value | Source | Notes |
|---|---|---|
| read/write bytes per second | `/proc/diskstats` (sectors × 512) | The sector unit in this file is always 512 bytes. |
| read/write IOPS | `/proc/diskstats` | completed requests per second |
| await | `/proc/diskstats` | (time spent on reads + writes) / completed requests, in ms. Includes queueing. |
| utilisation | `/proc/diskstats` (`io_ticks`) | Share of time with at least one request in flight. |
| device names | `/sys/block`, `/sys/block/<dev>/dm/name` | Only whole devices (no partitions); `loop*` and `ram*` are skipped, as are devices that never saw I/O. |

Totals (Overview, logging) sum only devices that are not built on other
devices (device-mapper, MD RAID are excluded), so the same I/O is not
counted twice.

Utilisation near 100 % means saturation only for devices that handle one
request at a time (classic hard disks). SSD, NVMe and RAID devices serve
many requests in parallel, so compare *await* as well.

## Filesystems

| Value | Source | Notes |
|---|---|---|
| mounts | `/proc/self/mountinfo` (fallback `/proc/self/mounts`) | |
| size, used, available | `statvfs(3)` | *available* is what unprivileged users can still write (excludes reserved blocks), like `df`. Usage % = used / (used + available), like `df` (which rounds up). |
| inodes | `statvfs(3)` | Some filesystems (e.g. btrfs) do not report inodes; shown as `n/a`. |
| read-only | super-block options in `mountinfo` | Read-only *bind* mounts of writable filesystems (common in sandboxes) are treated as writable. |

Skipped: pseudo filesystems (proc, sysfs, cgroup, …), squashfs/iso9660
images, container runtime internals (`/var/lib/docker`, `/snap`, …) and
mounts under `/proc` and `/sys`. Network and FUSE filesystems (NFS, CIFS,
sshfs, …) are skipped unless enabled in Settings because `statvfs` on an
unreachable server can block. Bind mounts of the same device are shown once.

The filesystem list is refreshed every 5 seconds.

## Processes

| Value | Source | Notes |
|---|---|---|
| state, threads, CPU time, RSS, parent | `/proc/<pid>/stat` | CPU % is relative to one CPU (like `top`) and can exceed 100 % for multi-threaded processes. |
| user | owner of `/proc/<pid>`, names from `/etc/passwd` | Users from LDAP/SSSD are shown as numeric uid. |
| command line | `/proc/<pid>/cmdline` | read only for rows on screen; kernel threads shown as `[name]` |
| read / write per second | `/proc/<pid>/io` (`read_bytes`, `write_bytes`) | Bytes that reached the storage layer. Readable only for your own processes unless run as root; otherwise `n/a`. Read only while the Processes screen is open. |

CPU % of a process first seen in the current sample is shown as `–`.

## Network

| Value | Source | Notes |
|---|---|---|
| RX/TX bytes and packets, errors, drops | `/proc/net/dev` | per second; totals since boot shown as well |
| virtual interface | `/sys/devices/virtual/net/<iface>` | Loopback, bridges, veth, tun, bonds … are excluded from totals to avoid double counting. If there is no physical interface (e.g. inside a container), totals use all interfaces except `lo`. |
| TCP counters | `/proc/net/snmp` (`Tcp:`) | Includes IPv4 and IPv6. Retransmit ratio = retransmitted / sent segments. |
| listen overflows / drops | `/proc/net/netstat` (`TcpExt:`) | |
| sockets: in use, TIME_WAIT, orphans | `/proc/net/sockstat`, `/proc/net/sockstat6` | |

Interfaces that never carried a packet are hidden. All network values are
for the network namespace Tirnix runs in.

## Permissions

Everything works as an unprivileged user except per-process I/O of other
users' processes, which the kernel only reveals to root (or with
`CAP_SYS_PTRACE`). Some hardened systems mount `/proc` with `hidepid=2`; then
only your own processes are visible.
