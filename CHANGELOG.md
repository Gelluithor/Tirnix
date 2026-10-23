# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-23

Tirnix 0.2.0 makes the diagnostics answer the next question you would ask:
not just *that* something is wrong, but *where* it happens and *which
process* is behind it. Everything new follows the same rule as before:
cheap counters on every sample, detailed inspection only while a problem is
actually happening – so the overhead in a healthy system is unchanged
(TUI about 0.6 % of one core, logger about 0.03 % at a 10 s interval).

### Find the source of network drops

Interface counters only tell you that packets are lost. Tirnix now works
out where they are lost and who is affected:

- **UDP sockets with full receive buffers** – names the socket, the process
  and its user, with the current drop rate, e.g. *"UDP socket 0.0.0.0:514
  (rsyslogd) drops datagrams: receive buffer full"*.
- **Full TCP accept queues** – names the listening port, the process and how
  many connections are waiting, e.g. *"Incoming TCP connections dropped at
  [::]:8080 (java)"*.
- **NIC receive ring overflows** – shows which CPUs handle the interface's
  interrupts and how busy they are, pointing at missing RSS / irqbalance.
- **Kernel receive backlog** – names the CPUs that cannot keep up.
- **Damaged frames** (CRC / alignment / length errors) – cable, port or
  duplex problems.
- **Full connection tracking table** – reported as critical when packets
  are dropped, as a warning above 90 %.
- **TCP memory-pressure drops** – pruned, backlog and receive-queue drops.
- **Harmless frames** for protocols the host does not use are recognised
  and labelled as such.
- **Unexplained drops** are reported honestly, together with the list of
  causes the counters ruled out and commands to dig further.

A new **Drop analysis** panel on the Network screen shows these sources
while drops occur.

### Smarter TCP retransmission findings

- Retransmissions are attributed to remote peers and the local processes
  involved.
- SYN retransmissions are recognised as unanswered connection attempts.
- When clients merely retry connections to this host's own full listen
  queue, the retransmissions are reported as a consequence (info) instead
  of a second, misleading warning.

### Find out what fills a disk

- A full filesystem now names **deleted files that are still held open** –
  space that `du` cannot see – and the process holding them. If they make
  up a large share of the used space, the finding says so in its title and
  suggests restarting that process.
- It also names the **processes writing to that filesystem right now**,
  with their write rate and the files they are writing.
- Under disk pressure, **per-process I/O is collected on every screen**, so
  the I/O bottleneck finding lists the processes doing the I/O.

### Spot memory leaks

- Processes whose resident memory **grows steadily** (at least 10 minutes,
  256 MiB and 25 %) are reported with the growth rate and an estimate of
  how long the available memory would last. One-off jumps such as a cache
  warming up are ignored.
- The low-memory finding points to the fastest growing process.

### Know what blocked processes wait for

- Processes stuck in uninterruptible sleep (state `D`) are grouped by what
  they wait for – an NFS or SMB server, a FUSE filesystem, the filesystem
  journal, disk I/O or a kernel lock – and the findings say so in the title,
  e.g. *"Tasks are persistently blocked waiting for an NFS server"*.

### Also changed

- Processes that are not visible without root are reported with the user
  that owns the socket instead of being left out.
- New stored and chartable metrics: NIC overruns, damaged frames, receive
  backlog drops, UDP buffer drops, conntrack usage and drops, TCP
  receive-side drops.
- Release notes on GitHub no longer break lines in the middle of sentences.

### Notes

- Identifying other users' processes (socket owners, open files, wait
  locations) requires root; without it Tirnix says what it could not see.
- Memory growth detection needs a running TUI session; `tirnix report`
  samples for too short a time.

## [0.1.0] - 2026-10-23

The first release of Tirnix: a lightweight terminal UI that monitors a Linux
system, spots common problems and explains how to confirm them.

### Highlights

- **Eight screens, one keypress apart:** Overview, CPU & Memory, Disks,
  Processes, Network, Diagnostics, History and Settings. The Overview fits
  all key metrics on an 80×24 terminal, and the header shows CPU, memory,
  load, findings and logging state on every screen.
- **Diagnostics that explain, not just alert.** Every finding separates
  what was *measured*, *possible causes* (marked as hypotheses) and *how to
  verify* (ready-to-run commands). Covered: CPU saturation, load caused by
  I/O waits, CPU steal, disk bottlenecks, low memory and swapping, memory
  pressure from cgroup limits, OOM kills, full or fast-filling filesystems,
  inode exhaustion, interface errors and drops, TCP retransmissions, listen
  queue drops, TIME_WAIT build-up, blocked tasks, zombies and file handle
  exhaustion.
- **No false alarms from spikes:** rate-based rules fire only when a
  condition persists for most of a 30-second window.
- **Optional long-term history.** Turn logging on in Settings and a small
  background process keeps recording after you close the TUI or log out.
  Choose metric groups, interval (1–60 s), directory, retention and size
  limit. Chart any metric over 1 hour to 30 days and compare it with the
  previous period, or export it as CSV/JSONL.
- **Honest numbers:** everything comes from `/proc`, `/sys` and `statvfs`;
  sources that are missing are shown as `n/a`.
- **Light enough for production:** about 0.6–0.8 % of one core and 2 MiB
  of RAM for the TUI, 0.05 % and 1.5 MiB for the logger at a 10 s interval.
  No daemon, database, telemetry or network traffic unless you ask for it.

### Also included

- `tirnix report` – one-shot text report for scripts and quick SSH checks.
- `tirnix export` – stored history as JSON Lines or CSV.
- Optional active checks (DNS resolution + TCP connect) against your own
  targets, run only when you press `a` on the Diagnostics screen.
- Process list with sorting, filtering, full command lines and per-process
  disk I/O.
- Works without root, over SSH and in small terminals; ASCII fallback for
  non-UTF-8 locales; honours `NO_COLOR`.

### Installation

```sh
curl -fsSL https://raw.githubusercontent.com/Gelluithor/Tirnix/main/install.sh | sh
```

The script verifies the download against `SHA256SUMS` and installs a single
static binary to `~/.local/bin` (no root needed; `--system` for
`/usr/local/bin`). `.deb` and `.rpm` packages and plain archives are
attached below for x86_64 and aarch64. Nothing is enabled or started on
installation; optional, hardened systemd units are included for running the
logger at boot.

### License

Tirnix is free software licensed under the GNU General Public License,
version 3 or (at your option) any later version (`GPL-3.0-or-later`).

### Known limitations

- Linux only. Pressure stall information needs kernel 4.20+ (with PSI
  enabled), the OOM kill counter 4.13+; older kernels show `n/a` there.
- Disk I/O of other users' processes is visible only to root.
- cgroup (container) memory limits are not evaluated; memory figures are
  system-wide.

[Unreleased]: https://github.com/Gelluithor/Tirnix/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Gelluithor/Tirnix/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Gelluithor/Tirnix/releases/tag/v0.1.0
