# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

### Known limitations

- Linux only. Pressure stall information needs kernel 4.20+ (with PSI
  enabled), the OOM kill counter 4.13+; older kernels show `n/a` there.
- Disk I/O of other users' processes is visible only to root.
- cgroup (container) memory limits are not evaluated; memory figures are
  system-wide.

[Unreleased]: https://github.com/Gelluithor/Tirnix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Gelluithor/Tirnix/releases/tag/v0.1.0
