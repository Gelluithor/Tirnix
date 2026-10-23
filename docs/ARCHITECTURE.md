# Tirnix architecture

This document describes how Tirnix is put together and why. It is meant for
contributors; user documentation lives in the [README](../README.md) and the
other files in this directory.

## Goals that shape the design

1. **Low overhead.** Tirnix must be safe to leave open on a production box.
   Nothing runs in the background unless the user explicitly enables logging.
2. **Honest numbers.** Every value comes from a kernel interface (`/proc`,
   `/sys`, `statvfs(3)`). Missing sources are shown as `n/a`, never guessed.
3. **Simple to ship.** One static binary, no services, no database server.

## Module layout

```
src/
├── main.rs            CLI parsing and dispatch (hand-written, no clap)
├── util.rs            Formatting, UTC/local time conversion, small helpers
├── config.rs          Config file (TOML) load/save, default paths
├── collect/
│   ├── mod.rs         Collector: owns previous counters, turns them into a Snapshot
│   ├── procfs.rs      Pure parsers for /proc text formats (unit tested)
│   ├── files.rs       Deleted-but-open and written files via /proc/<pid>/fd
│   ├── fs.rs          Mount table filtering + statvfs
│   ├── netdiag.rs     Network drop analysis: classify drops, find sockets/processes
│   └── process.rs     /proc/<pid> scanning, per-process CPU / RSS / I/O
├── metrics.rs         Data model: Snapshot (live) and Record (compact, storable)
├── window.rs          In-memory ring buffer of Records + statistics helpers
├── diagnose.rs        Diagnostic rules -> Findings (facts / hypotheses / checks)
├── active.rs          Optional, user-triggered connectivity checks (DNS + TCP)
├── storage.rs         Hourly JSONL files, range reads, retention
├── logger.rs          Background logger process: lock, pid, signals, loop
├── export.rs          JSONL / CSV export of stored history
├── report.rs          One-shot text report (`tirnix report`)
└── tui/
    ├── mod.rs         Event loop, App state, key handling
    ├── widgets.rs     Shared drawing helpers (bars, tables, sparklines)
    └── screens/…      One file per screen
```

Collection is independent of the UI: `Collector::sample()` returns a
`Snapshot`. The TUI, the logger and `tirnix report` all use the same
collector, so a new metric only needs to be added once in `collect` and once
in the screens that show it.

## Data model

* **Raw counters** (`collect::procfs::*Raw`) mirror kernel files 1:1.
* **Snapshot** holds derived values for one moment: percentages and per-second
  rates computed from the delta between two raw samples. Every group is an
  `Option` (or an empty `Vec`) so that a missing source is visible as such.
  Rates are `None` on the very first sample because there is no previous
  value to compare with.
* **Record** is a flat summary of a Snapshot (about 30 optional numeric
  fields). It is what the in-memory window stores, what diagnostics read for
  "sustained" conditions, and what the logger writes as one JSON line.

## Efficient collection

* One reusable `String` buffer for all file reads; no per-sample allocations
  for the common files.
* Process scanning (`/proc/<pid>/stat`) runs only when a consumer needs it.
  `/proc/<pid>/io` is read only while the Processes screen is visible, and
  `/proc/<pid>/cmdline` only for rows that are actually on screen.
* Filesystem usage (`statvfs`) is refreshed at most every 5 seconds. Network
  filesystems are skipped by default because `statvfs` on a dead NFS server
  can block. Mounts come from `/proc/self/mountinfo`, whose super-block
  options tell a read-only filesystem apart from a read-only *bind* mount –
  important under systemd's `ProtectSystem=strict`, where every mount looks
  read-only to `statvfs`.
* Totals avoid double counting: stacked block devices (dm, md) and virtual
  network interfaces are excluded. If there is no physical interface at all
  (inside a container), totals fall back to every interface except `lo`.
* The list of block devices and network interfaces (from `/sys`) is cached
  and refreshed once a minute.
* The logger does not scan processes at all.
* "Escalation": detailed sources are read only while cheap counters show a
  problem. Network drop analysis reads socket tables, `/proc/<pid>/fd` and
  `/proc/interrupts` only while drops occur, at most every 5 s, and caches
  socket owners for a minute. Disk pressure enables per-process I/O and
  open-file scans (every 30 s) for 10 minutes; memory growth tracking keeps
  one RSS point per 30 s for processes over 64 MiB.

## Diagnostics

Rules live in `diagnose.rs`. Each rule produces a `Finding` with

* **measured facts** – numbers taken directly from the snapshot/window;
* **possible causes** – explicitly labelled as hypotheses;
* **how to verify** – concrete commands the operator can run.

To avoid false alarms, rules about rates and utilisation require the
condition to hold for most of a sustain window (30 s in the TUI) instead of
firing on a single spike. Point-in-time facts (a filesystem at 97 %, an OOM
kill counter that increased) fire immediately.

Active checks (DNS resolution, TCP connect) live in `active.rs`. They are
never run by the passive collector; the user must configure targets and press
a key on the Diagnostics screen.

## Logging process

```
 TUI (Settings)                       tirnix logger run (detached, setsid)
 ──────────────                       ────────────────────────────────────
 toggle ON ─ writes config ─────────▶ reads config, flock(logger.lock),
           └ spawns detached process   writes logger.pid, loops:
 toggle OFF ─ writes config,             sample → Record → append JSONL
            └ SIGTERM via pid file       retention every 10 min
 status ◀── lock held? pid, sizes ──    reloads config when its mtime changes
```

* **Single instance:** an exclusive `flock` on `<data_dir>/logger.lock`. The
  lock, not the pid file, decides whether a logger is running, so stale pid
  files are harmless.
* **Stopping:** `SIGTERM`/`SIGINT` set a flag; the sleep (`nanosleep`
  without `SA_RESTART`) is interrupted and the loop flushes and exits.
* **Opt-in only:** `tirnix logger run` refuses to start unless
  `logging.enabled = true` in the config. Nothing enables it automatically.
* **systemd:** optional unit files live in `contrib/systemd/`; installing and
  enabling them is a manual, documented step.

### Storage format

Hourly files `metrics-YYYYMMDD-HH.jsonl` (UTC) in the data directory, one
JSON object per line. Rationale versus SQLite:

* no C library to bundle, smaller binary, trivial static linking;
* retention and size limits are "delete whole old files", no vacuuming;
* the files are already a useful export format (`jq`, `grep`, scripts);
* a torn last line after a crash is skipped by the reader.

Range queries open only the files whose hour overlaps the range. The History
screen downsamples to the screen width.

## Configuration

`$TIRNIX_CONFIG`, else `$XDG_CONFIG_HOME/tirnix/config.toml`, else
`~/.config/tirnix/config.toml`. A missing file means defaults; Tirnix writes
the file only when the user changes something in Settings. The file is
written from a commented template so it stays readable.

## Dependencies

| Crate        | Why                                              |
|--------------|--------------------------------------------------|
| `ratatui`    | TUI rendering (crossterm backend, re-exported)   |
| `serde`      | (De)serialisation of config and records          |
| `serde_json` | JSONL storage and export                         |
| `toml`       | Config file                                      |
| `libc`       | `statvfs`, `flock`, `setsid`, signals, `sysconf` |

No async runtime, no CLI framework, no time library. Time conversion is a
few lines of civil-calendar arithmetic in `util.rs`.
