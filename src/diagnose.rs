//! Diagnostic rules.
//!
//! Each rule inspects the current [`Snapshot`] and the recent [`Window`] and
//! may emit a [`Finding`]. A finding keeps three things apart:
//!
//! * `facts`  – values that were measured;
//! * `causes` – hypotheses that could explain them (never stated as fact);
//! * `checks` – commands the operator can run to confirm or rule them out.
//!
//! Rules about rates require the condition to be *sustained* (see
//! [`Window::sustained`]); point-in-time facts such as a nearly full
//! filesystem fire immediately. Thresholds are deliberately conservative.

use std::collections::{HashMap, VecDeque};

use crate::metrics::{ProcInfo, Snapshot};
use crate::util::{fmt_bytes, fmt_count, fmt_duration, fmt_pct, fmt_rate};
use crate::window::{self, Window};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Critical => "CRIT",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Stable identifier, e.g. `fs-space:/var`.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub facts: Vec<String>,
    pub causes: Vec<String>,
    pub checks: Vec<String>,
}

impl Finding {
    fn new(id: impl Into<String>, severity: Severity, title: impl Into<String>) -> Self {
        Finding {
            id: id.into(),
            severity,
            title: title.into(),
            facts: Vec::new(),
            causes: Vec::new(),
            checks: Vec::new(),
        }
    }

    fn fact(mut self, s: impl Into<String>) -> Self {
        self.facts.push(s.into());
        self
    }

    fn cause(mut self, s: impl Into<String>) -> Self {
        self.causes.push(s.into());
        self
    }

    fn check(mut self, s: impl Into<String>) -> Self {
        self.checks.push(s.into());
        self
    }
}

// Thresholds. Kept in one place so they are easy to review and document.
const CPU_BUSY_PCT: f64 = 90.0;
const LOAD_PER_CPU: f64 = 1.5;
const IOWAIT_PCT: f64 = 20.0;
const DISK_UTIL_PCT: f64 = 90.0;
const MEM_AVAIL_WARN_PCT: f64 = 10.0;
const MEM_AVAIL_CRIT_PCT: f64 = 5.0;
const SWAP_PAGES_PER_S: f64 = 100.0;
const PSI_MEM_PCT: f64 = 10.0;
const PSI_IO_PCT: f64 = 20.0;
const FS_WARN_PCT: f64 = 90.0;
const FS_CRIT_PCT: f64 = 95.0;
const FS_FILL_HORIZON_SECS: f64 = 24.0 * 3600.0;
const FS_TREND_MIN_SECS: i64 = 600;
const INODE_WARN_PCT: f64 = 90.0;
const INODE_CRIT_PCT: f64 = 95.0;
const RETRANS_PCT: f64 = 2.0;
const RETRANS_MIN_PER_S: f64 = 5.0;
const STEAL_PCT: f64 = 10.0;
const TIME_WAIT_HIGH: f64 = 30_000.0;
const ZOMBIES_HIGH: usize = 20;
const FD_WARN_PCT: f64 = 80.0;
const FD_CRIT_PCT: f64 = 95.0;

/// Stateful rule engine (remembers OOM baseline and filesystem trends).
pub struct Engine {
    /// Seconds a rate condition must hold before it is reported.
    pub sustain_secs: i64,
    oom_baseline: Option<u64>,
    fs_trend: HashMap<String, VecDeque<(i64, u64)>>,
}

impl Engine {
    pub fn new(sustain_secs: i64) -> Self {
        Engine {
            sustain_secs: sustain_secs.max(1),
            oom_baseline: None,
            fs_trend: HashMap::new(),
        }
    }

    /// Run every rule; results are sorted by severity (most severe first).
    pub fn evaluate(&mut self, s: &Snapshot, w: &Window) -> Vec<Finding> {
        let now = s.time as i64;
        let ctx = Ctx {
            s,
            w,
            now,
            secs: self.sustain_secs,
        };
        let mut out = Vec::new();
        rule_cpu(&ctx, &mut out);
        rule_steal(&ctx, &mut out);
        rule_io(&ctx, &mut out);
        rule_memory(&ctx, &mut out);
        self.rule_oom(&ctx, &mut out);
        self.rule_filesystems(&ctx, &mut out);
        rule_network(&ctx, &mut out);
        rule_tcp(&ctx, &mut out);
        rule_processes(&ctx, &mut out);
        rule_file_handles(&ctx, &mut out);
        out.sort_by_key(|a| std::cmp::Reverse(a.severity));
        out
    }

    fn rule_oom(&mut self, c: &Ctx, out: &mut Vec<Finding>) {
        let Some(kills) = c.s.mem.as_ref().and_then(|m| m.oom_kills) else {
            return;
        };
        let base = *self.oom_baseline.get_or_insert(kills);
        if kills > base {
            out.push(
                Finding::new(
                    "oom-new",
                    Severity::Critical,
                    "The kernel OOM killer terminated processes",
                )
                .fact(format!(
                    "{} process(es) killed by the OOM killer since Tirnix started ({kills} since boot).",
                    kills - base
                ))
                .cause("Memory demand exceeded RAM + swap, or a cgroup memory limit (container, systemd unit) was hit.")
                .cause("A process with a memory leak grew until the system ran out of memory.")
                .check("journalctl -k --since -1h | grep -iE 'out of memory|oom'")
                .check("dmesg -T | grep -i -A5 'invoked oom-killer'")
                .check("systemctl --failed   # services stopped by the kill"),
            );
        } else if kills > 0 {
            out.push(
                Finding::new(
                    "oom-boot",
                    Severity::Info,
                    "OOM kills occurred earlier since boot",
                )
                .fact(format!(
                    "{kills} OOM kill(s) since boot, none since Tirnix started."
                ))
                .cause("A past memory shortage; it may not be ongoing.")
                .check("journalctl -k | grep -iE 'out of memory|oom-kill'"),
            );
        }
    }

    fn rule_filesystems(&mut self, c: &Ctx, out: &mut Vec<Finding>) {
        let mut seen = Vec::new();
        for f in c.s.filesystems.iter().filter(|f| !f.readonly) {
            seen.push(f.mount_point.clone());
            // Track available space to estimate a fill rate.
            let trend = self.fs_trend.entry(f.mount_point.clone()).or_default();
            if trend.back().is_none_or(|(t, _)| c.now - t >= 5) {
                trend.push_back((c.now, f.avail));
            }
            while trend.front().is_some_and(|(t, _)| c.now - t > 3600) {
                trend.pop_front();
            }
            let fill = fill_estimate(trend, f.avail);

            let used_pct = f.used_pct().unwrap_or(0.0);
            let sev = if used_pct >= FS_CRIT_PCT {
                Some(Severity::Critical)
            } else if used_pct >= FS_WARN_PCT {
                Some(Severity::Warning)
            } else {
                None
            };
            let fast_fill = fill.filter(|(secs, _)| *secs < FS_FILL_HORIZON_SECS);
            if let Some(sev) = sev.or(fast_fill.map(|_| Severity::Warning)) {
                let title = if sev == Severity::Warning && used_pct < FS_WARN_PCT {
                    format!("Filesystem {} is filling up quickly", f.mount_point)
                } else {
                    format!("Filesystem {} is {} full", f.mount_point, fmt_pct(used_pct))
                };
                let mut fd =
                    Finding::new(format!("fs-space:{}", f.mount_point), sev, title).fact(format!(
                        "{} used, {} available of {} ({} on {}).",
                        fmt_bytes(f.used as f64),
                        fmt_bytes(f.avail as f64),
                        fmt_bytes(f.total as f64),
                        f.fstype,
                        f.device
                    ));
                if let Some((secs, rate)) = fill {
                    fd = fd.fact(format!(
                        "Free space shrinks by about {}/h (measured); estimated full in ~{} if this continues.",
                        fmt_bytes(rate * 3600.0),
                        fmt_duration(secs)
                    ));
                }
                out.push(
                    fd.cause("Growing log files or journals.")
                        .cause("Backups, core dumps, caches or container images accumulating.")
                        .cause("Deleted files still held open by a process (space is freed only when it closes them).")
                        .check(format!("du -xh --max-depth=2 {} 2>/dev/null | sort -h | tail -20", f.mount_point))
                        .check("lsof +L1   # deleted but still open files")
                        .check("journalctl --disk-usage"),
                );
            }

            if let Some(ip) = f.inode_pct() {
                let sev = if ip >= INODE_CRIT_PCT {
                    Some(Severity::Critical)
                } else if ip >= INODE_WARN_PCT {
                    Some(Severity::Warning)
                } else {
                    None
                };
                if let Some(sev) = sev {
                    out.push(
                        Finding::new(
                            format!("fs-inodes:{}", f.mount_point),
                            sev,
                            format!("Filesystem {} is running out of inodes", f.mount_point),
                        )
                        .fact(format!(
                            "{} of inodes used ({} free of {}). New files cannot be created when none are left, even with free space.",
                            fmt_pct(ip),
                            fmt_count(f.inodes_free as f64),
                            fmt_count(f.inodes_total as f64)
                        ))
                        .cause("Very many small files: caches, session files, mail queues, build artefacts.")
                        .check(format!("df -i {}", f.mount_point))
                        .check(format!(
                            "find {} -xdev -type f 2>/dev/null | cut -d/ -f2-4 | sort | uniq -c | sort -n | tail",
                            f.mount_point
                        )),
                    );
                }
            }
        }
        self.fs_trend.retain(|k, _| seen.contains(k));
    }
}

/// (seconds until full, bytes per second consumed) when free space has been
/// shrinking steadily for at least [`FS_TREND_MIN_SECS`].
fn fill_estimate(trend: &VecDeque<(i64, u64)>, avail_now: u64) -> Option<(f64, f64)> {
    let (t0, a0) = *trend.front()?;
    let (t1, a1) = *trend.back()?;
    if t1 - t0 < FS_TREND_MIN_SECS || a1 >= a0 {
        return None;
    }
    // Require a mostly monotonic decline, not a single large write.
    let steps = trend.len().saturating_sub(1);
    let declining = trend
        .iter()
        .zip(trend.iter().skip(1))
        .filter(|(a, b)| b.1 < a.1)
        .count();
    if steps < 5 || declining * 10 < steps * 6 {
        return None;
    }
    let rate = (a0 - a1) as f64 / (t1 - t0) as f64;
    (rate > 0.0).then(|| (avail_now as f64 / rate, rate))
}

struct Ctx<'a> {
    s: &'a Snapshot,
    w: &'a Window,
    now: i64,
    secs: i64,
}

impl Ctx<'_> {
    fn sustained(&self, f: impl Fn(&crate::metrics::Record) -> Option<bool>) -> bool {
        self.w.sustained(self.now, self.secs, f)
    }

    fn avg(&self, key: &str) -> Option<f64> {
        let v: Vec<f64> = self
            .w
            .since(self.now - self.secs)
            .filter_map(|r| r.get(key))
            .collect();
        window::stats(&v).map(|s| s.avg)
    }

    fn window_desc(&self) -> String {
        format!("over the last {}", fmt_duration(self.secs as f64))
    }

    fn ncpu(&self) -> f64 {
        self.s.host.ncpu.max(1) as f64
    }

    fn top_procs(&self, n: usize, key: impl Fn(&ProcInfo) -> Option<f64>) -> Vec<(&ProcInfo, f64)> {
        let Some(p) = &self.s.procs else {
            return Vec::new();
        };
        let mut v: Vec<(&ProcInfo, f64)> = p
            .list
            .iter()
            .filter_map(|p| Some((p, key(p)?)))
            .filter(|(_, v)| *v > 0.0)
            .collect();
        v.sort_by(|a, b| b.1.total_cmp(&a.1));
        v.truncate(n);
        v
    }

    fn psi_fact(&self, name: &str, p: Option<crate::metrics::Psi>) -> Option<String> {
        p.map(|p| {
            format!(
                "{name} pressure (PSI): tasks stalled {} of the time (avg10), {} (avg60).",
                fmt_pct(p.some_avg10),
                fmt_pct(p.some_avg60)
            )
        })
    }
}

fn list_procs(v: &[(&ProcInfo, f64)], fmt: impl Fn(f64) -> String) -> String {
    v.iter()
        .map(|(p, x)| format!("{} ({}) {}", p.comm, p.pid, fmt(*x)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn rule_cpu(c: &Ctx, out: &mut Vec<Finding>) {
    let ncpu = c.ncpu();
    let cpu_high = c.sustained(|r| r.cpu.map(|v| v >= CPU_BUSY_PCT));
    let load_high = c.sustained(|r| r.load1.map(|l| l >= LOAD_PER_CPU * ncpu));
    let load = c.s.load;

    if cpu_high {
        let mut f =
            Finding::new("cpu-saturated", Severity::Warning, "CPU is saturated").fact(format!(
                "CPU busy {} on average {} (threshold {}).",
                fmt_pct(c.avg("cpu").unwrap_or(0.0)),
                c.window_desc(),
                fmt_pct(CPU_BUSY_PCT)
            ));
        if let Some(l) = load {
            f = f.fact(format!(
                "Load average {:.2} / {:.2} / {:.2} on {} CPUs.",
                l.one, l.five, l.fifteen, ncpu
            ));
        }
        if let Some(p) = c.psi_fact("CPU", c.s.psi_cpu) {
            f = f.fact(p);
        }
        let top = c.top_procs(3, |p| p.cpu_pct);
        if !top.is_empty() {
            f = f.fact(format!(
                "Top CPU consumers now: {}.",
                list_procs(&top, |v| format!("{v:.0}%"))
            ));
        }
        out.push(
            f.cause("A legitimate CPU-heavy workload (builds, batch jobs, compression) – expected if planned.")
                .cause("A runaway process or busy loop.")
                .cause("Not enough CPU capacity for the regular load.")
                .check("ps -eo pid,user,comm,%cpu --sort=-%cpu | head")
                .check("pidstat -u 5 1   # per-process CPU over 5 s (sysstat)"),
        );
    } else if load_high {
        let iow = c.avg("iowait").unwrap_or(0.0);
        let blocked = c.s.cpu.as_ref().and_then(|x| x.procs_blocked).unwrap_or(0);
        let dstate = c.s.procs.as_ref().map_or(0, |p| p.uninterruptible);
        let mut f = Finding::new(
            "load-not-cpu",
            Severity::Warning,
            "High load average while CPUs are not saturated",
        );
        if let Some(l) = load {
            f = f.fact(format!(
                "Load average {:.2} (1 min) is above {:.1}× the {} CPUs.",
                l.one, LOAD_PER_CPU, ncpu
            ));
        }
        f = f
            .fact(format!(
                "CPU busy only {} on average, iowait {} {}.",
                fmt_pct(c.avg("cpu").unwrap_or(0.0)),
                fmt_pct(iow),
                c.window_desc()
            ))
            .fact(format!(
                "{blocked} task(s) currently blocked on I/O; {dstate} process(es) in uninterruptible sleep (D)."
            ));
        out.push(
            f.cause("On Linux, tasks waiting for disk or network storage (state D) count towards load even though they use no CPU.")
                .cause("A slow or hung storage device or NFS mount.")
                .check("ps -eo state,pid,user,comm | awk '$1==\"D\"'")
                .check("iostat -x 1 5")
                .check("cat /proc/<pid>/stack   # as root, shows where a D-state task waits"),
        );
    }
}

fn rule_steal(c: &Ctx, out: &mut Vec<Finding>) {
    if c.sustained(|r| r.steal.map(|v| v >= STEAL_PCT)) {
        out.push(
            Finding::new("cpu-steal", Severity::Warning, "High CPU steal time (virtual machine)")
                .fact(format!(
                    "Steal {} on average {}: the hypervisor did not schedule this VM although it was runnable.",
                    fmt_pct(c.avg("steal").unwrap_or(0.0)),
                    c.window_desc()
                ))
                .cause("The host is overcommitted or neighbouring VMs are busy.")
                .cause("CPU credits of a burstable cloud instance are exhausted.")
                .check("vmstat 1 5   # 'st' column")
                .check("Check CPU credit / host metrics in your provider's console"),
        );
    }
}

fn rule_io(c: &Ctx, out: &mut Vec<Finding>) {
    let iowait = c.sustained(|r| r.iowait.map(|v| v >= IOWAIT_PCT));
    let util = c.sustained(|r| r.disk_util_max.map(|v| v >= DISK_UTIL_PCT));
    let psi = c.sustained(|r| r.psi_io.map(|v| v >= PSI_IO_PCT));
    if !(iowait || util || psi) {
        return;
    }
    let title = if iowait || psi {
        "Processes are waiting on disk I/O"
    } else {
        "A disk is busy nearly all the time"
    };
    let mut f = Finding::new("io-bottleneck", Severity::Warning, title).fact(format!(
        "CPU iowait {} on average {}.",
        fmt_pct(c.avg("iowait").unwrap_or(0.0)),
        c.window_desc()
    ));
    if let Some(d) = c.s.busiest_disk() {
        f = f.fact(format!(
            "Busiest device {}: {} utilised, read {} ({:.0} IOPS), write {} ({:.0} IOPS), await {}.",
            d.label,
            fmt_pct(d.util_pct),
            fmt_rate(d.read_bps),
            d.read_iops,
            fmt_rate(d.write_bps),
            d.write_iops,
            d.await_ms.map_or("n/a".into(), |a| format!("{a:.1} ms"))
        ));
    }
    if let Some(p) = c.psi_fact("I/O", c.s.psi_io) {
        f = f.fact(p);
    }
    if let Some(p) = &c.s.procs
        && p.io_collected
    {
        let top = c.top_procs(3, |p| Some(p.read_bps? + p.write_bps?));
        if !top.is_empty() {
            f = f.fact(format!(
                "Top I/O processes now: {}.",
                list_procs(&top, fmt_rate)
            ));
        }
    }
    let swapping = c.avg("swap_in").unwrap_or(0.0) + c.avg("swap_out").unwrap_or(0.0);
    if swapping >= SWAP_PAGES_PER_S {
        f = f.fact(format!(
            "The system is also swapping ({swapping:.0} pages/s)."
        ));
    }
    out.push(
        f.cause("The storage device is at its throughput or IOPS limit.")
            .cause("Swapping caused by memory shortage (see memory findings).")
            .cause("A slow or failing disk: high await at low throughput points this way.")
            .cause("Note: SSD, NVMe and RAID devices serve requests in parallel, so 100 % utilisation alone does not prove saturation; compare await.")
            .check("iostat -x 1 5   # await, aqu-sz, %util per device")
            .check("pidstat -d 1 5   # per-process I/O (sysstat)")
            .check("dmesg -T | grep -iE 'i/o error|reset|timeout'")
            .check("smartctl -a /dev/<device>   # as root, disk health"),
    );
}

fn rule_memory(c: &Ctx, out: &mut Vec<Finding>) {
    let Some(m) = &c.s.mem else { return };
    let low = |thr: f64| {
        c.sustained(|r| {
            let (a, t) = (r.mem_avail?, r.mem_total?);
            Some(t > 0.0 && a / t * 100.0 < thr)
        })
    };
    let swapping = c.sustained(|r| Some(r.swap_in? + r.swap_out? >= SWAP_PAGES_PER_S));
    let psi_mem = c.sustained(|r| r.psi_mem.map(|v| v >= PSI_MEM_PCT));
    let crit = low(MEM_AVAIL_CRIT_PCT);
    let warn = crit || low(MEM_AVAIL_WARN_PCT);

    let avail = m.info.available;
    let mem_fact = format!(
        "Available {} of {} ({}); swap used {} of {}.",
        avail.map_or("n/a".into(), |a| fmt_bytes(a as f64)),
        fmt_bytes(m.info.total as f64),
        avail.map_or("n/a".into(), |a| fmt_pct(
            a as f64 / m.info.total.max(1) as f64 * 100.0
        )),
        fmt_bytes(m.info.swap_used() as f64),
        fmt_bytes(m.info.swap_total as f64)
    );
    let swap_fact = format!(
        "Swap-in {:.0} pages/s, swap-out {:.0} pages/s, major faults {:.0}/s on average {}.",
        c.avg("swap_in").unwrap_or(0.0),
        c.avg("swap_out").unwrap_or(0.0),
        c.avg("major_faults").unwrap_or(0.0),
        c.window_desc()
    );
    let top_rss = c.top_procs(3, |p| Some(p.rss as f64));

    if warn {
        let sev = if crit || swapping {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let title = if swapping {
            "Memory is exhausted and the system is swapping"
        } else {
            "Available memory is low"
        };
        let mut f = Finding::new("mem-low", sev, title)
            .fact(mem_fact)
            .fact(swap_fact)
            .fact("Tirnix uses MemAvailable, which already counts reclaimable page cache; low MemFree alone would be normal.");
        if let Some(p) = c.psi_fact("Memory", c.s.psi_mem) {
            f = f.fact(p);
        }
        if m.info.shmem > m.info.total / 5 {
            f = f.fact(format!(
                "Shared memory / tmpfs holds {} of RAM.",
                fmt_bytes(m.info.shmem as f64)
            ));
        }
        if !top_rss.is_empty() {
            f = f.fact(format!(
                "Largest processes (RSS): {}.",
                list_procs(&top_rss, fmt_bytes)
            ));
        }
        out.push(
            f.cause("The workload needs more memory than the machine has.")
                .cause("A memory leak in a long-running process (its RSS keeps growing).")
                .cause("Large tmpfs contents or kernel memory (slab) use.")
                .check("free -h")
                .check("ps -eo pid,user,comm,rss --sort=-rss | head")
                .check("grep -E 'Slab|SUnreclaim|Shmem' /proc/meminfo")
                .check("slabtop -o | head -20   # as root"),
        );
    } else if swapping {
        out.push(
            Finding::new("swap-active", Severity::Warning, "Sustained swap activity")
                .fact(swap_fact)
                .fact(mem_fact)
                .cause("Some memory regions were pushed to swap and are needed again (pressure in a cgroup or earlier shortage).")
                .cause("vm.swappiness favours swapping over dropping page cache.")
                .check("vmstat 1 5   # 'si'/'so' columns")
                .check("for f in /proc/[0-9]*/status; do awk '/^Name|^VmSwap/' $f; done 2>/dev/null | paste - - | sort -k4 -n | tail")
                .check("sysctl vm.swappiness"),
        );
    } else if psi_mem {
        let mut f = Finding::new(
            "mem-pressure",
            Severity::Warning,
            "Tasks are stalling on memory although RAM is available",
        )
        .fact(format!(
            "Memory PSI above {} {}.",
            fmt_pct(PSI_MEM_PCT),
            c.window_desc()
        ))
        .fact(mem_fact);
        if let Some(p) = c.psi_fact("Memory", c.s.psi_mem) {
            f = f.fact(p);
        }
        out.push(
            f.cause("A cgroup memory limit (container or systemd unit) forces reclaim inside that group.")
                .cause("Heavy page-cache reclaim or memory compaction.")
                .check("systemd-cgtop -m")
                .check("cat /sys/fs/cgroup/<group>/memory.pressure /sys/fs/cgroup/<group>/memory.events"),
        );
    } else if m.info.swap_total > 0 && m.info.swap_used() > m.info.swap_total / 4 {
        let idle = c.sustained(|r| Some(r.swap_in? + r.swap_out? < 1.0));
        if idle {
            out.push(
                Finding::new("swap-idle", Severity::Info, "Swap is in use but idle")
                    .fact(format!(
                        "{} of {} swap used, but there is no swap traffic {}.",
                        fmt_bytes(m.info.swap_used() as f64),
                        fmt_bytes(m.info.swap_total as f64),
                        c.window_desc()
                    ))
                    .cause("Rarely used memory was moved to swap earlier. This is usually harmless and frees RAM for cache.")
                    .check("vmstat 1 5   # confirm 'si'/'so' stay at 0"),
            );
        }
    }
}

fn rule_network(c: &Ctx, out: &mut Vec<Finding>) {
    if c.sustained(|r| r.net_errors.map(|v| v > 0.0)) {
        let ifaces: Vec<String> =
            c.s.nets
                .iter()
                .filter(|n| n.rx_errs_per_s + n.tx_errs_per_s > 0.0)
                .map(|n| {
                    format!(
                        "{} (rx {:.1}/s, tx {:.1}/s)",
                        n.name, n.rx_errs_per_s, n.tx_errs_per_s
                    )
                })
                .collect();
        let mut f = Finding::new("net-errors", Severity::Warning, "Network interface errors").fact(
            format!(
                "Interface errors on most samples {} ({:.2}/s on average).",
                c.window_desc(),
                c.avg("net_errors").unwrap_or(0.0)
            ),
        );
        if !ifaces.is_empty() {
            f = f.fact(format!("Currently: {}.", ifaces.join(", ")));
        }
        out.push(
            f.cause("Faulty cable, connector or switch port (CRC/frame errors).")
                .cause("Duplex or speed mismatch with the switch.")
                .cause("NIC driver or firmware problem.")
                .check("ip -s link show <iface>")
                .check("ethtool -S <iface> | grep -iE 'err|crc|fifo'")
                .check("ethtool <iface>   # speed / duplex"),
        );
    }
    if c.sustained(|r| r.net_drops.map(|v| v >= 1.0)) {
        let ifaces: Vec<String> =
            c.s.nets
                .iter()
                .filter(|n| n.rx_drop_per_s + n.tx_drop_per_s > 0.0)
                .map(|n| {
                    let pkts = n.rx_pps + n.tx_pps;
                    let drops = n.rx_drop_per_s + n.tx_drop_per_s;
                    let share = if pkts > 0.0 {
                        format!(", {} of packets", fmt_pct(drops / (pkts + drops) * 100.0))
                    } else {
                        String::new()
                    };
                    format!("{} ({drops:.1}/s{share})", n.name)
                })
                .collect();
        let mut f =
            Finding::new("net-drops", Severity::Info, "Packets are being dropped").fact(format!(
                "{:.1} dropped packets/s on average {}.",
                c.avg("net_drops").unwrap_or(0.0),
                c.window_desc()
            ));
        if !ifaces.is_empty() {
            f = f.fact(format!("Currently: {}.", ifaces.join(", ")));
        }
        out.push(
            f.cause(
                "Frames for protocols or VLANs this host does not handle – common and harmless.",
            )
            .cause("Receive ring buffer overflow during traffic bursts.")
            .cause("Traffic-control (qdisc) drops on transmit when the link is full.")
            .check("ip -s -s link show <iface>")
            .check("ethtool -g <iface>   # ring buffer sizes")
            .check("tc -s qdisc show dev <iface>"),
        );
    }
}

fn rule_tcp(c: &Ctx, out: &mut Vec<Finding>) {
    let Some(t) = &c.s.tcp else { return };
    if c.sustained(|r| {
        Some(r.tcp_retrans_pct? >= RETRANS_PCT && r.tcp_retrans? >= RETRANS_MIN_PER_S)
    }) {
        out.push(
            Finding::new(
                "tcp-retrans",
                Severity::Warning,
                "High TCP retransmission rate",
            )
            .fact(format!(
                "{} of sent segments were retransmissions on average {} ({:.0}/s).",
                fmt_pct(c.avg("tcp_retrans_pct").unwrap_or(0.0)),
                c.window_desc(),
                c.avg("tcp_retrans").unwrap_or(0.0)
            ))
            .fact(format!("{} established connections.", t.established))
            .cause("Packet loss on the path: congestion, a faulty link, Wi-Fi interference.")
            .cause("Overloaded or slow peers that do not acknowledge in time.")
            .cause("A single bulk transfer over a lossy long-distance link.")
            .check("ss -ti state established | grep -B1 retrans   # which connections")
            .check("nstat -az TcpRetransSegs TcpExtTCPTimeouts TcpExtTCPLostRetransmit")
            .check("mtr -rwc 50 <peer>   # active test: sends traffic"),
        );
    }
    let drops =
        c.w.since(c.now - c.secs)
            .filter(|r| r.tcp_listen_drops.is_some_and(|v| v > 0.0))
            .count();
    if drops >= 2 {
        out.push(
            Finding::new("tcp-listen-drops", Severity::Warning, "Incoming TCP connections are being dropped")
                .fact(format!(
                    "Listen queue drops in {drops} samples {}; now {:.1}/s.",
                    c.window_desc(),
                    t.listen_drops_per_s.unwrap_or(0.0)
                ))
                .cause("A server application accepts connections slower than they arrive (accept queue full).")
                .cause("The listen backlog is too small for bursts (net.core.somaxconn, application backlog).")
                .cause("A SYN flood.")
                .check("ss -ltn   # Recv-Q close to Send-Q means the queue is full")
                .check("nstat -az TcpExtListenOverflows TcpExtListenDrops")
                .check("sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog"),
        );
    }
    if let Some(tw) = t.sockets.tcp_tw
        && tw as f64 >= TIME_WAIT_HIGH
    {
        out.push(
                Finding::new("tcp-time-wait", Severity::Info, "Many sockets in TIME_WAIT")
                    .fact(format!("{tw} TCP sockets in TIME_WAIT."))
                    .cause("Many short-lived outgoing connections (no connection pooling / keep-alive).")
                    .cause("This only matters if local ports run out for connections to the same destination.")
                    .check("ss -s")
                    .check("ss -tan state time-wait | awk '{print $4}' | sort | uniq -c | sort -n | tail")
                    .check("sysctl net.ipv4.ip_local_port_range"),
            );
    }
}

fn rule_processes(c: &Ctx, out: &mut Vec<Finding>) {
    let Some(p) = &c.s.procs else { return };
    if c.sustained(|r| r.procs_blocked.map(|v| v >= 2.0)) && p.uninterruptible > 0 {
        let names: Vec<String> = p
            .list
            .iter()
            .filter(|x| x.state == 'D')
            .take(5)
            .map(|x| format!("{} ({})", x.comm, x.pid))
            .collect();
        out.push(
            Finding::new(
                "tasks-blocked",
                Severity::Info,
                "Tasks are persistently blocked on I/O",
            )
            .fact(format!(
                "At least 2 tasks blocked on I/O on most samples {}; now {} in state D: {}.",
                c.window_desc(),
                p.uninterruptible,
                names.join(", ")
            ))
            .cause("Slow storage, or a hung NFS / network filesystem.")
            .cause("Heavy synchronous writes (fsync) by databases or backups.")
            .check("ps -eo state,pid,user,wchan:32,comm | awk '$1==\"D\"'")
            .check("cat /proc/<pid>/stack   # as root"),
        );
    }
    if p.zombies >= ZOMBIES_HIGH {
        let mut parents: HashMap<u32, usize> = HashMap::new();
        for z in p.list.iter().filter(|x| x.state == 'Z') {
            *parents.entry(z.ppid).or_default() += 1;
        }
        let mut pv: Vec<(u32, usize)> = parents.into_iter().collect();
        pv.sort_by_key(|a| std::cmp::Reverse(a.1));
        let desc: Vec<String> = pv
            .iter()
            .take(3)
            .map(|(pid, n)| {
                let name = p
                    .list
                    .iter()
                    .find(|x| x.pid == *pid)
                    .map_or("?", |x| x.comm.as_str());
                format!("{name} ({pid}): {n}")
            })
            .collect();
        out.push(
            Finding::new("zombies", Severity::Info, "Many zombie processes")
                .fact(format!(
                    "{} zombie processes. Parents with most zombies: {}.",
                    p.zombies,
                    desc.join(", ")
                ))
                .cause("The parent process does not reap exited children (a bug in it). Zombies use no CPU or memory, only PIDs.")
                .check("ps -eo ppid,pid,stat,comm | awk '$3 ~ /^Z/'")
                .check("Restarting the parent process clears its zombies"),
        );
    }
}

fn rule_file_handles(c: &Ctx, out: &mut Vec<Finding>) {
    let Some((alloc, max)) = c.s.file_handles else {
        return;
    };
    let Some(pct) = crate::util::pct(alloc as f64, max as f64) else {
        return;
    };
    let sev = if pct >= FD_CRIT_PCT {
        Severity::Critical
    } else if pct >= FD_WARN_PCT {
        Severity::Warning
    } else {
        return;
    };
    out.push(
        Finding::new("file-handles", sev, "System-wide file handle limit nearly reached")
            .fact(format!("{alloc} of {max} file handles allocated ({}).", fmt_pct(pct)))
            .cause("A process leaks file descriptors or sockets.")
            .cause("fs.file-max is low for this workload.")
            .check("cat /proc/sys/fs/file-nr")
            .check("for p in /proc/[0-9]*; do echo \"$(ls $p/fd 2>/dev/null | wc -l) $(cat $p/comm 2>/dev/null)\"; done | sort -n | tail"),
    );
}

/// False when none of the core sources could be read (e.g. no `/proc`),
/// in which case "no findings" must not be presented as "all clear".
pub fn has_data(s: &Snapshot) -> bool {
    s.cpu.is_some() || s.mem.is_some() || s.disks_available || s.nets_available
}

/// Which data sources were available for the rules.
pub fn coverage(s: &Snapshot) -> Vec<(&'static str, bool, String)> {
    let mut v = vec![
        ("CPU (/proc/stat)", s.cpu.is_some(), String::new()),
        (
            "Memory (/proc/meminfo, /proc/vmstat)",
            s.mem.is_some(),
            String::new(),
        ),
        (
            "OOM kill counter",
            s.mem.as_ref().is_some_and(|m| m.oom_kills.is_some()),
            "needs Linux 4.13+".into(),
        ),
        (
            "Pressure stall info (PSI)",
            s.psi_cpu.is_some() || s.psi_mem.is_some() || s.psi_io.is_some(),
            "needs Linux 4.20+ with CONFIG_PSI (psi=1 on some distros)".into(),
        ),
        ("Disks (/proc/diskstats)", s.disks_available, String::new()),
        ("Filesystems (statvfs)", s.fs_available, String::new()),
        ("Network (/proc/net/dev)", s.nets_available, String::new()),
        ("TCP (/proc/net/snmp)", s.tcp.is_some(), String::new()),
        ("Processes (/proc/<pid>)", s.procs.is_some(), String::new()),
    ];
    if let Some(p) = &s.procs
        && p.io_collected
    {
        let note = if p.io_denied > 0 {
            format!(
                "{} of {} processes not readable without root",
                p.io_denied, p.total
            )
        } else {
            String::new()
        };
        v.push(("Per-process I/O", p.io_denied < p.total, note));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::*;

    fn snapshot(now: i64) -> Snapshot {
        Snapshot {
            time: now as f64,
            interval: Some(2.0),
            host: HostInfo {
                ncpu: 4,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn window_with(now: i64, secs: i64, f: impl Fn(&mut Record)) -> Window {
        let mut w = Window::new(1000);
        let mut t = now - secs;
        while t <= now {
            let mut r = Record {
                t,
                ..Default::default()
            };
            f(&mut r);
            w.push(r);
            t += 2;
        }
        w
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }

    #[test]
    fn quiet_system_has_no_findings() {
        let now = 10_000;
        let w = window_with(now, 60, |r| {
            r.cpu = Some(10.0);
            r.iowait = Some(0.5);
            r.load1 = Some(0.5);
            r.mem_avail = Some(8e9);
            r.mem_total = Some(16e9);
            r.swap_in = Some(0.0);
            r.swap_out = Some(0.0);
            r.net_errors = Some(0.0);
            r.net_drops = Some(0.0);
        });
        let mut e = Engine::new(30);
        assert!(e.evaluate(&snapshot(now), &w).is_empty());
    }

    #[test]
    fn sustained_cpu_is_reported_spike_is_not() {
        let now = 10_000;
        let mut e = Engine::new(30);
        let w = window_with(now, 60, |r| r.cpu = Some(97.0));
        let f = e.evaluate(&snapshot(now), &w);
        assert_eq!(ids(&f), vec!["cpu-saturated"]);
        assert!(!f[0].facts.is_empty() && !f[0].causes.is_empty() && !f[0].checks.is_empty());

        let w = window_with(now, 60, |r| {
            r.cpu = Some(if r.t == now { 100.0 } else { 20.0 })
        });
        assert!(e.evaluate(&snapshot(now), &w).is_empty());
    }

    #[test]
    fn high_load_with_idle_cpu_points_to_io() {
        let now = 10_000;
        let w = window_with(now, 60, |r| {
            r.cpu = Some(15.0);
            r.load1 = Some(12.0);
            r.iowait = Some(5.0);
        });
        let mut s = snapshot(now);
        s.load = Some(LoadAvg {
            one: 12.0,
            ..Default::default()
        });
        let f = Engine::new(30).evaluate(&s, &w);
        assert_eq!(ids(&f), vec!["load-not-cpu"]);
    }

    #[test]
    fn low_memory_with_swapping_is_critical() {
        let now = 10_000;
        let w = window_with(now, 60, |r| {
            r.mem_avail = Some(0.8e9);
            r.mem_total = Some(16e9);
            r.swap_in = Some(400.0);
            r.swap_out = Some(900.0);
        });
        let mut s = snapshot(now);
        s.mem = Some(MemStats {
            info: MemInfo {
                total: 16_000_000_000,
                available: Some(800_000_000),
                ..Default::default()
            },
            ..Default::default()
        });
        let f = Engine::new(30).evaluate(&s, &w);
        assert_eq!(ids(&f), vec!["mem-low"]);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn oom_kill_after_start_is_critical() {
        let now = 10_000;
        let w = window_with(now, 10, |_| {});
        let mut e = Engine::new(30);
        let mut s = snapshot(now);
        s.mem = Some(MemStats {
            info: MemInfo {
                total: 1,
                available: Some(1),
                ..Default::default()
            },
            oom_kills: Some(3),
            ..Default::default()
        });
        assert_eq!(ids(&e.evaluate(&s, &w)), vec!["oom-boot"]);
        s.mem.as_mut().unwrap().oom_kills = Some(4);
        let f = e.evaluate(&s, &w);
        assert_eq!(ids(&f), vec!["oom-new"]);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn filesystem_thresholds() {
        let now = 10_000;
        let w = window_with(now, 10, |_| {});
        let mut s = snapshot(now);
        let fs = |m: &str, used: u64, avail: u64, ro: bool| FsStats {
            mount_point: m.into(),
            total: used + avail,
            used,
            avail,
            readonly: ro,
            inodes_total: 100,
            inodes_free: 50,
            ..Default::default()
        };
        s.fs_available = true;
        s.filesystems = vec![
            fs("/", 50, 50, false),
            fs("/var", 92, 8, false),
            fs("/data", 97, 3, false),
            fs("/ro", 100, 0, true),
        ];
        let f = Engine::new(30).evaluate(&s, &w);
        assert_eq!(ids(&f), vec!["fs-space:/data", "fs-space:/var"]);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[1].severity, Severity::Warning);
    }

    #[test]
    fn inode_exhaustion() {
        let now = 10_000;
        let w = window_with(now, 10, |_| {});
        let mut s = snapshot(now);
        s.filesystems = vec![FsStats {
            mount_point: "/srv".into(),
            total: 100,
            used: 10,
            avail: 90,
            inodes_total: 1000,
            inodes_free: 20,
            ..Default::default()
        }];
        let f = Engine::new(30).evaluate(&s, &w);
        assert_eq!(ids(&f), vec!["fs-inodes:/srv"]);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn steady_fill_rate_is_estimated() {
        let mut trend = VecDeque::new();
        for i in 0..=20 {
            trend.push_back((i * 60, 10_000_000 - i as u64 * 10_000));
        }
        let (secs, rate) = fill_estimate(&trend, 9_800_000).unwrap();
        assert!((rate - 10_000.0 / 60.0).abs() < 1e-6);
        assert!((secs - 9_800_000.0 / rate).abs() < 1.0);
        // Too short a history: no estimate.
        let short: VecDeque<_> = trend.iter().take(5).copied().collect();
        assert!(fill_estimate(&short, 0).is_none());
        // One big drop followed by stable usage is not a trend.
        let mut jump = VecDeque::new();
        for i in 0..=20 {
            jump.push_back((i * 60, if i < 3 { 10_000_000 } else { 5_000_000 }));
        }
        assert!(fill_estimate(&jump, 5_000_000).is_none());
    }

    #[test]
    fn retransmissions_need_volume() {
        let now = 10_000;
        let mut s = snapshot(now);
        s.tcp = Some(TcpStats::default());
        // High ratio but tiny volume: not reported.
        let w = window_with(now, 60, |r| {
            r.tcp_retrans_pct = Some(20.0);
            r.tcp_retrans = Some(0.5);
        });
        assert!(Engine::new(30).evaluate(&s, &w).is_empty());
        let w = window_with(now, 60, |r| {
            r.tcp_retrans_pct = Some(5.0);
            r.tcp_retrans = Some(50.0);
        });
        assert_eq!(ids(&Engine::new(30).evaluate(&s, &w)), vec!["tcp-retrans"]);
    }

    #[test]
    fn idle_swap_is_informational() {
        let now = 10_000;
        let w = window_with(now, 60, |r| {
            r.mem_avail = Some(8e9);
            r.mem_total = Some(16e9);
            r.swap_in = Some(0.0);
            r.swap_out = Some(0.0);
        });
        let mut s = snapshot(now);
        s.mem = Some(MemStats {
            info: MemInfo {
                total: 16_000_000_000,
                available: Some(8_000_000_000),
                swap_total: 4_000_000_000,
                swap_free: 1_000_000_000,
                ..Default::default()
            },
            ..Default::default()
        });
        let f = Engine::new(30).evaluate(&s, &w);
        assert_eq!(ids(&f), vec!["swap-idle"]);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn huge_file_max_is_not_an_issue() {
        let now = 10_000;
        let w = window_with(now, 10, |_| {});
        let mut s = snapshot(now);
        s.file_handles = Some((5000, 9_223_372_036_854_775_807));
        assert!(Engine::new(30).evaluate(&s, &w).is_empty());
        s.file_handles = Some((990, 1000));
        let f = Engine::new(30).evaluate(&s, &w);
        assert_eq!(f[0].severity, Severity::Critical);
    }
}
