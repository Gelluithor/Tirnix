//! Parsers for `/proc` text formats.
//!
//! Every function here is pure (`&str` in, plain data out) so it can be
//! tested against captured kernel output. Missing or malformed fields yield
//! `None` instead of a made-up value.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// /proc/stat
// ---------------------------------------------------------------------------

/// Cumulative CPU time in clock ticks, one line of `/proc/stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    /// Total time. `guest` and `guest_nice` are already included in `user`
    /// and `nice` by the kernel, so they are not added again.
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }
}

#[derive(Debug, Clone, Default)]
pub struct StatRaw {
    pub cpu: CpuTimes,
    pub per_cpu: Vec<CpuTimes>,
    pub ctxt: Option<u64>,
    pub forks: Option<u64>,
    pub procs_running: Option<u64>,
    pub procs_blocked: Option<u64>,
}

fn parse_cpu_line(rest: &str) -> Option<CpuTimes> {
    let mut it = rest.split_ascii_whitespace().map(|v| v.parse::<u64>());
    let mut next = || it.next().and_then(Result::ok);
    Some(CpuTimes {
        user: next()?,
        nice: next()?,
        system: next()?,
        idle: next()?,
        // Older kernels may lack the trailing columns.
        iowait: next().unwrap_or(0),
        irq: next().unwrap_or(0),
        softirq: next().unwrap_or(0),
        steal: next().unwrap_or(0),
    })
}

pub fn parse_stat(text: &str) -> Option<StatRaw> {
    let mut out = StatRaw::default();
    let mut have_total = false;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "cpu" => {
                out.cpu = parse_cpu_line(rest)?;
                have_total = true;
            }
            k if k.starts_with("cpu") => {
                if let Some(t) = parse_cpu_line(rest) {
                    out.per_cpu.push(t);
                }
            }
            "ctxt" => out.ctxt = rest.trim().parse().ok(),
            "processes" => out.forks = rest.trim().parse().ok(),
            "procs_running" => out.procs_running = rest.trim().parse().ok(),
            "procs_blocked" => out.procs_blocked = rest.trim().parse().ok(),
            _ => {}
        }
    }
    have_total.then_some(out)
}

// ---------------------------------------------------------------------------
// /proc/loadavg
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
    pub runnable: u64,
    pub total_tasks: u64,
}

pub fn parse_loadavg(text: &str) -> Option<LoadAvg> {
    let mut it = text.split_ascii_whitespace();
    let one = it.next()?.parse().ok()?;
    let five = it.next()?.parse().ok()?;
    let fifteen = it.next()?.parse().ok()?;
    let (r, t) = it.next()?.split_once('/')?;
    Some(LoadAvg {
        one,
        five,
        fifteen,
        runnable: r.parse().ok()?,
        total_tasks: t.parse().ok()?,
    })
}

// ---------------------------------------------------------------------------
// /proc/meminfo
// ---------------------------------------------------------------------------

/// Memory figures in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total: u64,
    pub free: u64,
    /// `MemAvailable` exists since Linux 3.14; it is the kernel's own estimate
    /// of memory available for new workloads without swapping.
    pub available: Option<u64>,
    pub buffers: u64,
    pub cached: u64,
    pub sreclaimable: u64,
    pub shmem: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub swap_cached: u64,
}

impl MemInfo {
    /// Memory in use by applications and the kernel, i.e. not available.
    /// Falls back to `total - free - buffers - cache` on ancient kernels.
    pub fn used(&self) -> u64 {
        match self.available {
            Some(a) => self.total.saturating_sub(a),
            None => self
                .total
                .saturating_sub(self.free + self.buffers + self.cached + self.sreclaimable),
        }
    }

    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let mut have_total = false;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut parts = rest.split_ascii_whitespace();
        let Some(Ok(v)) = parts.next().map(str::parse::<u64>) else {
            continue;
        };
        let v = if parts.next() == Some("kB") {
            v * 1024
        } else {
            v
        };
        match key {
            "MemTotal" => {
                m.total = v;
                have_total = true;
            }
            "MemFree" => m.free = v,
            "MemAvailable" => m.available = Some(v),
            "Buffers" => m.buffers = v,
            "Cached" => m.cached = v,
            "SReclaimable" => m.sreclaimable = v,
            "Shmem" => m.shmem = v,
            "Dirty" => m.dirty = v,
            "Writeback" => m.writeback = v,
            "SwapTotal" => m.swap_total = v,
            "SwapFree" => m.swap_free = v,
            "SwapCached" => m.swap_cached = v,
            _ => {}
        }
    }
    have_total.then_some(m)
}

// ---------------------------------------------------------------------------
// /proc/vmstat
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VmStatRaw {
    pub pswpin: Option<u64>,
    pub pswpout: Option<u64>,
    pub pgmajfault: Option<u64>,
    /// Present since Linux 4.13.
    pub oom_kill: Option<u64>,
}

pub fn parse_vmstat(text: &str) -> VmStatRaw {
    let mut v = VmStatRaw::default();
    for line in text.lines() {
        let Some((key, val)) = line.split_once(' ') else {
            continue;
        };
        let slot = match key {
            "pswpin" => &mut v.pswpin,
            "pswpout" => &mut v.pswpout,
            "pgmajfault" => &mut v.pgmajfault,
            "oom_kill" => &mut v.oom_kill,
            _ => continue,
        };
        *slot = val.trim().parse().ok();
    }
    v
}

// ---------------------------------------------------------------------------
// /proc/pressure/{cpu,memory,io}  (PSI, Linux 4.20+, CONFIG_PSI)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Psi {
    /// Share of wall time in which at least one task was stalled (%).
    pub some_avg10: f64,
    pub some_avg60: f64,
    /// Share of wall time in which all non-idle tasks were stalled (%).
    /// Not reported for CPU on older kernels.
    pub full_avg10: Option<f64>,
}

pub fn parse_psi(text: &str) -> Option<Psi> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut parts = line.split_ascii_whitespace();
        let kind = parts.next()?;
        let mut avg10 = None;
        let mut avg60 = None;
        for p in parts {
            if let Some(v) = p.strip_prefix("avg10=") {
                avg10 = v.parse::<f64>().ok();
            } else if let Some(v) = p.strip_prefix("avg60=") {
                avg60 = v.parse::<f64>().ok();
            }
        }
        match kind {
            "some" => some = Some((avg10?, avg60?)),
            "full" => full = avg10,
            _ => {}
        }
    }
    let (some_avg10, some_avg60) = some?;
    Some(Psi {
        some_avg10,
        some_avg60,
        full_avg10: full,
    })
}

// ---------------------------------------------------------------------------
// /proc/diskstats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiskRaw {
    pub name: String,
    pub reads: u64,
    pub read_sectors: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub write_sectors: u64,
    pub write_ms: u64,
    /// Milliseconds during which the device had I/O in flight.
    pub io_ms: u64,
}

/// Parse `/proc/diskstats`, keeping only devices accepted by `keep`.
/// Sector counts in this file are always in 512-byte units.
pub fn parse_diskstats(text: &str, mut keep: impl FnMut(&str) -> bool) -> Vec<DiskRaw> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_ascii_whitespace().collect();
        if f.len() < 14 || !keep(f[2]) {
            continue;
        }
        let n = |i: usize| f[i].parse::<u64>().unwrap_or(0);
        out.push(DiskRaw {
            name: f[2].to_string(),
            reads: n(3),
            read_sectors: n(5),
            read_ms: n(6),
            writes: n(7),
            write_sectors: n(9),
            write_ms: n(10),
            io_ms: n(12),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// /proc/net/dev
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetRaw {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
}

pub fn parse_net_dev(text: &str) -> Vec<NetRaw> {
    let mut out = Vec::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let f: Vec<u64> = rest
            .split_ascii_whitespace()
            .map(|v| v.parse().unwrap_or(0))
            .collect();
        if f.len() < 16 {
            continue;
        }
        out.push(NetRaw {
            name: name.trim().to_string(),
            rx_bytes: f[0],
            rx_packets: f[1],
            rx_errs: f[2],
            rx_drop: f[3],
            tx_bytes: f[8],
            tx_packets: f[9],
            tx_errs: f[10],
            tx_drop: f[11],
        });
    }
    out
}

// ---------------------------------------------------------------------------
// /proc/net/snmp, /proc/net/netstat, /proc/net/sockstat
// ---------------------------------------------------------------------------

/// Parse the "header line / value line" pairs used by `/proc/net/snmp` and
/// `/proc/net/netstat` into `section -> field -> value`.
pub fn parse_snmp_table(text: &str) -> HashMap<String, HashMap<String, i64>> {
    let mut out: HashMap<String, HashMap<String, i64>> = HashMap::new();
    let mut lines = text.lines();
    while let (Some(h), Some(v)) = (lines.next(), lines.next()) {
        let (Some((hs, hf)), Some((vs, vf))) = (h.split_once(':'), v.split_once(':')) else {
            continue;
        };
        if hs != vs {
            continue;
        }
        let map = out.entry(hs.to_string()).or_default();
        for (k, val) in hf.split_ascii_whitespace().zip(vf.split_ascii_whitespace()) {
            if let Ok(n) = val.parse::<i64>() {
                map.insert(k.to_string(), n);
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpRaw {
    pub active_opens: u64,
    pub passive_opens: u64,
    pub attempt_fails: u64,
    pub estab_resets: u64,
    pub curr_estab: u64,
    pub in_segs: u64,
    pub out_segs: u64,
    pub retrans_segs: u64,
    pub in_errs: u64,
    pub out_rsts: u64,
    pub listen_overflows: Option<u64>,
    pub listen_drops: Option<u64>,
}

pub fn parse_tcp(snmp: &str, netstat: Option<&str>) -> Option<TcpRaw> {
    let t = parse_snmp_table(snmp);
    let tcp = t.get("Tcp")?;
    let g = |k: &str| tcp.get(k).map(|v| (*v).max(0) as u64);
    let mut out = TcpRaw {
        active_opens: g("ActiveOpens")?,
        passive_opens: g("PassiveOpens")?,
        attempt_fails: g("AttemptFails").unwrap_or(0),
        estab_resets: g("EstabResets").unwrap_or(0),
        curr_estab: g("CurrEstab")?,
        in_segs: g("InSegs")?,
        out_segs: g("OutSegs")?,
        retrans_segs: g("RetransSegs")?,
        in_errs: g("InErrs").unwrap_or(0),
        out_rsts: g("OutRsts").unwrap_or(0),
        listen_overflows: None,
        listen_drops: None,
    };
    if let Some(ns) = netstat {
        let n = parse_snmp_table(ns);
        if let Some(ext) = n.get("TcpExt") {
            out.listen_overflows = ext.get("ListenOverflows").map(|v| (*v).max(0) as u64);
            out.listen_drops = ext.get("ListenDrops").map(|v| (*v).max(0) as u64);
        }
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SockStat {
    pub sockets_used: Option<u64>,
    pub tcp_inuse: Option<u64>,
    pub tcp_orphan: Option<u64>,
    pub tcp_tw: Option<u64>,
    pub tcp_alloc: Option<u64>,
    pub udp_inuse: Option<u64>,
}

/// Parse `/proc/net/sockstat`, optionally adding IPv6 counts from
/// `/proc/net/sockstat6` (which only reports `inuse`).
pub fn parse_sockstat(v4: &str, v6: Option<&str>) -> SockStat {
    fn field(rest: &str, name: &str) -> Option<u64> {
        let mut it = rest.split_ascii_whitespace();
        while let Some(k) = it.next() {
            let v = it.next()?;
            if k == name {
                return v.parse().ok();
            }
        }
        None
    }
    let mut s = SockStat::default();
    for line in v4.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        match key {
            "sockets" => s.sockets_used = field(rest, "used"),
            "TCP" => {
                s.tcp_inuse = field(rest, "inuse");
                s.tcp_orphan = field(rest, "orphan");
                s.tcp_tw = field(rest, "tw");
                s.tcp_alloc = field(rest, "alloc");
            }
            "UDP" => s.udp_inuse = field(rest, "inuse"),
            _ => {}
        }
    }
    if let Some(v6) = v6 {
        for line in v6.lines() {
            let Some((key, rest)) = line.split_once(':') else {
                continue;
            };
            let add = |slot: &mut Option<u64>, v: Option<u64>| {
                if let (Some(a), Some(b)) = (slot.as_mut(), v) {
                    *a += b;
                }
            };
            match key {
                "TCP6" => add(&mut s.tcp_inuse, field(rest, "inuse")),
                "UDP6" => add(&mut s.udp_inuse, field(rest, "inuse")),
                _ => {}
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// /proc/sys/fs/file-nr
// ---------------------------------------------------------------------------

/// Returns (allocated file handles, maximum).
pub fn parse_file_nr(text: &str) -> Option<(u64, u64)> {
    let mut it = text.split_ascii_whitespace();
    let alloc = it.next()?.parse().ok()?;
    let _unused = it.next()?;
    let max = it.next()?.parse().ok()?;
    Some((alloc, max))
}

// ---------------------------------------------------------------------------
// /proc/mounts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub mount_point: String,
    pub fstype: String,
    /// Read-only state of the filesystem itself (superblock), known only
    /// from `mountinfo`. A read-only *bind mount* of a writable filesystem
    /// (e.g. inside a sandboxed systemd service) is not read-only here.
    pub sb_readonly: Option<bool>,
}

/// Undo the octal escaping (`\040` for space etc.) used in the mount table.
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mounts(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_ascii_whitespace();
            Some(Mount {
                device: unescape_mount(f.next()?),
                mount_point: unescape_mount(f.next()?),
                fstype: f.next()?.to_string(),
                sb_readonly: None,
            })
        })
        .collect()
}

/// Parse `/proc/self/mountinfo` (see proc(5)):
/// `id parent maj:min root mount_point mount_opts [optional...] - fstype source super_opts`
pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let mut l = left.split_ascii_whitespace();
            let mount_point = unescape_mount(l.nth(4)?);
            let mut r = right.split_ascii_whitespace();
            let fstype = r.next()?.to_string();
            let device = unescape_mount(r.next()?);
            let sb_readonly = r.next().map(|o| o.split(',').any(|x| x == "ro"));
            Some(Mount {
                device,
                mount_point,
                fstype,
                sb_readonly,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// /proc/<pid>/stat and /proc/<pid>/io
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidStat {
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub utime: u64,
    pub stime: u64,
    pub num_threads: u64,
    pub starttime: u64,
    pub rss_pages: u64,
}

/// Parse `/proc/<pid>/stat`. The command name is enclosed in parentheses and
/// may itself contain spaces and parentheses, so we split at the *last* `)`.
pub fn parse_pid_stat(text: &str) -> Option<PidStat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = text.get(close + 1..)?.split_ascii_whitespace().collect();
    // `rest[0]` is field 3 (state) in proc(5) numbering.
    let f = |n: usize| rest.get(n - 3).and_then(|v| v.parse::<u64>().ok());
    Some(PidStat {
        comm,
        state: rest.first()?.chars().next()?,
        ppid: f(4)? as u32,
        utime: f(14)?,
        stime: f(15)?,
        num_threads: f(20)?,
        starttime: f(22)?,
        rss_pages: f(24)?,
    })
}

/// Returns (read_bytes, write_bytes): bytes that actually hit the storage
/// layer, as opposed to `rchar`/`wchar` which include page-cache hits.
pub fn parse_pid_io(text: &str) -> Option<(u64, u64)> {
    let mut r = None;
    let mut w = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("read_bytes:") {
            r = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("write_bytes:") {
            w = v.trim().parse().ok();
        }
    }
    Some((r?, w?))
}

// ---------------------------------------------------------------------------
// /proc/uptime
// ---------------------------------------------------------------------------

pub fn parse_uptime(text: &str) -> Option<f64> {
    text.split_ascii_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "cpu  10132153 290696 3084719 46828483 16683 0 25195 0 0 0
cpu0 1393280 32966 572056 13343292 6130 0 17875 0 0 0
cpu1 1335990 44063 487004 13504658 3254 0 4263 12 0 0
intr 199292334 26 0 0 0 0 0 0 0 1 0 0 0
ctxt 3436785126
btime 1700000000
processes 1234567
procs_running 3
procs_blocked 1
softirq 61217829 1 18036473 6 2069016 0 0 26 13530010 0 27582297
";

    #[test]
    fn stat_parses_totals_and_cores() {
        let s = parse_stat(STAT).unwrap();
        assert_eq!(s.cpu.user, 10_132_153);
        assert_eq!(s.cpu.iowait, 16_683);
        assert_eq!(s.per_cpu.len(), 2);
        assert_eq!(s.per_cpu[1].steal, 12);
        assert_eq!(s.ctxt, Some(3_436_785_126));
        assert_eq!(s.procs_running, Some(3));
        assert_eq!(s.procs_blocked, Some(1));
        assert_eq!(
            s.cpu.total(),
            10_132_153 + 290_696 + 3_084_719 + 46_828_483 + 16_683 + 25_195
        );
    }

    #[test]
    fn stat_without_cpu_line_is_none() {
        assert!(parse_stat("ctxt 5\n").is_none());
    }

    #[test]
    fn loadavg() {
        let l = parse_loadavg("0.52 0.58 0.59 2/1203 45678\n").unwrap();
        assert_eq!(l.one, 0.52);
        assert_eq!(l.fifteen, 0.59);
        assert_eq!(l.runnable, 2);
        assert_eq!(l.total_tasks, 1203);
        assert!(parse_loadavg("").is_none());
    }

    const MEMINFO: &str = "MemTotal:       16314912 kB
MemFree:         1021404 kB
MemAvailable:    9876544 kB
Buffers:          412000 kB
Cached:          8000000 kB
SwapCached:        10000 kB
Shmem:            300000 kB
SReclaimable:     500000 kB
SwapTotal:       2097148 kB
SwapFree:        1048574 kB
Dirty:              1204 kB
Writeback:             0 kB
HugePages_Total:       0
";

    #[test]
    fn meminfo_converts_to_bytes() {
        let m = parse_meminfo(MEMINFO).unwrap();
        assert_eq!(m.total, 16_314_912 * 1024);
        assert_eq!(m.available, Some(9_876_544 * 1024));
        assert_eq!(m.used(), (16_314_912 - 9_876_544) * 1024);
        assert_eq!(m.swap_used(), (2_097_148 - 1_048_574) * 1024);
        assert_eq!(m.dirty, 1204 * 1024);
    }

    #[test]
    fn meminfo_without_available_falls_back() {
        let m =
            parse_meminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 300 kB\n")
                .unwrap();
        assert_eq!(m.available, None);
        assert_eq!(m.used(), 500 * 1024);
    }

    #[test]
    fn vmstat_fields() {
        let v =
            parse_vmstat("nr_free_pages 1\npswpin 10\npswpout 20\npgmajfault 300\noom_kill 2\n");
        assert_eq!(v.pswpin, Some(10));
        assert_eq!(v.pswpout, Some(20));
        assert_eq!(v.pgmajfault, Some(300));
        assert_eq!(v.oom_kill, Some(2));
        assert_eq!(parse_vmstat("pswpin 1\n").oom_kill, None);
    }

    #[test]
    fn psi_some_and_full() {
        let p = parse_psi(
            "some avg10=1.50 avg60=0.80 avg300=0.10 total=123\nfull avg10=0.25 avg60=0.00 avg300=0.00 total=5\n",
        )
        .unwrap();
        assert_eq!(p.some_avg10, 1.5);
        assert_eq!(p.some_avg60, 0.8);
        assert_eq!(p.full_avg10, Some(0.25));
        let cpu = parse_psi("some avg10=3.00 avg60=2.00 avg300=1.00 total=1\n").unwrap();
        assert_eq!(cpu.full_avg10, None);
    }

    #[test]
    fn diskstats_filters_and_parses() {
        let text = "   8       0 sda 1000 10 80000 500 2000 20 160000 1500 0 1800 2000 0 0 0 0
   8       1 sda1 900 10 70000 450 1900 20 150000 1400 0 1700 1850
   7       0 loop0 5 0 10 0 0 0 0 0 0 0 0
 259       0 nvme0n1 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17";
        let d = parse_diskstats(text, |n| !n.starts_with("loop") && n != "sda1");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].name, "sda");
        assert_eq!(d[0].reads, 1000);
        assert_eq!(d[0].read_sectors, 80_000);
        assert_eq!(d[0].write_sectors, 160_000);
        assert_eq!(d[0].io_ms, 1800);
        assert_eq!(d[1].name, "nvme0n1");
    }

    #[test]
    fn net_dev() {
        let text = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 98765 432 1 2 0 0 0 0 12345 210 3 4 0 0 0 0
";
        let n = parse_net_dev(text);
        assert_eq!(n.len(), 2);
        assert_eq!(n[1].name, "eth0");
        assert_eq!(n[1].rx_bytes, 98_765);
        assert_eq!(n[1].rx_errs, 1);
        assert_eq!(n[1].rx_drop, 2);
        assert_eq!(n[1].tx_bytes, 12_345);
        assert_eq!(n[1].tx_errs, 3);
        assert_eq!(n[1].tx_drop, 4);
    }

    #[test]
    fn tcp_from_snmp_and_netstat() {
        let snmp = "Ip: Forwarding DefaultTTL
Ip: 1 64
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 5000 300 20 40 12 900000 800000 1600 3 77 0
Udp: InDatagrams NoPorts
Udp: 5 6
";
        let netstat = "TcpExt: SyncookiesSent ListenOverflows ListenDrops
TcpExt: 0 7 9
";
        let t = parse_tcp(snmp, Some(netstat)).unwrap();
        assert_eq!(t.active_opens, 5000);
        assert_eq!(t.curr_estab, 12);
        assert_eq!(t.out_segs, 800_000);
        assert_eq!(t.retrans_segs, 1600);
        assert_eq!(t.listen_overflows, Some(7));
        assert_eq!(t.listen_drops, Some(9));
        assert!(parse_tcp("Ip: a\nIp: 1\n", None).is_none());
    }

    #[test]
    fn sockstat_combines_v6() {
        let v4 = "sockets: used 512
TCP: inuse 20 orphan 1 tw 150 alloc 25 mem 3
UDP: inuse 4 mem 2
";
        let v6 = "TCP6: inuse 5\nUDP6: inuse 2\n";
        let s = parse_sockstat(v4, Some(v6));
        assert_eq!(s.sockets_used, Some(512));
        assert_eq!(s.tcp_inuse, Some(25));
        assert_eq!(s.tcp_tw, Some(150));
        assert_eq!(s.tcp_orphan, Some(1));
        assert_eq!(s.udp_inuse, Some(6));
    }

    #[test]
    fn file_nr() {
        assert_eq!(
            parse_file_nr("3456\t0\t9223372036854775807\n"),
            Some((3456, 9_223_372_036_854_775_807))
        );
    }

    #[test]
    fn mounts_unescape() {
        let m = parse_mounts(
            "/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sdb1 /mnt/my\\040disk xfs rw 0 0\n",
        );
        assert_eq!(m.len(), 2);
        assert_eq!(m[1].mount_point, "/mnt/my disk");
        assert_eq!(m[1].fstype, "xfs");
        assert_eq!(m[1].sb_readonly, None);
    }

    #[test]
    fn mountinfo_separates_bind_and_superblock_flags() {
        let text = "\
22 1 8:2 / / ro,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro
23 22 8:3 / /my\\040data ro,nosuid master:2 propagate_from:1 - xfs /dev/sdb1 rw,attr2
24 22 7:0 / /snap/core/1 ro,nodev - squashfs /dev/loop0 ro
25 22 0:5 / /run rw,nosuid - tmpfs tmpfs rw,size=1600k
";
        let m = parse_mountinfo(text);
        assert_eq!(m.len(), 4);
        // Read-only bind mount (sandbox) of a writable filesystem.
        assert_eq!(m[0].mount_point, "/");
        assert_eq!(m[0].device, "/dev/sda2");
        assert_eq!(m[0].sb_readonly, Some(false));
        // Optional fields before the separator are skipped; escapes undone.
        assert_eq!(m[1].mount_point, "/my data");
        assert_eq!(m[1].fstype, "xfs");
        assert_eq!(m[2].sb_readonly, Some(true));
        assert_eq!(m[3].fstype, "tmpfs");
    }

    #[test]
    fn pid_stat_with_tricky_comm() {
        let text = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 7 0 98765 123456789 4321 18446744073709551615";
        let p = parse_pid_stat(text).unwrap();
        assert_eq!(p.comm, "my (weird) proc");
        assert_eq!(p.state, 'S');
        assert_eq!(p.ppid, 1);
        assert_eq!(p.utime, 250);
        assert_eq!(p.stime, 50);
        assert_eq!(p.num_threads, 7);
        assert_eq!(p.starttime, 98_765);
        assert_eq!(p.rss_pages, 4321);
    }

    #[test]
    fn pid_io() {
        let text = "rchar: 100\nwchar: 200\nsyscr: 1\nsyscw: 2\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n";
        assert_eq!(parse_pid_io(text), Some((4096, 8192)));
        assert_eq!(parse_pid_io("rchar: 1\n"), None);
    }

    #[test]
    fn uptime() {
        assert_eq!(parse_uptime("12345.67 54321.00\n"), Some(12345.67));
    }
}
