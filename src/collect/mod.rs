//! System metric collection.
//!
//! [`Collector`] reads kernel interfaces, keeps the previous raw counters and
//! turns their deltas into a [`Snapshot`]. It performs no network I/O and
//! writes nothing to disk.

pub mod fs;
pub mod process;
pub mod procfs;

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::metrics::*;
use crate::util;
use procfs::*;

/// Read a whole file into a reusable buffer.
pub(crate) fn read_into(path: &str, buf: &mut String) -> io::Result<()> {
    buf.clear();
    std::fs::File::open(path)?.read_to_string(buf)?;
    Ok(())
}

/// Which optional (more expensive) sources to collect.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub processes: bool,
    pub process_io: bool,
    pub filesystems: bool,
    pub include_network_fs: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            processes: true,
            process_io: false,
            filesystems: true,
            include_network_fs: false,
        }
    }
}

/// How often slow-changing or more expensive data is refreshed.
const FS_REFRESH: Duration = Duration::from_secs(5);
const META_REFRESH: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct DiskMeta {
    label: String,
    stacked: bool,
}

pub struct Collector {
    pub opts: Options,
    buf: String,
    buf2: String,
    clk_tck: f64,
    page_size: u64,
    host: HostInfo,
    prev_time: Option<Instant>,
    prev_stat: Option<StatRaw>,
    prev_vm: Option<VmStatRaw>,
    prev_disks: HashMap<String, DiskRaw>,
    prev_nets: HashMap<String, NetRaw>,
    prev_tcp: Option<TcpRaw>,
    procs: process::ProcessScanner,
    fs_cache: Vec<FsStats>,
    fs_available: bool,
    fs_time: Option<Instant>,
    /// `None` when `/sys/block` is not readable.
    disk_meta: Option<HashMap<String, DiskMeta>>,
    net_virtual: HashMap<String, bool>,
    meta_time: Option<Instant>,
}

impl Collector {
    pub fn new(opts: Options) -> Self {
        // SAFETY: sysconf has no preconditions.
        let clk = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        Collector {
            opts,
            buf: String::with_capacity(16 * 1024),
            buf2: String::with_capacity(4 * 1024),
            clk_tck: if clk > 0 { clk as f64 } else { 100.0 },
            page_size: if page > 0 { page as u64 } else { 4096 },
            host: host_info(),
            prev_time: None,
            prev_stat: None,
            prev_vm: None,
            prev_disks: HashMap::new(),
            prev_nets: HashMap::new(),
            prev_tcp: None,
            procs: process::ProcessScanner::default(),
            fs_cache: Vec::new(),
            fs_available: false,
            fs_time: None,
            disk_meta: None,
            net_virtual: HashMap::new(),
            meta_time: None,
        }
    }

    /// Force the filesystem list to be refreshed on the next sample.
    pub fn invalidate_fs(&mut self) {
        self.fs_time = None;
    }

    pub fn sample(&mut self) -> Snapshot {
        let now = Instant::now();
        let dt = self
            .prev_time
            .map(|t| now.duration_since(t).as_secs_f64())
            .filter(|d| *d > 0.001);
        if self
            .meta_time
            .is_none_or(|t| now.duration_since(t) >= META_REFRESH)
        {
            self.refresh_meta();
            self.meta_time = Some(now);
        }

        let mut s = Snapshot {
            time: util::now_unix(),
            interval: dt,
            ..Default::default()
        };

        self.sample_cpu(&mut s, dt);
        if read_into("/proc/loadavg", &mut self.buf).is_ok() {
            s.load = parse_loadavg(&self.buf);
        }
        self.sample_mem(&mut s, dt);
        s.psi_cpu = self.read_psi("/proc/pressure/cpu");
        s.psi_mem = self.read_psi("/proc/pressure/memory");
        s.psi_io = self.read_psi("/proc/pressure/io");
        self.sample_disks(&mut s, dt);
        self.sample_net(&mut s, dt);
        self.sample_tcp(&mut s, dt);
        if read_into("/proc/sys/fs/file-nr", &mut self.buf).is_ok() {
            s.file_handles = parse_file_nr(&self.buf);
        }

        if self.opts.filesystems {
            if self
                .fs_time
                .is_none_or(|t| now.duration_since(t) >= FS_REFRESH)
            {
                self.refresh_fs();
                self.fs_time = Some(now);
            }
            s.fs_available = self.fs_available;
            s.filesystems = self.fs_cache.clone();
        }

        if self.opts.processes {
            s.procs = self
                .procs
                .scan(self.opts.process_io, self.clk_tck, self.page_size);
        }

        let mut host = self.host.clone();
        if read_into("/proc/uptime", &mut self.buf).is_ok() {
            host.uptime = parse_uptime(&self.buf);
        }
        if let Some(n) = self.prev_stat.as_ref().map(|p| p.per_cpu.len())
            && n > 0
        {
            host.ncpu = n;
        }
        s.host = host;
        self.prev_time = Some(now);
        s
    }

    fn read_psi(&mut self, path: &str) -> Option<Psi> {
        read_into(path, &mut self.buf).ok()?;
        parse_psi(&self.buf)
    }

    fn sample_cpu(&mut self, s: &mut Snapshot, dt: Option<f64>) {
        if read_into("/proc/stat", &mut self.buf).is_err() {
            return;
        }
        let Some(cur) = parse_stat(&self.buf) else {
            return;
        };
        let mut stats = CpuStats {
            procs_running: cur.procs_running,
            procs_blocked: cur.procs_blocked,
            ..Default::default()
        };
        // On the first sample counts are valid, percentages are not yet.
        if let (Some(prev), Some(dt)) = (&self.prev_stat, dt) {
            stats.total = cpu_usage(&prev.cpu, &cur.cpu);
            if stats.total.is_some() && prev.per_cpu.len() == cur.per_cpu.len() {
                stats.per_core = prev
                    .per_cpu
                    .iter()
                    .zip(&cur.per_cpu)
                    .map(|(p, c)| cpu_usage(p, c).map_or(0.0, |u| u.busy))
                    .collect();
            }
            stats.ctxt_per_s = rate_opt(prev.ctxt, cur.ctxt, dt);
            stats.forks_per_s = rate_opt(prev.forks, cur.forks, dt);
        }
        s.cpu = Some(stats);
        self.prev_stat = Some(cur);
    }

    fn sample_mem(&mut self, s: &mut Snapshot, dt: Option<f64>) {
        if read_into("/proc/meminfo", &mut self.buf).is_err() {
            return;
        }
        let Some(info) = parse_meminfo(&self.buf) else {
            return;
        };
        let mut m = MemStats {
            info,
            ..Default::default()
        };
        if read_into("/proc/vmstat", &mut self.buf).is_ok() {
            let vm = parse_vmstat(&self.buf);
            m.oom_kills = vm.oom_kill;
            if let (Some(p), Some(dt)) = (&self.prev_vm, dt) {
                m.swap_in_per_s = rate_opt(p.pswpin, vm.pswpin, dt);
                m.swap_out_per_s = rate_opt(p.pswpout, vm.pswpout, dt);
                m.major_faults_per_s = rate_opt(p.pgmajfault, vm.pgmajfault, dt);
            }
            self.prev_vm = Some(vm);
        }
        s.mem = Some(m);
    }

    fn refresh_meta(&mut self) {
        self.disk_meta = std::fs::read_dir("/sys/block").ok().map(|dir| {
            dir.flatten()
                .filter_map(|e| {
                    let name = e.file_name().into_string().ok()?;
                    if name.starts_with("loop") || name.starts_with("ram") {
                        return None;
                    }
                    let base = format!("/sys/block/{name}");
                    let label = std::fs::read_to_string(format!("{base}/dm/name"))
                        .map(|s| s.trim().to_string())
                        .ok()
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| name.clone());
                    let stacked = std::fs::read_dir(format!("{base}/slaves"))
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false);
                    Some((name, DiskMeta { label, stacked }))
                })
                .collect()
        });
        self.net_virtual.clear();
    }

    fn sample_disks(&mut self, s: &mut Snapshot, dt: Option<f64>) {
        if read_into("/proc/diskstats", &mut self.buf).is_err() {
            return;
        }
        s.disks_available = true;
        let meta = &self.disk_meta;
        let cur = parse_diskstats(&self.buf, |name| match meta {
            Some(m) => m.contains_key(name),
            // Without /sys, fall back to skipping obvious non-disks.
            None => !name.starts_with("loop") && !name.starts_with("ram"),
        });
        let mut next = HashMap::with_capacity(cur.len());
        for d in cur {
            // Skip devices that never saw any I/O (empty card readers etc.).
            if d.reads == 0 && d.writes == 0 {
                continue;
            }
            if let (Some(p), Some(dt)) = (self.prev_disks.get(&d.name), dt) {
                let ios = d.reads.saturating_sub(p.reads) + d.writes.saturating_sub(p.writes);
                let wait_ms =
                    d.read_ms.saturating_sub(p.read_ms) + d.write_ms.saturating_sub(p.write_ms);
                let m = meta.as_ref().and_then(|m| m.get(&d.name));
                s.disks.push(DiskStats {
                    name: d.name.clone(),
                    label: m.map_or_else(|| d.name.clone(), |m| m.label.clone()),
                    read_bps: d.read_sectors.saturating_sub(p.read_sectors) as f64 * 512.0 / dt,
                    write_bps: d.write_sectors.saturating_sub(p.write_sectors) as f64 * 512.0 / dt,
                    read_iops: d.reads.saturating_sub(p.reads) as f64 / dt,
                    write_iops: d.writes.saturating_sub(p.writes) as f64 / dt,
                    util_pct: (d.io_ms.saturating_sub(p.io_ms) as f64 / (dt * 1000.0) * 100.0)
                        .min(100.0),
                    await_ms: (ios > 0).then(|| wait_ms as f64 / ios as f64),
                    stacked: m.is_some_and(|m| m.stacked),
                });
            }
            next.insert(d.name.clone(), d);
        }
        s.disks.sort_by(|a, b| a.name.cmp(&b.name));
        self.prev_disks = next;
    }

    fn is_virtual_net(&mut self, name: &str) -> bool {
        if let Some(v) = self.net_virtual.get(name) {
            return *v;
        }
        let sys = Path::new("/sys/class/net");
        let v = if sys.exists() {
            Path::new("/sys/devices/virtual/net").join(name).exists()
        } else {
            name == "lo"
        };
        self.net_virtual.insert(name.to_string(), v);
        v
    }

    fn sample_net(&mut self, s: &mut Snapshot, dt: Option<f64>) {
        if read_into("/proc/net/dev", &mut self.buf).is_err() {
            return;
        }
        s.nets_available = true;
        let cur = parse_net_dev(&self.buf);
        let mut next = HashMap::with_capacity(cur.len());
        for n in cur {
            // Interfaces that never carried a packet (unused tunnel stubs
            // such as gre0 or sit0) are noise.
            if n.rx_packets == 0 && n.tx_packets == 0 {
                continue;
            }
            if let (Some(p), Some(dt)) = (self.prev_nets.get(&n.name), dt) {
                let r = |c: u64, p: u64| c.saturating_sub(p) as f64 / dt;
                let stats = NetStats {
                    name: n.name.clone(),
                    is_virtual: false,
                    rx_bps: r(n.rx_bytes, p.rx_bytes),
                    tx_bps: r(n.tx_bytes, p.tx_bytes),
                    rx_pps: r(n.rx_packets, p.rx_packets),
                    tx_pps: r(n.tx_packets, p.tx_packets),
                    rx_errs_per_s: r(n.rx_errs, p.rx_errs),
                    tx_errs_per_s: r(n.tx_errs, p.tx_errs),
                    rx_drop_per_s: r(n.rx_drop, p.rx_drop),
                    tx_drop_per_s: r(n.tx_drop, p.tx_drop),
                    total_errs: n.rx_errs + n.tx_errs,
                    total_drops: n.rx_drop + n.tx_drop,
                };
                s.nets.push(stats);
            }
            next.insert(n.name.clone(), n);
        }
        for i in 0..s.nets.len() {
            let name = s.nets[i].name.clone();
            s.nets[i].is_virtual = self.is_virtual_net(&name);
        }
        s.nets.sort_by(|a, b| {
            a.is_virtual
                .cmp(&b.is_virtual)
                .then_with(|| a.name.cmp(&b.name))
        });
        self.prev_nets = next;
    }

    fn sample_tcp(&mut self, s: &mut Snapshot, dt: Option<f64>) {
        if read_into("/proc/net/snmp", &mut self.buf).is_err() {
            return;
        }
        let netstat = read_into("/proc/net/netstat", &mut self.buf2)
            .is_ok()
            .then_some(self.buf2.as_str());
        let Some(cur) = parse_tcp(&self.buf, netstat) else {
            return;
        };
        let sockets = match read_into("/proc/net/sockstat", &mut self.buf) {
            Ok(()) => {
                let v6 = read_into("/proc/net/sockstat6", &mut self.buf2)
                    .is_ok()
                    .then_some(self.buf2.as_str());
                parse_sockstat(&self.buf, v6)
            }
            Err(_) => SockStat::default(),
        };
        if let (Some(p), Some(dt)) = (&self.prev_tcp, dt) {
            let r = |c: u64, p: u64| c.saturating_sub(p) as f64 / dt;
            s.tcp = Some(TcpStats {
                established: cur.curr_estab,
                active_opens_per_s: r(cur.active_opens, p.active_opens),
                passive_opens_per_s: r(cur.passive_opens, p.passive_opens),
                attempt_fails_per_s: r(cur.attempt_fails, p.attempt_fails),
                estab_resets_per_s: r(cur.estab_resets, p.estab_resets),
                in_segs_per_s: r(cur.in_segs, p.in_segs),
                out_segs_per_s: r(cur.out_segs, p.out_segs),
                retrans_per_s: r(cur.retrans_segs, p.retrans_segs),
                in_errs_per_s: r(cur.in_errs, p.in_errs),
                out_rsts_per_s: r(cur.out_rsts, p.out_rsts),
                listen_overflows_per_s: rate_opt(p.listen_overflows, cur.listen_overflows, dt),
                listen_drops_per_s: rate_opt(p.listen_drops, cur.listen_drops, dt),
                sockets,
            });
        } else {
            s.tcp = Some(TcpStats {
                established: cur.curr_estab,
                sockets,
                ..Default::default()
            });
        }
        self.prev_tcp = Some(cur);
    }

    fn refresh_fs(&mut self) {
        let mounts = if read_into("/proc/self/mountinfo", &mut self.buf).is_ok() {
            parse_mountinfo(&self.buf)
        } else if read_into("/proc/self/mounts", &mut self.buf).is_ok()
            || read_into("/proc/mounts", &mut self.buf).is_ok()
        {
            parse_mounts(&self.buf)
        } else {
            self.fs_available = false;
            self.fs_cache.clear();
            return;
        };
        self.fs_available = true;
        self.fs_cache = fs::collect(&mounts, self.opts.include_network_fs);
    }
}

fn rate_opt(prev: Option<u64>, cur: Option<u64>, dt: f64) -> Option<f64> {
    Some(cur?.saturating_sub(prev?) as f64 / dt)
}

/// Percentages from two cumulative CPU time samples.
pub fn cpu_usage(prev: &CpuTimes, cur: &CpuTimes) -> Option<CpuUsage> {
    let total = cur.total().checked_sub(prev.total())?;
    if total == 0 {
        return None;
    }
    let t = total as f64;
    let d = |c: u64, p: u64| c.saturating_sub(p) as f64 / t * 100.0;
    let idle = d(cur.idle, prev.idle);
    let iowait = d(cur.iowait, prev.iowait);
    Some(CpuUsage {
        user: d(cur.user, prev.user),
        nice: d(cur.nice, prev.nice),
        system: d(cur.system, prev.system),
        iowait,
        irq: d(cur.irq + cur.softirq, prev.irq + prev.softirq),
        steal: d(cur.steal, prev.steal),
        idle,
        busy: (100.0 - idle - iowait).clamp(0.0, 100.0),
    })
}

// `c_char` is `i8` on x86_64 but `u8` on aarch64, so the cast is needed.
#[allow(clippy::unnecessary_cast)]
fn cstr_field(field: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn host_info() -> HostInfo {
    // SAFETY: utsname is plain data; uname fills it in.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::uname(&mut u) } == 0;
    // SAFETY: sysconf has no preconditions.
    let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    HostInfo {
        hostname: if ok {
            cstr_field(&u.nodename)
        } else {
            "unknown".into()
        },
        kernel: if ok {
            format!("{} {}", cstr_field(&u.sysname), cstr_field(&u.release))
        } else {
            "unknown".into()
        },
        uptime: None,
        ncpu: if ncpu > 0 { ncpu as usize } else { 1 },
    }
}

/// True when the kernel interfaces Tirnix relies on are present.
pub fn procfs_available() -> bool {
    Path::new("/proc/stat").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_usage_from_deltas() {
        let p = CpuTimes {
            user: 100,
            system: 50,
            idle: 800,
            iowait: 50,
            ..Default::default()
        };
        let c = CpuTimes {
            user: 160,
            system: 70,
            idle: 900,
            iowait: 70,
            ..Default::default()
        };
        let u = cpu_usage(&p, &c).unwrap();
        assert!((u.user - 30.0).abs() < 1e-9);
        assert!((u.system - 10.0).abs() < 1e-9);
        assert!((u.idle - 50.0).abs() < 1e-9);
        assert!((u.iowait - 10.0).abs() < 1e-9);
        assert!((u.busy - 40.0).abs() < 1e-9);
    }

    #[test]
    fn cpu_usage_rejects_no_progress_or_reset() {
        let p = CpuTimes {
            user: 100,
            ..Default::default()
        };
        assert!(cpu_usage(&p, &p).is_none());
        assert!(cpu_usage(&p, &CpuTimes::default()).is_none());
    }

    #[test]
    fn rate_helper() {
        assert_eq!(rate_opt(Some(10), Some(30), 2.0), Some(10.0));
        assert_eq!(rate_opt(None, Some(30), 2.0), None);
        // Counter reset never yields a negative rate.
        assert_eq!(rate_opt(Some(30), Some(10), 2.0), Some(0.0));
    }

    #[test]
    fn collector_never_panics() {
        // Works on any OS: on non-Linux systems sources are simply missing.
        let mut c = Collector::new(Options {
            process_io: true,
            ..Default::default()
        });
        let a = c.sample();
        assert!(a.interval.is_none());
        std::thread::sleep(Duration::from_millis(20));
        let b = c.sample();
        assert!(b.interval.is_some());
        if procfs_available() {
            assert!(b.cpu.is_some());
            assert!(b.mem.is_some());
        }
    }
}
