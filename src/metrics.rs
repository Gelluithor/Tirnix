//! Data model shared by the collector, the TUI, diagnostics and storage.
//!
//! * [`Snapshot`] – everything derived from one sample (percentages, rates).
//! * [`Record`]   – a flat, compact summary of a snapshot. This is what the
//!   in-memory window keeps and what the logger writes as one JSON line.

use serde::{Deserialize, Serialize};

pub use crate::collect::procfs::{LoadAvg, MemInfo, Psi, SockStat};
use crate::util;

#[derive(Debug, Clone, Default)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel: String,
    pub uptime: Option<f64>,
    pub ncpu: usize,
}

/// CPU time split in percent of all CPUs (0–100).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CpuUsage {
    pub user: f64,
    pub nice: f64,
    pub system: f64,
    pub iowait: f64,
    /// Hardware + software interrupts.
    pub irq: f64,
    pub steal: f64,
    pub idle: f64,
    /// Everything except idle and iowait.
    pub busy: f64,
}

#[derive(Debug, Clone, Default)]
pub struct CpuStats {
    /// `None` until two samples exist.
    pub total: Option<CpuUsage>,
    /// Busy percentage per logical CPU.
    pub per_core: Vec<f64>,
    pub ctxt_per_s: Option<f64>,
    pub forks_per_s: Option<f64>,
    pub procs_running: Option<u64>,
    pub procs_blocked: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct MemStats {
    pub info: MemInfo,
    /// Pages swapped in / out per second.
    pub swap_in_per_s: Option<f64>,
    pub swap_out_per_s: Option<f64>,
    pub major_faults_per_s: Option<f64>,
    /// Cumulative OOM kills since boot (Linux 4.13+).
    pub oom_kills: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct DiskStats {
    /// Kernel name, e.g. `sda`, `nvme0n1`, `dm-0`.
    pub name: String,
    /// Friendlier name where available (device-mapper name), else `name`.
    pub label: String,
    pub read_bps: f64,
    pub write_bps: f64,
    pub read_iops: f64,
    pub write_iops: f64,
    /// Share of wall time with at least one request in flight. For SSDs and
    /// RAID devices that serve requests in parallel, 100 % does not
    /// necessarily mean saturated.
    pub util_pct: f64,
    /// Average time per completed request (queue + service), `None` when no
    /// request completed during the interval.
    pub await_ms: Option<f64>,
    /// Device is built on top of other devices (dm, md). Excluded from
    /// totals to avoid counting the same I/O twice.
    pub stacked: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FsStats {
    pub mount_point: String,
    pub device: String,
    pub fstype: String,
    pub total: u64,
    pub used: u64,
    /// Space available to unprivileged users.
    pub avail: u64,
    pub inodes_total: u64,
    pub inodes_free: u64,
    pub readonly: bool,
}

impl FsStats {
    /// Usage as `df` reports it: used / (used + available).
    pub fn used_pct(&self) -> Option<f64> {
        util::pct(self.used as f64, (self.used + self.avail) as f64)
    }

    /// `None` when the filesystem does not report inodes (btrfs, some FUSE).
    pub fn inode_pct(&self) -> Option<f64> {
        let used = self.inodes_total.saturating_sub(self.inodes_free);
        util::pct(used as f64, self.inodes_total as f64)
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetStats {
    pub name: String,
    /// Loopback or a software interface (bridge, veth, tun, bond, …).
    /// Excluded from totals to avoid double counting.
    pub is_virtual: bool,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub rx_errs_per_s: f64,
    pub tx_errs_per_s: f64,
    pub rx_drop_per_s: f64,
    pub tx_drop_per_s: f64,
    pub total_errs: u64,
    pub total_drops: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TcpStats {
    pub established: u64,
    pub active_opens_per_s: f64,
    pub passive_opens_per_s: f64,
    pub attempt_fails_per_s: f64,
    pub estab_resets_per_s: f64,
    pub in_segs_per_s: f64,
    pub out_segs_per_s: f64,
    pub retrans_per_s: f64,
    pub in_errs_per_s: f64,
    pub out_rsts_per_s: f64,
    pub listen_overflows_per_s: Option<f64>,
    pub listen_drops_per_s: Option<f64>,
    pub sockets: SockStat,
}

impl TcpStats {
    /// Retransmitted segments as a share of all sent segments.
    pub fn retrans_pct(&self) -> Option<f64> {
        util::pct(self.retrans_per_s, self.out_segs_per_s)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub state: char,
    /// Percent of one CPU (like `top`); can exceed 100 for multi-threaded
    /// processes. `None` for processes first seen in this sample.
    pub cpu_pct: Option<f64>,
    pub rss: u64,
    pub threads: u64,
    pub read_bps: Option<f64>,
    pub write_bps: Option<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcSummary {
    pub list: Vec<ProcInfo>,
    pub total: usize,
    pub threads: u64,
    pub running: usize,
    /// Processes in uninterruptible sleep (state `D`), usually waiting on I/O.
    pub uninterruptible: usize,
    pub zombies: usize,
    /// Whether per-process I/O was requested for this sample.
    pub io_collected: bool,
    /// Processes whose `/proc/<pid>/io` could not be read (permissions).
    pub io_denied: usize,
}

// ---------------------------------------------------------------------------
// Network drop analysis
// ---------------------------------------------------------------------------
//
// Filled by `collect::netdiag`. Cheap counters are read on every sample; the
// expensive parts (socket tables, process ownership, interrupt distribution)
// only while the cheap counters show drops. All rates are per second.

/// Process that owns a socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub comm: String,
}

/// Who holds a socket. The user is known from the socket table even when
/// the process is not visible (another user's process without root).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SockOwner {
    pub process: Option<Owner>,
    pub user: Option<String>,
    /// The process could not be identified because of permissions.
    pub hidden: bool,
}

impl SockOwner {
    pub fn describe(&self) -> String {
        let user = self.user.as_deref();
        match (&self.process, user) {
            (Some(p), Some(u)) => format!("{} (pid {}, user {u})", p.comm, p.pid),
            (Some(p), None) => format!("{} (pid {})", p.comm, p.pid),
            (None, Some(u)) if self.hidden => {
                format!("a process of user {u} (not visible without root)")
            }
            (None, _) if self.hidden => "a process not visible without root".into(),
            (None, Some(u)) => format!("user {u}; process not found (socket may be closed)"),
            (None, None) => "owner not found (socket may be closed)".into(),
        }
    }

    /// Short form for titles: process name, else user.
    pub fn short(&self) -> Option<String> {
        self.process
            .as_ref()
            .map(|p| p.comm.clone())
            .or_else(|| self.user.as_ref().map(|u| format!("user {u}")))
    }
}

/// A remote peer with TCP connections that currently retransmit.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RetransPeer {
    pub remote: String,
    /// Local address of the first such connection (shows the service).
    pub local: String,
    pub sockets: usize,
    /// Connections still in SYN-SENT (connection attempts not answered).
    pub connecting: usize,
    pub owner: SockOwner,
}

/// Interrupt distribution of one network interface.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IrqShare {
    /// CPU that handled most of the interface's interrupts.
    pub top_cpu: usize,
    /// Share of the interrupts handled by `top_cpu` (%).
    pub top_share: f64,
    /// CPUs that handled at least 5 % of the interrupts.
    pub cpus_used: usize,
    pub per_s: f64,
}

/// Classified drop and error rates of one interface, from
/// `/sys/class/net/<iface>/statistics`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IfaceDiag {
    pub name: String,
    pub rx_dropped: f64,
    pub tx_dropped: f64,
    /// CRC, frame-alignment and length errors: damaged frames.
    pub rx_corrupt: f64,
    /// Missed, over and FIFO errors: the NIC ran out of receive buffers.
    pub rx_overrun: f64,
    /// Frames for protocols nothing on this host handles.
    pub rx_nohandler: f64,
    /// Carrier, aborted and FIFO transmit errors.
    pub tx_errors: f64,
    pub irq: Option<IrqShare>,
}

/// Per-CPU drops of the kernel's receive backlog (`/proc/net/softnet_stat`).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SoftnetCpu {
    pub cpu: usize,
    /// Packets dropped because the backlog queue was full.
    pub dropped: f64,
    /// Times packet processing ran out of budget with work left.
    pub squeezed: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct UdpDiag {
    /// Datagrams dropped because a socket's receive buffer was full.
    pub rcvbuf_errors: f64,
    pub sndbuf_errors: f64,
    pub in_errors: f64,
    /// Datagrams to ports nobody listens on.
    pub no_ports: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TcpDropDiag {
    pub backlog_drop: f64,
    pub rcvq_drop: f64,
    pub zero_window_drop: f64,
    /// Data discarded from receive queues under memory pressure.
    pub pruned: f64,
    pub ofo_drop: f64,
    pub mem_pressures: f64,
    pub reqq_full_drop: f64,
    /// Retransmitted SYN and SYN-ACK segments (connection setup).
    pub syn_retrans: f64,
}

impl TcpDropDiag {
    /// Received data dropped inside the TCP stack.
    pub fn receive_drops(&self) -> f64 {
        self.backlog_drop + self.rcvq_drop + self.pruned + self.ofo_drop + self.zero_window_drop
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IpDiag {
    pub in_discards: f64,
    pub in_hdr_errors: f64,
    pub in_addr_errors: f64,
    pub reasm_fails: f64,
    pub out_discards: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ConntrackDiag {
    pub count: u64,
    pub max: u64,
    /// Packets dropped because the table was full (needs the stat file).
    pub drop: Option<f64>,
    pub early_drop: Option<f64>,
    pub insert_failed: Option<f64>,
}

impl ConntrackDiag {
    pub fn used_pct(&self) -> Option<f64> {
        util::pct(self.count as f64, self.max as f64)
    }
}

/// A UDP socket whose receive buffer overflowed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SocketDrops {
    pub proto: &'static str,
    pub local: String,
    /// Drops per second since the previous scan, if there was one.
    pub drops_per_s: Option<f64>,
    /// Drops since the socket was created.
    pub total: u64,
    pub owner: SockOwner,
}

/// A listening TCP socket with connections waiting to be accepted.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ListenQueue {
    pub local: String,
    pub queued: u64,
    pub owner: SockOwner,
}

#[derive(Debug, Clone, Default)]
pub struct NetDiag {
    /// Interfaces that recently had drops or errors.
    pub ifaces: Vec<IfaceDiag>,
    pub softnet_available: bool,
    /// CPUs with backlog drops or squeezes in this interval.
    pub softnet: Vec<SoftnetCpu>,
    pub udp: Option<UdpDiag>,
    pub tcp: Option<TcpDropDiag>,
    pub ip: Option<IpDiag>,
    pub conntrack: Option<ConntrackDiag>,
    /// UDP sockets that dropped datagrams (scanned only during drops).
    pub udp_sockets: Vec<SocketDrops>,
    /// Listening sockets with a non-empty accept queue (scanned only
    /// during listen drops).
    pub listeners: Vec<ListenQueue>,
    /// Peers of retransmitting TCP connections (scanned only while the
    /// retransmission ratio is high).
    pub retrans_peers: Vec<RetransPeer>,
}

impl NetDiag {
    pub fn softnet_drops(&self) -> f64 {
        self.softnet.iter().map(|c| c.dropped).sum()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Unix time of the sample.
    pub time: f64,
    /// Seconds since the previous sample; `None` for the first one, in which
    /// case no rates are available yet.
    pub interval: Option<f64>,
    pub host: HostInfo,
    pub cpu: Option<CpuStats>,
    pub load: Option<LoadAvg>,
    pub mem: Option<MemStats>,
    pub psi_cpu: Option<Psi>,
    pub psi_mem: Option<Psi>,
    pub psi_io: Option<Psi>,
    pub disks_available: bool,
    pub disks: Vec<DiskStats>,
    pub fs_available: bool,
    pub filesystems: Vec<FsStats>,
    pub nets_available: bool,
    pub nets: Vec<NetStats>,
    pub tcp: Option<TcpStats>,
    pub procs: Option<ProcSummary>,
    /// (allocated, max) file handles system-wide.
    pub file_handles: Option<(u64, u64)>,
    pub net_diag: NetDiag,
}

impl Snapshot {
    fn physical_disks(&self) -> impl Iterator<Item = &DiskStats> {
        self.disks.iter().filter(|d| !d.stacked)
    }

    /// Sum over physical devices; `None` before rates exist.
    pub fn disk_total(&self) -> Option<(f64, f64, f64, f64)> {
        if !self.disks_available || self.interval.is_none() {
            return None;
        }
        Some(self.physical_disks().fold((0.0, 0.0, 0.0, 0.0), |a, d| {
            (
                a.0 + d.read_bps,
                a.1 + d.write_bps,
                a.2 + d.read_iops,
                a.3 + d.write_iops,
            )
        }))
    }

    pub fn busiest_disk(&self) -> Option<&DiskStats> {
        self.disks
            .iter()
            .max_by(|a, b| a.util_pct.total_cmp(&b.util_pct))
    }

    /// Interfaces that count towards totals: physical ones, or - when there
    /// are none, as inside a container whose `eth0` is a veth - every
    /// interface except loopback.
    pub fn counted_nets(&self) -> impl Iterator<Item = &NetStats> {
        let any_physical = self.nets.iter().any(|n| !n.is_virtual);
        self.nets.iter().filter(move |n| {
            if any_physical {
                !n.is_virtual
            } else {
                n.name != "lo"
            }
        })
    }

    /// (rx B/s, tx B/s, errors/s, drops/s) over [`Snapshot::counted_nets`].
    pub fn net_total(&self) -> Option<(f64, f64, f64, f64)> {
        if !self.nets_available || self.interval.is_none() {
            return None;
        }
        Some(self.counted_nets().fold((0.0, 0.0, 0.0, 0.0), |a, n| {
            (
                a.0 + n.rx_bps,
                a.1 + n.tx_bps,
                a.2 + n.rx_errs_per_s + n.tx_errs_per_s,
                a.3 + n.rx_drop_per_s + n.tx_drop_per_s,
            )
        }))
    }

    /// The writable filesystem with the highest usage.
    pub fn fullest_fs(&self) -> Option<&FsStats> {
        self.filesystems
            .iter()
            .filter(|f| !f.readonly)
            .max_by(|a, b| {
                a.used_pct()
                    .unwrap_or(0.0)
                    .total_cmp(&b.used_pct().unwrap_or(0.0))
            })
    }
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/// Metric groups that can be selected for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Cpu,
    Memory,
    Disk,
    Network,
    Tcp,
    Filesystem,
    Pressure,
}

impl Group {
    pub const ALL: [Group; 7] = [
        Group::Cpu,
        Group::Memory,
        Group::Disk,
        Group::Network,
        Group::Tcp,
        Group::Filesystem,
        Group::Pressure,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Group::Cpu => "cpu",
            Group::Memory => "memory",
            Group::Disk => "disk",
            Group::Network => "network",
            Group::Tcp => "tcp",
            Group::Filesystem => "filesystem",
            Group::Pressure => "pressure",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Group::Cpu => "CPU usage, iowait, steal, load average",
            Group::Memory => "RAM, swap, swap activity, OOM kills",
            Group::Disk => "Disk throughput, IOPS, max utilisation",
            Group::Network => "Network RX/TX, errors, drops",
            Group::Tcp => "TCP connections and retransmissions",
            Group::Filesystem => "Highest filesystem space/inode usage",
            Group::Pressure => "Pressure stall information (PSI)",
        }
    }

    pub fn from_key(key: &str) -> Option<Group> {
        Group::ALL.into_iter().find(|g| g.key() == key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Percent,
    Bytes,
    BytesPerSec,
    PerSec,
    Count,
    Load,
}

impl Unit {
    pub fn format(self, v: f64) -> String {
        match self {
            Unit::Percent => util::fmt_pct(v),
            Unit::Bytes => util::fmt_bytes(v),
            Unit::BytesPerSec => util::fmt_rate(v),
            Unit::PerSec => format!("{}/s", util::fmt_count(v)),
            Unit::Count => util::fmt_count(v),
            Unit::Load => format!("{v:.2}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FieldInfo {
    pub key: &'static str,
    pub group: Group,
    pub label: &'static str,
    pub unit: Unit,
}

/// Write whole numbers without a fractional part (`1024` instead of
/// `1024.0`) to keep stored lines short.
fn compact_number<S: serde::Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(x) if x.fract() == 0.0 && x.abs() < 9.0e15 => s.serialize_i64(*x as i64),
        Some(x) => s.serialize_f64(*x),
        None => s.serialize_none(),
    }
}

macro_rules! record_fields {
    ($( $name:ident : $group:ident, $unit:ident, $label:literal; )*) => {
        /// Flat summary of a snapshot. Every metric is optional: absent means
        /// "not measured" (unavailable, or not selected for logging).
        #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
        pub struct Record {
            /// Unix time in seconds.
            pub t: i64,
            $(
                #[serde(
                    default,
                    skip_serializing_if = "Option::is_none",
                    serialize_with = "compact_number"
                )]
                pub $name: Option<f64>,
            )*
        }

        /// Metadata for every metric field of [`Record`], in column order.
        pub const FIELDS: &[FieldInfo] = &[
            $( FieldInfo {
                key: stringify!($name),
                group: Group::$group,
                label: $label,
                unit: Unit::$unit,
            }, )*
        ];

        impl Record {
            pub fn get(&self, key: &str) -> Option<f64> {
                match key {
                    $( stringify!($name) => self.$name, )*
                    _ => None,
                }
            }

            fn clear_group(&mut self, group: Group) {
                $( if Group::$group == group { self.$name = None; } )*
            }
        }
    };
}

record_fields! {
    cpu: Cpu, Percent, "CPU busy";
    iowait: Cpu, Percent, "CPU iowait";
    steal: Cpu, Percent, "CPU steal";
    load1: Cpu, Load, "Load 1m";
    load5: Cpu, Load, "Load 5m";
    load15: Cpu, Load, "Load 15m";
    procs_blocked: Cpu, Count, "Tasks blocked on I/O";
    mem_used: Memory, Bytes, "Memory used";
    mem_avail: Memory, Bytes, "Memory available";
    mem_total: Memory, Bytes, "Memory total";
    swap_used: Memory, Bytes, "Swap used";
    swap_total: Memory, Bytes, "Swap total";
    swap_in: Memory, PerSec, "Swap-in pages";
    swap_out: Memory, PerSec, "Swap-out pages";
    major_faults: Memory, PerSec, "Major page faults";
    oom_kills: Memory, Count, "OOM kills (since boot)";
    disk_read: Disk, BytesPerSec, "Disk read";
    disk_write: Disk, BytesPerSec, "Disk write";
    disk_read_iops: Disk, PerSec, "Disk read IOPS";
    disk_write_iops: Disk, PerSec, "Disk write IOPS";
    disk_util_max: Disk, Percent, "Busiest disk utilisation";
    net_rx: Network, BytesPerSec, "Network RX";
    net_tx: Network, BytesPerSec, "Network TX";
    net_errors: Network, PerSec, "Network errors";
    net_drops: Network, PerSec, "Network drops";
    nic_rx_overruns: Network, PerSec, "NIC receive overruns";
    nic_rx_corrupt: Network, PerSec, "Corrupted frames received";
    softnet_drops: Network, PerSec, "Receive backlog drops";
    udp_buf_errors: Network, PerSec, "UDP receive buffer drops";
    conntrack_pct: Network, Percent, "Conntrack table usage";
    conntrack_drops: Network, PerSec, "Conntrack drops";
    tcp_estab: Tcp, Count, "TCP established";
    tcp_time_wait: Tcp, Count, "TCP TIME_WAIT";
    tcp_retrans: Tcp, PerSec, "TCP retransmits";
    tcp_retrans_pct: Tcp, Percent, "TCP retransmit ratio";
    tcp_listen_drops: Tcp, PerSec, "TCP listen drops";
    tcp_rcv_drops: Tcp, PerSec, "TCP receive-side drops";
    fs_used_max: Filesystem, Percent, "Fullest filesystem";
    fs_inodes_max: Filesystem, Percent, "Highest inode usage";
    psi_cpu: Pressure, Percent, "CPU pressure (some, 10s)";
    psi_mem: Pressure, Percent, "Memory pressure (some, 10s)";
    psi_io: Pressure, Percent, "I/O pressure (some, 10s)";
}

impl Record {
    pub fn from_snapshot(s: &Snapshot) -> Record {
        let r2 = |v: f64| Some(util::round2(v));
        let mut r = Record {
            t: s.time as i64,
            ..Default::default()
        };
        if let Some(c) = &s.cpu {
            if let Some(u) = &c.total {
                r.cpu = r2(u.busy);
                r.iowait = r2(u.iowait);
                r.steal = r2(u.steal);
            }
            r.procs_blocked = c.procs_blocked.map(|v| v as f64);
        }
        if let Some(l) = &s.load {
            r.load1 = Some(l.one);
            r.load5 = Some(l.five);
            r.load15 = Some(l.fifteen);
        }
        if let Some(m) = &s.mem {
            r.mem_used = Some(m.info.used() as f64);
            r.mem_avail = m.info.available.map(|v| v as f64);
            r.mem_total = Some(m.info.total as f64);
            r.swap_used = Some(m.info.swap_used() as f64);
            r.swap_total = Some(m.info.swap_total as f64);
            r.swap_in = m.swap_in_per_s.map(util::round2);
            r.swap_out = m.swap_out_per_s.map(util::round2);
            r.major_faults = m.major_faults_per_s.map(util::round2);
            r.oom_kills = m.oom_kills.map(|v| v as f64);
        }
        if let Some((rd, wr, ri, wi)) = s.disk_total() {
            r.disk_read = Some(rd.round());
            r.disk_write = Some(wr.round());
            r.disk_read_iops = r2(ri);
            r.disk_write_iops = r2(wi);
            r.disk_util_max = r2(s.busiest_disk().map_or(0.0, |d| d.util_pct));
        }
        if let Some((rx, tx, errs, drops)) = s.net_total() {
            r.net_rx = Some(rx.round());
            r.net_tx = Some(tx.round());
            r.net_errors = r2(errs);
            r.net_drops = r2(drops);
        }
        let nd = &s.net_diag;
        if s.interval.is_some() && s.nets_available {
            let sum = |f: fn(&IfaceDiag) -> f64| r2(nd.ifaces.iter().map(f).sum());
            r.nic_rx_overruns = sum(|i| i.rx_overrun);
            r.nic_rx_corrupt = sum(|i| i.rx_corrupt);
        }
        if nd.softnet_available && s.interval.is_some() {
            r.softnet_drops = r2(nd.softnet_drops());
        }
        r.udp_buf_errors = nd.udp.map(|u| util::round2(u.rcvbuf_errors));
        if let Some(ct) = nd.conntrack {
            r.conntrack_pct = ct.used_pct().map(util::round2);
            r.conntrack_drops = ct.drop.map(util::round2);
        }
        r.tcp_rcv_drops = nd.tcp.map(|t| util::round2(t.receive_drops()));
        if let Some(t) = &s.tcp {
            r.tcp_estab = Some(t.established as f64);
            r.tcp_time_wait = t.sockets.tcp_tw.map(|v| v as f64);
            if s.interval.is_some() {
                r.tcp_retrans = r2(t.retrans_per_s);
                r.tcp_retrans_pct = t.retrans_pct().map(util::round2);
                r.tcp_listen_drops = t.listen_drops_per_s.map(util::round2);
            }
        }
        if s.fs_available {
            let writable = || s.filesystems.iter().filter(|f| !f.readonly);
            r.fs_used_max = writable()
                .filter_map(FsStats::used_pct)
                .reduce(f64::max)
                .map(util::round2);
            r.fs_inodes_max = writable()
                .filter_map(FsStats::inode_pct)
                .reduce(f64::max)
                .map(util::round2);
        }
        r.psi_cpu = s.psi_cpu.map(|p| p.some_avg10);
        r.psi_mem = s.psi_mem.map(|p| p.some_avg10);
        r.psi_io = s.psi_io.map(|p| p.some_avg10);
        r
    }

    /// Drop every metric whose group is not in `groups`.
    pub fn retain_groups(&mut self, groups: &[Group]) {
        for g in Group::ALL {
            if !groups.contains(&g) {
                self.clear_group(g);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            time: 1_700_000_000.4,
            interval: Some(2.0),
            cpu: Some(CpuStats {
                total: Some(CpuUsage {
                    busy: 42.123,
                    iowait: 3.0,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            mem: Some(MemStats {
                info: MemInfo {
                    total: 1000,
                    available: Some(400),
                    ..Default::default()
                },
                ..Default::default()
            }),
            disks_available: true,
            disks: vec![
                DiskStats {
                    name: "sda".into(),
                    read_bps: 100.0,
                    util_pct: 50.0,
                    ..Default::default()
                },
                DiskStats {
                    name: "dm-0".into(),
                    read_bps: 100.0,
                    util_pct: 60.0,
                    stacked: true,
                    ..Default::default()
                },
            ],
            fs_available: true,
            filesystems: vec![
                FsStats {
                    used: 90,
                    avail: 10,
                    ..Default::default()
                },
                FsStats {
                    used: 99,
                    avail: 1,
                    readonly: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn record_from_snapshot() {
        let r = Record::from_snapshot(&sample_snapshot());
        assert_eq!(r.t, 1_700_000_000);
        assert_eq!(r.cpu, Some(42.12));
        assert_eq!(r.mem_used, Some(600.0));
        // Stacked device is not counted twice, but utilisation uses the max.
        assert_eq!(r.disk_read, Some(100.0));
        assert_eq!(r.disk_util_max, Some(60.0));
        // Read-only filesystems are ignored for "fullest".
        assert_eq!(r.fs_used_max, Some(90.0));
        // Unavailable sources stay absent.
        assert_eq!(r.net_rx, None);
        assert_eq!(r.tcp_estab, None);
    }

    #[test]
    fn net_totals_skip_virtual_or_fall_back_in_containers() {
        let nic = |name: &str, virt: bool, rx: f64| NetStats {
            name: name.into(),
            is_virtual: virt,
            rx_bps: rx,
            ..Default::default()
        };
        let mut s = Snapshot {
            interval: Some(1.0),
            nets_available: true,
            nets: vec![
                nic("eth0", false, 10.0),
                nic("docker0", true, 5.0),
                nic("lo", true, 7.0),
            ],
            ..Default::default()
        };
        assert_eq!(s.net_total().unwrap().0, 10.0);
        // Container: only a veth and loopback.
        s.nets = vec![nic("eth0", true, 3.0), nic("lo", true, 7.0)];
        assert_eq!(s.net_total().unwrap().0, 3.0);
    }

    #[test]
    fn first_sample_has_no_rates() {
        let mut s = sample_snapshot();
        s.interval = None;
        s.cpu.as_mut().unwrap().total = None;
        let r = Record::from_snapshot(&s);
        assert_eq!(r.cpu, None);
        assert_eq!(r.disk_read, None);
        assert_eq!(r.mem_used, Some(600.0));
    }

    #[test]
    fn retain_groups_clears_others() {
        let mut r = Record::from_snapshot(&sample_snapshot());
        r.retain_groups(&[Group::Memory]);
        assert_eq!(r.cpu, None);
        assert_eq!(r.disk_read, None);
        assert_eq!(r.mem_used, Some(600.0));
    }

    #[test]
    fn record_json_skips_missing() {
        let r = Record {
            t: 5,
            cpu: Some(1.5),
            ..Default::default()
        };
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#"{"t":5,"cpu":1.5}"#);
        let back: Record = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
        // Whole numbers are written without ".0" and read back as f64.
        let whole = Record {
            t: 5,
            mem_used: Some(1024.0),
            ..Default::default()
        };
        let j = serde_json::to_string(&whole).unwrap();
        assert_eq!(j, r#"{"t":5,"mem_used":1024}"#);
        assert_eq!(serde_json::from_str::<Record>(&j).unwrap(), whole);
        // Unknown keys from future versions are ignored.
        let fut: Record = serde_json::from_str(r#"{"t":1,"new_metric":3}"#).unwrap();
        assert_eq!(fut.t, 1);
    }

    #[test]
    fn field_lookup() {
        let r = Record {
            t: 0,
            net_rx: Some(7.0),
            ..Default::default()
        };
        assert_eq!(r.get("net_rx"), Some(7.0));
        assert_eq!(r.get("nope"), None);
        let info = FIELDS.iter().find(|f| f.key == "net_rx").unwrap();
        assert_eq!(info.group, Group::Network);
        assert!(
            FIELDS
                .iter()
                .all(|f| Group::from_key(f.group.key()).is_some())
        );
    }
}
