//! Network drop analysis: find out *where* packets are lost and, when
//! possible, *who* is affected.
//!
//! Cheap counters (`/proc/net/softnet_stat`, SNMP counters, conntrack) are
//! read on every sample. The expensive sources are read only while the cheap
//! ones show a problem ("escalation"), and at most every few seconds:
//!
//! * `/sys/class/net/<iface>/statistics/*` for interfaces with recent drops
//!   or errors (classifies them: corrupted frames, NIC overruns, no handler);
//! * `/proc/interrupts` for those interfaces (which CPUs handle them);
//! * `/proc/net/udp{,6}` when UDP receive buffers overflow (which sockets);
//! * `/proc/net/tcp{,6}` when listen queues overflow (which listeners);
//! * `/proc/<pid>/fd` to map those sockets to processes.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use super::procfs::parse_snmp_table;
use super::read_into;
use crate::metrics::*;

/// How long an interface stays under closer watch after its last drop.
const WATCH_FOR: Duration = Duration::from_secs(600);
/// Minimum time between two scans of the socket tables.
const SCAN_EVERY: Duration = Duration::from_secs(5);
/// How long socket owners are cached.
const OWNER_TTL: Duration = Duration::from_secs(60);
/// Retransmission level at which connections are inspected.
const RETRANS_SCAN_MIN_PER_S: f64 = 5.0;
const RETRANS_SCAN_RATIO: f64 = 0.02;

fn v4_counter(t: &HashMap<String, HashMap<String, i64>>, sec: &str, key: &str) -> Option<u64> {
    t.get(sec)
        .and_then(|m| m.get(key))
        .map(|v| (*v).max(0) as u64)
}

// ---------------------------------------------------------------------------
// Parsers (pure)
// ---------------------------------------------------------------------------

/// `/proc/net/softnet_stat`: per CPU (cpu, dropped, time_squeeze). Values are
/// hexadecimal; newer kernels append the CPU number as the 13th column.
pub fn parse_softnet(text: &str) -> Vec<(usize, u64, u64)> {
    text.lines()
        .enumerate()
        .filter_map(|(row, line)| {
            let f: Vec<&str> = line.split_ascii_whitespace().collect();
            let hex = |i: usize| f.get(i).and_then(|v| u64::from_str_radix(v, 16).ok());
            let cpu = if f.len() >= 13 {
                hex(12).map_or(row, |c| c as usize)
            } else {
                row
            };
            Some((cpu, hex(1)?, hex(2)?))
        })
        .collect()
}

/// `/proc/net/snmp6`: `Name Value` lines.
pub fn parse_snmp6(text: &str) -> HashMap<String, u64> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_ascii_whitespace();
            Some((it.next()?.to_string(), it.next()?.parse().ok()?))
        })
        .collect()
}

/// `/proc/net/stat/nf_conntrack`: hexadecimal per-CPU rows under a header;
/// returns column totals (the `entries` column is global, not summed).
pub fn parse_conntrack_stat(text: &str) -> HashMap<String, u64> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return HashMap::new();
    };
    let names: Vec<&str> = header.split_ascii_whitespace().collect();
    let mut out: HashMap<String, u64> = HashMap::new();
    for line in lines {
        for (name, v) in names.iter().zip(line.split_ascii_whitespace()) {
            let Ok(v) = u64::from_str_radix(v, 16) else {
                continue;
            };
            let e = out.entry((*name).to_string()).or_default();
            if *name == "entries" {
                *e = v;
            } else {
                *e += v;
            }
        }
    }
    out
}

/// `/proc/interrupts`: rows of (irq, per-CPU counts, description).
pub fn parse_interrupts(text: &str) -> Vec<(String, Vec<u64>, String)> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let ncpu = header.split_ascii_whitespace().count();
    lines
        .filter_map(|line| {
            let (irq, rest) = line.split_once(':')?;
            let mut f = rest.split_ascii_whitespace();
            let mut counts = Vec::with_capacity(ncpu);
            for _ in 0..ncpu {
                counts.push(f.next()?.parse().ok()?);
            }
            let desc: Vec<&str> = f.collect();
            Some((irq.trim().to_string(), counts, desc.join(" ")))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockRow {
    pub local: String,
    pub remote: String,
    pub state: u8,
    pub uid: u32,
    /// Unacknowledged retransmissions of this socket right now.
    pub retransmits: u64,
    pub rx_queue: u64,
    pub inode: u64,
    /// Only in the UDP tables.
    pub drops: Option<u64>,
}

/// Decode an address as printed in `/proc/net/{tcp,udp}{,6}`: 32-bit words
/// in host byte order.
fn decode_addr(hex: &str) -> Option<String> {
    let (addr, port) = hex.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::to_ne_bytes);
    match addr.len() {
        8 => Some(format!("{}:{port}", Ipv4Addr::from(word(addr)?))),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(&addr[i * 8..i * 8 + 8])?);
            }
            let ip = Ipv6Addr::from(b);
            match ip.to_ipv4_mapped() {
                Some(v4) => Some(format!("{v4}:{port}")),
                None => Some(format!("[{ip}]:{port}")),
            }
        }
        _ => None,
    }
}

/// Parse `/proc/net/tcp`, `tcp6`, `udp` or `udp6`.
pub fn parse_sock_table(text: &str) -> Vec<SockRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_ascii_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let (_, rx) = f[4].split_once(':')?;
            Some(SockRow {
                local: decode_addr(f[1])?,
                remote: decode_addr(f[2])?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                uid: f[7].parse().ok()?,
                retransmits: u64::from_str_radix(f[6], 16).unwrap_or(0),
                rx_queue: u64::from_str_radix(rx, 16).ok()?,
                inode: f[9].parse().ok()?,
                drops: f.get(12).and_then(|v| v.parse().ok()),
            })
        })
        .collect()
}

const TCP_SYN_SENT: u8 = 0x02;
const TCP_LISTEN: u8 = 0x0A;

/// Counters from `/sys/class/net/<iface>/statistics` (missing files are 0:
/// a counter the driver does not provide has not counted anything).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfaceCounters {
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_corrupt: u64,
    pub rx_overrun: u64,
    pub rx_nohandler: u64,
    pub tx_errors: u64,
}

fn read_iface_counters(name: &str, buf: &mut String) -> Option<IfaceCounters> {
    let base = format!("/sys/class/net/{name}/statistics");
    if !Path::new(&base).is_dir() {
        return None;
    }
    let mut get = |f: &str| -> u64 {
        read_into(&format!("{base}/{f}"), buf)
            .ok()
            .and_then(|_| buf.trim().parse().ok())
            .unwrap_or(0)
    };
    Some(IfaceCounters {
        rx_dropped: get("rx_dropped"),
        tx_dropped: get("tx_dropped"),
        rx_corrupt: get("rx_crc_errors") + get("rx_frame_errors") + get("rx_length_errors"),
        rx_overrun: get("rx_missed_errors") + get("rx_over_errors") + get("rx_fifo_errors"),
        rx_nohandler: get("rx_nohandler"),
        tx_errors: get("tx_carrier_errors") + get("tx_aborted_errors") + get("tx_fifo_errors"),
    })
}

/// IRQ numbers and name fragments that identify an interface's interrupts.
fn iface_irq_keys(name: &str) -> (HashSet<String>, Vec<String>) {
    let dev = Path::new("/sys/class/net").join(name).join("device");
    let mut irqs = HashSet::new();
    if let Ok(rd) = fs::read_dir(dev.join("msi_irqs")) {
        irqs.extend(
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok()),
        );
    }
    if let Ok(s) = fs::read_to_string(dev.join("irq")) {
        let s = s.trim();
        if !s.is_empty() && s != "0" {
            irqs.insert(s.to_string());
        }
    }
    // Many drivers name their queues after the interface ("eth0-TxRx-0") or
    // the bus device ("virtio0-input.0").
    let mut names = vec![name.to_string()];
    if let Some(dev_name) = fs::read_link(&dev)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    {
        names.push(dev_name);
    }
    (irqs, names)
}

/// Map socket inodes to the processes holding them by scanning
/// `/proc/<pid>/fd`. Returns the owners found and whether some process
/// directories could not be inspected (permissions).
pub fn find_owners(inodes: &HashSet<u64>) -> (HashMap<u64, Owner>, bool) {
    let mut found = HashMap::new();
    let mut denied = false;
    let Ok(procs) = fs::read_dir("/proc") else {
        return (found, true);
    };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let fds = match fs::read_dir(p.path().join("fd")) {
            Ok(fds) => fds,
            Err(_) => {
                denied = true;
                continue;
            }
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let t = target.to_string_lossy();
            let Some(inode) = t
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if inodes.contains(&inode) && !found.contains_key(&inode) {
                let comm = fs::read_to_string(p.path().join("comm"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                found.insert(inode, Owner { pid, comm });
            }
        }
        if found.len() == inodes.len() {
            break;
        }
    }
    (found, denied)
}

// ---------------------------------------------------------------------------
// Stateful probe
// ---------------------------------------------------------------------------

/// Previous values of named counters, for rates.
#[derive(Default)]
struct Rates(HashMap<String, u64>);

impl Rates {
    fn rate(&mut self, key: &str, cur: u64, dt: Option<f64>) -> Option<f64> {
        let prev = match self.0.get_mut(key) {
            Some(p) => std::mem::replace(p, cur),
            None => {
                self.0.insert(key.to_string(), cur);
                return None;
            }
        };
        Some(cur.saturating_sub(prev) as f64 / dt?)
    }
}

#[derive(Default)]
pub struct NetProbe {
    rates: Rates,
    buf: String,
    /// Interfaces under closer watch, until the given time.
    watch: HashMap<String, Instant>,
    irq_prev: HashMap<String, Vec<u64>>,
    udp_drops_prev: HashMap<u64, u64>,
    udp_scan: Option<(Instant, Vec<SocketDrops>)>,
    listen_scan: Option<(Instant, Vec<ListenQueue>)>,
    retrans_scan: Option<(Instant, Vec<RetransPeer>)>,
    /// inode -> (resolved at, process, hidden by permissions)
    owners: HashMap<u64, (Instant, Option<Owner>, bool)>,
    users: Option<HashMap<u32, String>>,
}

impl NetProbe {
    /// `active` lists interfaces whose `/proc/net/dev` drop or error
    /// counters moved in this interval; `snmp` and `netstat` are the texts
    /// of `/proc/net/snmp` and `/proc/net/netstat` if readable.
    pub fn sample(
        &mut self,
        dt: Option<f64>,
        active: &[String],
        snmp: Option<&str>,
        netstat: Option<&str>,
    ) -> NetDiag {
        let now = Instant::now();
        let mut d = NetDiag::default();

        for name in active {
            self.watch.insert(name.clone(), now + WATCH_FOR);
        }
        self.watch.retain(|_, until| *until > now);
        let mut watched: Vec<String> = self.watch.keys().cloned().collect();
        watched.sort();
        for name in watched {
            if let Some(i) = self.iface(&name, dt) {
                d.ifaces.push(i);
            }
        }

        if read_into("/proc/net/softnet_stat", &mut self.buf).is_ok() {
            d.softnet_available = true;
            for (cpu, dropped, squeezed) in parse_softnet(&self.buf) {
                let dr = self.rates.rate(&format!("softnet.{cpu}.drop"), dropped, dt);
                let sq = self
                    .rates
                    .rate(&format!("softnet.{cpu}.squeeze"), squeezed, dt);
                if let (Some(dropped), Some(squeezed)) = (dr, sq)
                    && (dropped > 0.0 || squeezed > 0.0)
                {
                    d.softnet.push(SoftnetCpu {
                        cpu,
                        dropped,
                        squeezed,
                    });
                }
            }
        }

        let snmp6 = read_into("/proc/net/snmp6", &mut self.buf)
            .ok()
            .map(|_| parse_snmp6(&self.buf))
            .unwrap_or_default();
        let mut retransmitting = false;
        if let Some(text) = snmp {
            let t = parse_snmp_table(text);
            let retr = v4_counter(&t, "Tcp", "RetransSegs")
                .and_then(|v| self.rates.rate("tcp.RetransSegs", v, dt));
            let out = v4_counter(&t, "Tcp", "OutSegs")
                .and_then(|v| self.rates.rate("tcp.OutSegs", v, dt));
            if let (Some(r), Some(o)) = (retr, out) {
                retransmitting = r >= RETRANS_SCAN_MIN_PER_S && r >= o * RETRANS_SCAN_RATIO;
            }
            let v4 = |sec: &str, k: &str| {
                t.get(sec)
                    .and_then(|m| m.get(k))
                    .map(|v| (*v).max(0) as u64)
            };
            let v6 = |k: &str| snmp6.get(k).copied().unwrap_or(0);
            if v4("Udp", "RcvbufErrors").is_some() {
                let mut r = |k: &str| {
                    let total = v4("Udp", k).unwrap_or(0) + v6(&format!("Udp6{k}"));
                    self.rates.rate(&format!("udp.{k}"), total, dt)
                };
                if let (Some(rcv), Some(snd), Some(inerr), Some(noports)) = (
                    r("RcvbufErrors"),
                    r("SndbufErrors"),
                    r("InErrors"),
                    r("NoPorts"),
                ) {
                    d.udp = Some(UdpDiag {
                        rcvbuf_errors: rcv,
                        sndbuf_errors: snd,
                        in_errors: inerr,
                        no_ports: noports,
                    });
                }
            }
            if v4("Ip", "InDiscards").is_some() {
                let mut r = |k: &str, k6: &str| {
                    let total = v4("Ip", k).unwrap_or(0) + v6(k6);
                    self.rates.rate(&format!("ip.{k}"), total, dt)
                };
                let vals = [
                    r("InDiscards", "Ip6InDiscards"),
                    r("InHdrErrors", "Ip6InHdrErrors"),
                    r("InAddrErrors", "Ip6InAddrErrors"),
                    r("ReasmFails", "Ip6ReasmFails"),
                    r("OutDiscards", "Ip6OutDiscards"),
                ];
                if let [Some(a), Some(b), Some(c), Some(e), Some(f)] = vals {
                    d.ip = Some(IpDiag {
                        in_discards: a,
                        in_hdr_errors: b,
                        in_addr_errors: c,
                        reasm_fails: e,
                        out_discards: f,
                    });
                }
            }
        }
        let mut listen_dropping = false;
        if let Some(text) = netstat {
            let t = parse_snmp_table(text);
            if let Some(ext) = t.get("TcpExt") {
                let drops = ext.get("ListenDrops").map_or(0, |v| (*v).max(0) as u64);
                listen_dropping = self
                    .rates
                    .rate("tcpext.ListenDrops", drops, dt)
                    .is_some_and(|r| r > 0.0);
                let mut r = |k: &str| {
                    let v = ext.get(k).map_or(0, |v| (*v).max(0) as u64);
                    self.rates.rate(&format!("tcpext.{k}"), v, dt)
                };
                let vals = [
                    r("TCPBacklogDrop"),
                    r("TCPRcvQDrop"),
                    r("TCPZeroWindowDrop"),
                    r("RcvPruned"),
                    r("TCPOFODrop"),
                    r("TCPMemoryPressures"),
                    r("TCPReqQFullDrop"),
                    r("TCPSynRetrans"),
                ];
                if let [
                    Some(a),
                    Some(b),
                    Some(c),
                    Some(e),
                    Some(f),
                    Some(g),
                    Some(h),
                    Some(i),
                ] = vals
                {
                    d.tcp = Some(TcpDropDiag {
                        backlog_drop: a,
                        rcvq_drop: b,
                        zero_window_drop: c,
                        pruned: e,
                        ofo_drop: f,
                        mem_pressures: g,
                        reqq_full_drop: h,
                        syn_retrans: i,
                    });
                }
            }
        }

        d.conntrack = self.conntrack(dt);

        // Escalation: which sockets / listeners are affected.
        let udp_dropping = d.udp.is_some_and(|u| u.rcvbuf_errors > 0.0);
        if udp_dropping {
            if self
                .udp_scan
                .as_ref()
                .is_none_or(|(t, ..)| t.elapsed() >= SCAN_EVERY)
            {
                let socks = self.scan_udp(now);
                self.udp_scan = Some((now, socks));
            }
        } else if self
            .udp_scan
            .as_ref()
            .is_some_and(|(t, ..)| t.elapsed() > WATCH_FOR)
        {
            self.udp_scan = None;
        }
        if let Some((_, socks)) = &self.udp_scan {
            d.udp_sockets = socks.clone();
        }

        if listen_dropping {
            if self
                .listen_scan
                .as_ref()
                .is_none_or(|(t, ..)| t.elapsed() >= SCAN_EVERY)
            {
                let l = self.scan_listeners(now);
                self.listen_scan = Some((now, l));
            }
        } else if self
            .listen_scan
            .as_ref()
            .is_some_and(|(t, ..)| t.elapsed() > WATCH_FOR)
        {
            self.listen_scan = None;
        }
        if let Some((_, l)) = &self.listen_scan {
            d.listeners = l.clone();
        }

        // Which peers the retransmitting connections talk to.
        if retransmitting {
            if self
                .retrans_scan
                .as_ref()
                .is_none_or(|(t, _)| t.elapsed() >= SCAN_EVERY)
            {
                let p = self.scan_retrans(now);
                self.retrans_scan = Some((now, p));
            }
        } else if self
            .retrans_scan
            .as_ref()
            .is_some_and(|(t, _)| t.elapsed() > WATCH_FOR)
        {
            self.retrans_scan = None;
        }
        if let Some((_, p)) = &self.retrans_scan {
            d.retrans_peers = p.clone();
        }

        // Interrupt distribution for interfaces that overflow or when the
        // receive backlog drops: both point at RX processing on few CPUs.
        let need_irq = d.softnet.iter().any(|c| c.dropped > 0.0)
            || d.ifaces.iter().any(|i| i.rx_overrun > 0.0);
        if need_irq && read_into("/proc/interrupts", &mut self.buf).is_ok() {
            let rows = parse_interrupts(&self.buf);
            for i in &mut d.ifaces {
                i.irq = Self::irq_share(&mut self.irq_prev, &i.name, &rows, dt);
            }
        }
        d
    }

    fn iface(&mut self, name: &str, dt: Option<f64>) -> Option<IfaceDiag> {
        let c = read_iface_counters(name, &mut self.buf)?;
        let mut r = |k: &str, v: u64| self.rates.rate(&format!("if.{name}.{k}"), v, dt);
        Some(IfaceDiag {
            name: name.to_string(),
            rx_dropped: r("rx_dropped", c.rx_dropped)?,
            tx_dropped: r("tx_dropped", c.tx_dropped)?,
            rx_corrupt: r("rx_corrupt", c.rx_corrupt)?,
            rx_overrun: r("rx_overrun", c.rx_overrun)?,
            rx_nohandler: r("rx_nohandler", c.rx_nohandler)?,
            tx_errors: r("tx_errors", c.tx_errors)?,
            irq: None,
        })
    }

    fn irq_share(
        prev: &mut HashMap<String, Vec<u64>>,
        name: &str,
        rows: &[(String, Vec<u64>, String)],
        dt: Option<f64>,
    ) -> Option<IrqShare> {
        let (irqs, names) = iface_irq_keys(name);
        let mut per_cpu: Vec<u64> = Vec::new();
        for (irq, counts, desc) in rows {
            let ours = irqs.contains(irq)
                || desc.split_ascii_whitespace().any(|w| {
                    names
                        .iter()
                        .any(|n| w == n || w.starts_with(&format!("{n}-")))
                });
            if !ours {
                continue;
            }
            if per_cpu.len() < counts.len() {
                per_cpu.resize(counts.len(), 0);
            }
            for (i, c) in counts.iter().enumerate() {
                per_cpu[i] += c;
            }
        }
        if per_cpu.is_empty() {
            return None;
        }
        let old = prev.insert(name.to_string(), per_cpu.clone())?;
        if old.len() != per_cpu.len() {
            return None;
        }
        let delta: Vec<u64> = per_cpu
            .iter()
            .zip(&old)
            .map(|(c, p)| c.saturating_sub(*p))
            .collect();
        let total: u64 = delta.iter().sum();
        if total == 0 {
            return None;
        }
        let (top_cpu, top) = delta.iter().enumerate().max_by_key(|(_, v)| **v)?;
        Some(IrqShare {
            top_cpu,
            top_share: *top as f64 / total as f64 * 100.0,
            cpus_used: delta.iter().filter(|v| **v * 20 >= total).count(),
            per_s: total as f64 / dt?,
        })
    }

    fn conntrack(&mut self, dt: Option<f64>) -> Option<ConntrackDiag> {
        let read = |p: &str, buf: &mut String| -> Option<u64> {
            read_into(p, buf).ok()?;
            buf.trim().parse().ok()
        };
        let count = read("/proc/sys/net/netfilter/nf_conntrack_count", &mut self.buf)?;
        let max = read("/proc/sys/net/netfilter/nf_conntrack_max", &mut self.buf)?;
        let mut ct = ConntrackDiag {
            count,
            max,
            ..Default::default()
        };
        if read_into("/proc/net/stat/nf_conntrack", &mut self.buf).is_ok() {
            let st = parse_conntrack_stat(&self.buf);
            let mut r = |k: &str| {
                let v = *st.get(k)?;
                self.rates.rate(&format!("ct.{k}"), v, dt)
            };
            ct.drop = r("drop");
            ct.early_drop = r("early_drop");
            ct.insert_failed = r("insert_failed");
        }
        Some(ct)
    }

    fn user_name(&mut self, uid: u32) -> String {
        let users = self.users.get_or_insert_with(super::process::load_users);
        users.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
    }

    /// Resolve owners of `(inode, uid)` sockets, using the cache where fresh.
    fn owners_for(&mut self, socks: &[(u64, u32)], now: Instant) -> HashMap<u64, SockOwner> {
        self.owners
            .retain(|_, (t, ..)| now.duration_since(*t) < OWNER_TTL);
        let missing: HashSet<u64> = socks
            .iter()
            .map(|(i, _)| *i)
            .filter(|i| !self.owners.contains_key(i))
            .collect();
        if !missing.is_empty() {
            let (found, denied) = find_owners(&missing);
            for i in missing {
                let p = found.get(&i).cloned();
                let hidden = p.is_none() && denied;
                self.owners.insert(i, (now, p, hidden));
            }
        }
        socks
            .iter()
            .map(|(inode, uid)| {
                let (process, hidden) = self
                    .owners
                    .get(inode)
                    .map(|(_, p, h)| (p.clone(), *h))
                    .unwrap_or((None, false));
                let user = Some(self.user_name(*uid));
                (
                    *inode,
                    SockOwner {
                        process,
                        user,
                        hidden,
                    },
                )
            })
            .collect()
    }

    fn read_tables(&mut self, paths: &[&'static str]) -> Vec<(&'static str, SockRow)> {
        let mut rows = Vec::new();
        for path in paths {
            if read_into(path, &mut self.buf).is_ok() {
                let proto = path.rsplit('/').next().unwrap_or(path);
                rows.extend(parse_sock_table(&self.buf).into_iter().map(|r| (proto, r)));
            }
        }
        rows
    }

    fn scan_udp(&mut self, now: Instant) -> Vec<SocketDrops> {
        let elapsed = self
            .udp_scan
            .as_ref()
            .map(|(t, _)| now.duration_since(*t).as_secs_f64());
        let rows = self.read_tables(&["/proc/net/udp", "/proc/net/udp6"]);
        let mut out = Vec::new();
        let mut next_prev = HashMap::new();
        for (proto, r) in rows {
            let Some(total) = r.drops.filter(|d| *d > 0) else {
                continue;
            };
            next_prev.insert(r.inode, total);
            let rate = match (self.udp_drops_prev.get(&r.inode), elapsed) {
                (Some(p), Some(e)) if e > 0.0 => Some(total.saturating_sub(*p) as f64 / e),
                _ => None,
            };
            out.push((
                (r.inode, r.uid),
                SocketDrops {
                    proto,
                    local: r.local,
                    drops_per_s: rate,
                    total,
                    owner: SockOwner::default(),
                },
            ));
        }
        self.udp_drops_prev = next_prev;
        // Busiest first: by current rate, then by total.
        out.sort_by(|a, b| {
            b.1.drops_per_s
                .unwrap_or(0.0)
                .total_cmp(&a.1.drops_per_s.unwrap_or(0.0))
                .then(b.1.total.cmp(&a.1.total))
        });
        out.truncate(5);
        let keys: Vec<(u64, u32)> = out.iter().map(|(k, _)| *k).collect();
        let mut owners = self.owners_for(&keys, now);
        out.into_iter()
            .map(|((inode, _), mut s)| {
                s.owner = owners.remove(&inode).unwrap_or_default();
                s
            })
            .collect()
    }

    fn scan_listeners(&mut self, now: Instant) -> Vec<ListenQueue> {
        let mut rows: Vec<SockRow> = self
            .read_tables(&["/proc/net/tcp", "/proc/net/tcp6"])
            .into_iter()
            .map(|(_, r)| r)
            .filter(|r| r.state == TCP_LISTEN && r.rx_queue > 0)
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.rx_queue));
        rows.truncate(5);
        let keys: Vec<(u64, u32)> = rows.iter().map(|r| (r.inode, r.uid)).collect();
        let mut owners = self.owners_for(&keys, now);
        rows.into_iter()
            .map(|r| ListenQueue {
                owner: owners.remove(&r.inode).unwrap_or_default(),
                local: r.local,
                queued: r.rx_queue,
            })
            .collect()
    }

    /// Connections that currently retransmit, grouped by remote address.
    fn scan_retrans(&mut self, now: Instant) -> Vec<RetransPeer> {
        let mut groups: HashMap<String, (RetransPeer, (u64, u32))> = HashMap::new();
        for (_, r) in self.read_tables(&["/proc/net/tcp", "/proc/net/tcp6"]) {
            if r.retransmits == 0 || r.state == TCP_LISTEN {
                continue;
            }
            let g = groups.entry(r.remote.clone()).or_insert_with(|| {
                (
                    RetransPeer {
                        remote: r.remote.clone(),
                        local: r.local.clone(),
                        ..Default::default()
                    },
                    (r.inode, r.uid),
                )
            });
            g.0.sockets += 1;
            if r.state == TCP_SYN_SENT {
                g.0.connecting += 1;
            }
        }
        let mut peers: Vec<(RetransPeer, (u64, u32))> = groups.into_values().collect();
        peers.sort_by(|a, b| {
            b.0.sockets
                .cmp(&a.0.sockets)
                .then(a.0.remote.cmp(&b.0.remote))
        });
        peers.truncate(5);
        let keys: Vec<(u64, u32)> = peers.iter().map(|(_, k)| *k).collect();
        let mut owners = self.owners_for(&keys, now);
        peers
            .into_iter()
            .map(|(mut p, (inode, _))| {
                p.owner = owners.remove(&inode).unwrap_or_default();
                p
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softnet_old_and_new_formats() {
        let old = "0000a000 00000010 00000003 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
000b0000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
";
        assert_eq!(parse_softnet(old), vec![(0, 16, 3), (1, 0, 0)]);
        // 13+ columns: the last one is the CPU id (offline CPUs are skipped).
        let new = "0000a000 00000001 00000002 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004 00000000
";
        assert_eq!(parse_softnet(new), vec![(4, 1, 2)]);
    }

    #[test]
    fn snmp6_pairs() {
        let m = parse_snmp6(
            "Ip6InDiscards                   \t7\nUdp6RcvbufErrors                \t42\n",
        );
        assert_eq!(m.get("Udp6RcvbufErrors"), Some(&42));
        assert_eq!(m.get("Ip6InDiscards"), Some(&7));
    }

    #[test]
    fn conntrack_stat_sums_cpus() {
        let text = "entries  clashres found new invalid ignore delete delete_list insert insert_failed drop early_drop
00000064  00000000 00000000 00000000 00000005 00000000 00000000 00000000 00000000 00000001 0000000a 00000002
00000064  00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000005 00000000
";
        let s = parse_conntrack_stat(text);
        assert_eq!(s.get("entries"), Some(&100));
        assert_eq!(s.get("drop"), Some(&15));
        assert_eq!(s.get("early_drop"), Some(&2));
        assert_eq!(s.get("insert_failed"), Some(&1));
    }

    #[test]
    fn interrupts_rows() {
        let text = "           CPU0       CPU1       CPU2
  24:     900000         10          5   PCI-MSI 524288-edge      eth0-TxRx-0
  25:          1          2          3   PCI-MSI 524289-edge      virtio0-input.0
 NMI:          0          0          0   Non-maskable interrupts
 ERR:          0
";
        let rows = parse_interrupts(text);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, "24");
        assert_eq!(rows[0].1, vec![900_000, 10, 5]);
        assert!(rows[0].2.ends_with("eth0-TxRx-0"));
    }

    #[test]
    fn irq_share_from_deltas() {
        let mut prev = HashMap::new();
        let rows = |a: u64, b: u64| {
            vec![(
                "24".to_string(),
                vec![a, b],
                "PCI-MSI eth9-TxRx-0".to_string(),
            )]
        };
        assert!(NetProbe::irq_share(&mut prev, "eth9", &rows(1000, 10), Some(1.0)).is_none());
        let s = NetProbe::irq_share(&mut prev, "eth9", &rows(1990, 20), Some(1.0)).unwrap();
        assert_eq!(s.top_cpu, 0);
        assert!((s.top_share - 99.0).abs() < 0.01);
        assert_eq!(s.cpus_used, 1);
        assert_eq!(s.per_s, 1000.0);
    }

    #[test]
    fn socket_tables() {
        let udp = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  371: 00000000:0202 00000000:0000 07 00000000:00034000 00:00000000 00000000     0        0 31337 2 0000000000000000 1204
  372: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 4242 2 0000000000000000 0
";
        let r = parse_sock_table(udp);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].local, "0.0.0.0:514");
        assert_eq!(r[0].remote, "0.0.0.0:0");
        assert_eq!(r[1].uid, 101);
        assert_eq!(r[0].inode, 31337);
        assert_eq!(r[0].drops, Some(1204));
        assert_eq!(r[0].rx_queue, 0x34000);
        assert_eq!(r[1].local, "127.0.0.1:53");

        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000081 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 778 1 0000000000000000 100 0 0 10 0
";
        let r = parse_sock_table(tcp6);
        assert_eq!(r[0].local, "[::]:8080");
        assert_eq!(r[0].state, TCP_LISTEN);
        assert_eq!(r[0].rx_queue, 129);
        assert_eq!(r[0].inode, 777);
        // IPv4-mapped addresses are shown as IPv4.
        assert_eq!(r[1].local, "127.0.0.1:8081");
    }

    #[test]
    fn rates_need_two_values() {
        let mut r = Rates::default();
        assert_eq!(r.rate("x", 10, Some(1.0)), None);
        assert_eq!(r.rate("x", 30, Some(2.0)), Some(10.0));
        assert_eq!(r.rate("x", 5, Some(1.0)), Some(0.0));
    }

    #[test]
    fn owners_of_own_socket() {
        // A socket of this test process must be attributed to it.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let Ok(text) = fs::read_to_string("/proc/net/udp") else {
            return; // not Linux
        };
        let port = sock.local_addr().unwrap().port();
        let row = parse_sock_table(&text)
            .into_iter()
            .find(|r| r.local == format!("127.0.0.1:{port}"))
            .expect("own socket listed");
        let (owners, _) = find_owners(&HashSet::from([row.inode]));
        assert_eq!(
            owners.get(&row.inode).map(|o| o.pid),
            Some(std::process::id())
        );
    }
}
