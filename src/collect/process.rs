//! Per-process statistics from `/proc/<pid>/`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

use super::procfs::{parse_pid_io, parse_pid_stat};
use super::read_into;
use crate::metrics::{ProcInfo, ProcSummary};

#[derive(Clone, Copy)]
struct Prev {
    starttime: u64,
    ticks: u64,
    io: Option<(u64, u64)>,
}

/// Scans `/proc` and keeps the previous counters needed for rates.
#[derive(Default)]
pub struct ProcessScanner {
    prev: HashMap<u32, Prev>,
    next: HashMap<u32, Prev>,
    prev_time: Option<Instant>,
    buf: String,
    path: String,
}

impl ProcessScanner {
    pub fn scan(&mut self, with_io: bool, clk_tck: f64, page_size: u64) -> Option<ProcSummary> {
        let entries = fs::read_dir("/proc").ok()?;
        let now = Instant::now();
        let dt = self
            .prev_time
            .map(|t| now.duration_since(t).as_secs_f64())
            .filter(|d| *d > 0.0);
        let mut sum = ProcSummary {
            io_collected: with_io,
            ..Default::default()
        };
        self.next.clear();

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            self.path.clear();
            let _ = write!(self.path, "/proc/{pid}/stat");
            if read_into(&self.path, &mut self.buf).is_err() {
                continue; // process exited meanwhile
            }
            let Some(st) = parse_pid_stat(&self.buf) else {
                continue;
            };
            let uid = entry.metadata().map(|m| m.uid()).unwrap_or(u32::MAX);
            let ticks = st.utime + st.stime;

            let io = if with_io {
                self.path.clear();
                let _ = write!(self.path, "/proc/{pid}/io");
                let v = read_into(&self.path, &mut self.buf)
                    .ok()
                    .and_then(|_| parse_pid_io(&self.buf));
                if v.is_none() {
                    sum.io_denied += 1;
                }
                v
            } else {
                None
            };

            // Only compare with the previous sample if it is the same process
            // (PIDs get reused; `starttime` tells instances apart).
            let prev = self.prev.get(&pid).filter(|p| p.starttime == st.starttime);
            let cpu_pct = match (prev, dt) {
                (Some(p), Some(dt)) => {
                    let pct = ticks.saturating_sub(p.ticks) as f64 / clk_tck / dt * 100.0;
                    // Tick quantisation (10 ms) can push a busy single thread
                    // slightly above 100 %; no process can exceed its threads.
                    Some(pct.min(st.num_threads.max(1) as f64 * 100.0))
                }
                _ => None,
            };
            let (read_bps, write_bps) = match (prev.and_then(|p| p.io), io, dt) {
                (Some((pr, pw)), Some((r, w)), Some(dt)) => (
                    Some(r.saturating_sub(pr) as f64 / dt),
                    Some(w.saturating_sub(pw) as f64 / dt),
                ),
                _ => (None, None),
            };

            match st.state {
                'R' => sum.running += 1,
                'D' => sum.uninterruptible += 1,
                'Z' => sum.zombies += 1,
                _ => {}
            }
            sum.threads += st.num_threads;
            sum.list.push(ProcInfo {
                pid,
                ppid: st.ppid,
                uid,
                comm: st.comm,
                state: st.state,
                cpu_pct,
                rss: st.rss_pages * page_size,
                threads: st.num_threads,
                read_bps,
                write_bps,
            });
            self.next.insert(
                pid,
                Prev {
                    starttime: st.starttime,
                    ticks,
                    io,
                },
            );
        }
        sum.total = sum.list.len();
        std::mem::swap(&mut self.prev, &mut self.next);
        self.prev_time = Some(now);
        Some(sum)
    }
}

/// Full command line of a process, or `None` for kernel threads and
/// processes we may not inspect.
pub fn read_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let s: String = String::from_utf8_lossy(&raw)
        .chars()
        .map(|c| if c == '\0' { ' ' } else { c })
        .collect();
    Some(s.trim_end().to_string())
}

/// uid -> user name, from `/etc/passwd` (read once).
pub fn load_users() -> HashMap<u32, String> {
    fs::read_to_string("/etc/passwd")
        .map(|t| parse_passwd(&t))
        .unwrap_or_default()
}

pub fn parse_passwd(text: &str) -> HashMap<u32, String> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let _pw = f.next()?;
            let uid = f.next()?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd() {
        let u = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n# comment\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nbroken\n",
        );
        assert_eq!(u.get(&0).map(String::as_str), Some("root"));
        assert_eq!(u.get(&33).map(String::as_str), Some("www-data"));
        assert_eq!(u.len(), 2);
    }
}
