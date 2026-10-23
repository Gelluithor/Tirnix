//! One-shot text report (`tirnix report`): samples for a few seconds, then
//! prints a summary and the diagnostics that apply to that period.

use std::fmt::Write as _;
use std::time::Duration;

use crate::collect::{self, Collector};
use crate::diagnose::{self, Engine};
use crate::metrics::{Record, Snapshot};
use crate::util::*;
use crate::window::Window;

pub fn run(seconds: u64, include_network_fs: bool) -> String {
    let seconds = seconds.max(1);
    let mut c = Collector::new(collect::Options {
        processes: true,
        process_io: true,
        filesystems: true,
        include_network_fs,
    });
    let mut w = Window::new(seconds as usize + 2);
    let mut s = c.sample();
    w.push(Record::from_snapshot(&s));
    for _ in 0..seconds {
        std::thread::sleep(Duration::from_secs(1));
        s = c.sample();
        w.push(Record::from_snapshot(&s));
    }
    // Sustained rules look at the whole sampled period.
    let mut engine = Engine::new(seconds as i64);
    let findings = engine.evaluate(&s, &w);
    render(&s, &findings, seconds)
}

fn render(s: &Snapshot, findings: &[diagnose::Finding], seconds: u64) -> String {
    let mut o = String::new();
    let h = &s.host;
    let _ = writeln!(
        o,
        "Tirnix report — {} ({}), {} CPUs, up {}",
        h.hostname,
        h.kernel,
        h.ncpu,
        h.uptime.map_or("n/a".into(), fmt_duration)
    );
    let _ = writeln!(
        o,
        "Sampled for {seconds} s at {}\n",
        fmt_local_datetime(s.time as i64)
    );

    match s.cpu.as_ref().and_then(|c| c.total) {
        Some(u) => {
            let _ = writeln!(
                o,
                "CPU      {} busy (user {}, system {}, iowait {}, steal {})",
                fmt_pct(u.busy),
                fmt_pct(u.user + u.nice),
                fmt_pct(u.system + u.irq),
                fmt_pct(u.iowait),
                fmt_pct(u.steal)
            );
        }
        None => {
            let _ = writeln!(o, "CPU      n/a");
        }
    }
    if let Some(l) = s.load {
        let _ = writeln!(o, "Load     {:.2} {:.2} {:.2}", l.one, l.five, l.fifteen);
    }
    match &s.mem {
        Some(m) => {
            let _ = writeln!(
                o,
                "Memory   {} used of {} ({} available)",
                fmt_bytes(m.info.used() as f64),
                fmt_bytes(m.info.total as f64),
                m.info
                    .available
                    .map_or("n/a".into(), |a| fmt_bytes(a as f64))
            );
            let _ = writeln!(
                o,
                "Swap     {} used of {}",
                fmt_bytes(m.info.swap_used() as f64),
                fmt_bytes(m.info.swap_total as f64)
            );
        }
        None => {
            let _ = writeln!(o, "Memory   n/a");
        }
    }
    match s.disk_total() {
        Some((r, wr, ri, wi)) => {
            let _ = writeln!(
                o,
                "Disk     read {} ({ri:.0} IOPS), write {} ({wi:.0} IOPS)",
                fmt_rate(r),
                fmt_rate(wr)
            );
        }
        None => {
            let _ = writeln!(o, "Disk     n/a");
        }
    }
    match s.net_total() {
        Some((rx, tx, e, d)) => {
            let _ = writeln!(
                o,
                "Network  rx {}, tx {}, errors {e:.1}/s, drops {d:.1}/s",
                fmt_rate(rx),
                fmt_rate(tx)
            );
        }
        None => {
            let _ = writeln!(o, "Network  n/a");
        }
    }
    if let Some(t) = &s.tcp {
        let _ = writeln!(
            o,
            "TCP      {} established, retransmits {:.1}/s ({})",
            t.established,
            t.retrans_per_s,
            opt_pct(t.retrans_pct())
        );
    }
    if !s.filesystems.is_empty() {
        let _ = writeln!(o, "\nFilesystems:");
        for f in &s.filesystems {
            let _ = writeln!(
                o,
                "  {:<24} {:>6} of {:>9}  inodes {:>6}{}",
                f.mount_point,
                opt_pct(f.used_pct()),
                fmt_bytes(f.total as f64),
                opt_pct(f.inode_pct()),
                if f.readonly { "  (ro)" } else { "" }
            );
        }
    }

    let _ = writeln!(o);
    if !diagnose::has_data(s) {
        let _ = writeln!(
            o,
            "Diagnostics: not evaluated — no system data could be read."
        );
    } else if findings.is_empty() {
        let _ = writeln!(
            o,
            "Diagnostics: no anomalies detected during the sampled period."
        );
    } else {
        let _ = writeln!(o, "Diagnostics ({}):", findings.len());
        for f in findings {
            let _ = writeln!(o, "\n[{}] {}", f.severity.label(), f.title);
            for x in &f.facts {
                let _ = writeln!(o, "  measured: {x}");
            }
            for x in &f.causes {
                let _ = writeln!(o, "  possible cause: {x}");
            }
            for x in &f.checks {
                let _ = writeln!(o, "  verify: {x}");
            }
        }
    }
    let missing: Vec<String> = diagnose::coverage(s)
        .into_iter()
        .filter(|(_, ok, _)| !ok)
        .map(|(n, _, note)| {
            if note.is_empty() {
                n.to_string()
            } else {
                format!("{n} ({note})")
            }
        })
        .collect();
    if !missing.is_empty() {
        let _ = writeln!(o, "\nUnavailable data sources: {}", missing.join("; "));
    }
    o
}
