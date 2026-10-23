//! Overview: all key metrics at a glance, the most important findings and
//! the top processes.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Sparkline};

use super::super::App;
use super::super::widgets::*;
use crate::util::*;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let summary_h = 10u16;
    let spark_h = if area.height >= summary_h + 14 { 4 } else { 0 };
    let [top, sparks, bottom] = Layout::vertical([
        Constraint::Length(summary_h.min(area.height)),
        Constraint::Length(spark_h),
        Constraint::Min(0),
    ])
    .areas(area);

    draw_summary(f, top, app);
    if spark_h > 0 {
        draw_sparks(f, sparks, app);
    }
    if bottom.height >= 3 {
        if bottom.width >= 110 {
            let [l, r] =
                Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .areas(bottom);
            draw_findings(f, l, app);
            draw_top(f, r, app);
        } else if bottom.height >= 10 {
            let [a, b] = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(bottom);
            draw_findings(f, a, app);
            draw_top(f, b, app);
        } else {
            draw_findings(f, bottom, app);
        }
    }
}

fn draw_summary(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.snap;
    let inner_w = area.width.saturating_sub(2) as usize;
    let bw = (inner_w / 4).clamp(8, 30);
    let mut lines = Vec::new();

    let cpu = s.cpu.as_ref().and_then(|c| c.total);
    lines.push(meter(
        "CPU",
        cpu.map(|u| u.busy),
        bw,
        cpu.map_or_else(String::new, |u| {
            format!(
                "usr {} sys {} iow {} steal {}",
                fmt_pct(u.user + u.nice),
                fmt_pct(u.system + u.irq),
                fmt_pct(u.iowait),
                fmt_pct(u.steal)
            )
        }),
    ));
    match &s.mem {
        Some(m) => {
            let used = m.info.used() as f64;
            lines.push(meter(
                "MEM",
                pct(used, m.info.total as f64),
                bw,
                format!(
                    "{} / {}  avail {}",
                    fmt_bytes(used),
                    fmt_bytes(m.info.total as f64),
                    m.info
                        .available
                        .map_or("n/a".into(), |a| fmt_bytes(a as f64))
                ),
            ));
            let swap_detail = if m.info.swap_total == 0 {
                "no swap configured".to_string()
            } else {
                format!(
                    "{} / {}  in {} out {} pg/s",
                    fmt_bytes(m.info.swap_used() as f64),
                    fmt_bytes(m.info.swap_total as f64),
                    opt_count(m.swap_in_per_s),
                    opt_count(m.swap_out_per_s)
                )
            };
            lines.push(meter(
                "SWAP",
                pct(m.info.swap_used() as f64, m.info.swap_total as f64),
                bw,
                swap_detail,
            ));
        }
        None => {
            lines.push(super::unavailable("Memory"));
            lines.push(Line::from(""));
        }
    }

    let mut load = vec![Span::styled("LOAD ", bold())];
    match s.load {
        Some(l) => {
            let per = l.one / s.host.ncpu.max(1) as f64;
            load.push(Span::styled(
                format!("{:.2}", l.one),
                level(per * 100.0 / 1.5),
            ));
            load.push(Span::raw(format!(" {:.2} {:.2}", l.five, l.fifteen)));
            load.push(Span::styled(format!("  on {} CPUs", s.host.ncpu), dim()));
        }
        None => load.push(na()),
    }
    if let Some(p) = &s.procs {
        load.push(Span::styled("   tasks ", dim()));
        load.push(Span::raw(format!("{}", p.total)));
        load.push(Span::styled("  running ", dim()));
        load.push(Span::raw(format!("{}", p.running)));
        load.push(Span::styled("  D ", dim()));
        load.push(Span::styled(
            format!("{}", p.uninterruptible),
            if p.uninterruptible > 0 {
                level(75.0)
            } else {
                ratatui::style::Style::new()
            },
        ));
        if p.zombies > 0 {
            load.push(Span::styled("  zombie ", dim()));
            load.push(Span::raw(format!("{}", p.zombies)));
        }
    }
    lines.push(Line::from(load));

    let mut disk = vec![Span::styled("DISK ", bold())];
    match s.disk_total() {
        Some((r, w, ri, wi)) => {
            disk.extend(kv("read", fmt_rate(r)));
            disk.extend(kv("  write", fmt_rate(w)));
            disk.extend(kv("  IOPS", format!("{}/{}", fmt_count(ri), fmt_count(wi))));
            if let Some(b) = s.busiest_disk() {
                disk.push(Span::styled("  busiest ", dim()));
                disk.push(Span::raw(format!("{} ", b.label)));
                disk.push(Span::styled(fmt_pct(b.util_pct), level(b.util_pct)));
            }
        }
        None if s.disks_available => disk.push(super::collecting().spans[0].clone()),
        None => disk.push(na()),
    }
    lines.push(Line::from(disk));

    let mut net = vec![Span::styled("NET  ", bold())];
    match s.net_total() {
        Some((rx, tx, e, d)) => {
            net.extend(kv("rx", fmt_rate(rx)));
            net.extend(kv("  tx", fmt_rate(tx)));
            net.push(Span::styled("  err ", dim()));
            net.push(Span::styled(
                format!("{e:.1}/s"),
                if e > 0.0 { level(75.0) } else { dim() },
            ));
            net.push(Span::styled("  drop ", dim()));
            net.push(Span::styled(
                format!("{d:.1}/s"),
                if d > 0.0 { level(75.0) } else { dim() },
            ));
        }
        None if s.nets_available => net.push(super::collecting().spans[0].clone()),
        None => net.push(na()),
    }
    lines.push(Line::from(net));

    let mut tcp = vec![Span::styled("TCP  ", bold())];
    match &s.tcp {
        Some(t) => {
            tcp.extend(kv("established", t.established.to_string()));
            if let Some(tw) = t.sockets.tcp_tw {
                tcp.extend(kv("  time-wait", tw.to_string()));
            }
            if s.interval.is_some() {
                tcp.extend(kv("  retrans", format!("{:.1}/s", t.retrans_per_s)));
                if let Some(p) = t.retrans_pct() {
                    tcp.push(Span::styled(format!(" ({})", fmt_pct(p)), level(p * 20.0)));
                }
            }
        }
        None => tcp.push(na()),
    }
    lines.push(Line::from(tcp));

    let mut fsl = vec![Span::styled("FS   ", bold())];
    match s.fullest_fs() {
        Some(fs) => {
            let p = fs.used_pct().unwrap_or(0.0);
            fsl.push(Span::styled("fullest ", dim()));
            fsl.push(Span::raw(format!("{} ", truncate(&fs.mount_point, 24))));
            fsl.push(Span::styled(fmt_pct(p), level(p)));
            fsl.push(Span::styled(
                format!("  ({} free)", fmt_bytes(fs.avail as f64)),
                dim(),
            ));
            let inode_max = s
                .filesystems
                .iter()
                .filter(|f| !f.readonly)
                .filter_map(|f| f.inode_pct())
                .reduce(f64::max);
            if let Some(i) = inode_max {
                fsl.push(Span::styled("  inodes max ", dim()));
                fsl.push(Span::styled(fmt_pct(i), level(i)));
            }
        }
        None if s.fs_available => fsl.push(Span::styled("no local filesystems found", dim())),
        None => fsl.push(na()),
    }
    lines.push(Line::from(fsl));

    let title = format!("Overview — {}", s.host.kernel);
    f.render_widget(Paragraph::new(lines).block(block(&title)), area);
}

fn draw_sparks(f: &mut Frame, area: Rect, app: &App) {
    let [l, r] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    let n = l.width.saturating_sub(2) as usize;
    let cpu: Vec<Option<f64>> = tail(app, "cpu", n);
    f.render_widget(
        Sparkline::default()
            .block(block("CPU busy %"))
            .data(spark_data(&cpu, 1.0))
            .max(100)
            .style(accent()),
        l,
    );
    let rx = tail(app, "net_rx", n);
    let tx = tail(app, "net_tx", n);
    let sum: Vec<Option<f64>> = rx
        .iter()
        .zip(&tx)
        .map(|(a, b)| match (a, b) {
            (Some(a), Some(b)) => Some(a + b),
            _ => None,
        })
        .collect();
    let peak = sum.iter().flatten().copied().fold(0.0, f64::max);
    f.render_widget(
        Sparkline::default()
            .block(block(&format!("Network rx+tx (peak {})", fmt_rate(peak))))
            .data(spark_data(&sum, 1.0))
            .style(fg(ratatui::style::Color::Magenta)),
        r,
    );
}

/// Last `n` values of a metric, `None` where unknown, oldest first.
pub fn tail(app: &App, key: &str, n: usize) -> Vec<Option<f64>> {
    let mut v: Vec<Option<f64>> = app
        .window
        .iter()
        .rev()
        .take(n)
        .map(|r| r.get(key))
        .collect();
    v.reverse();
    v
}

fn draw_findings(f: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    if app.findings.is_empty() {
        let secs = app
            .window
            .last()
            .zip(app.window.first())
            .map_or(0, |(a, b)| a.t - b.t);
        if crate::diagnose::has_data(&app.snap) {
            lines.push(Line::from(Span::styled(
                "No anomalies detected.",
                fg(ratatui::style::Color::Green),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Not evaluated: no system data could be read (Linux /proc required).",
                fg(ratatui::style::Color::Red),
            )));
        }
        if secs < super::super::SUSTAIN_SECS {
            lines.push(Line::from(Span::styled(
                format!(
                    "Rate-based checks need {} s of samples ({} s so far).",
                    super::super::SUSTAIN_SECS,
                    secs
                ),
                dim(),
            )));
        }
    } else {
        for x in app
            .findings
            .iter()
            .take(area.height.saturating_sub(2) as usize)
        {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{} {} ", severity_symbol(x.severity), x.severity.label()),
                    severity(x.severity),
                ),
                Span::raw(x.title.clone()),
            ]));
        }
    }
    let title = if app.findings.is_empty() {
        "Diagnostics".to_string()
    } else {
        format!("Diagnostics ({}) — press 6 for details", app.findings.len())
    };
    f.render_widget(Paragraph::new(lines).block(block(&title)), area);
}

fn draw_top(f: &mut Frame, area: Rect, app: &App) {
    let Some(p) = &app.snap.procs else {
        f.render_widget(
            Paragraph::new(super::unavailable("Processes")).block(block("Top processes")),
            area,
        );
        return;
    };
    let mut idx: Vec<usize> = (0..p.list.len()).collect();
    idx.sort_by(|&a, &b| {
        p.list[b]
            .cpu_pct
            .unwrap_or(0.0)
            .total_cmp(&p.list[a].cpu_pct.unwrap_or(0.0))
            .then(p.list[b].rss.cmp(&p.list[a].rss))
    });
    let total_mem = app.snap.mem.as_ref().map_or(0, |m| m.info.total) as f64;
    let w = area.width.saturating_sub(2) as usize;
    let mut lines = vec![Line::from(Span::styled(
        format!("{:>7} {:>6} {:>5}  {}", "PID", "CPU%", "MEM%", "NAME"),
        dim(),
    ))];
    for &i in idx.iter().take(area.height.saturating_sub(3) as usize) {
        let x = &p.list[i];
        let cpu = x.cpu_pct.map_or("–".into(), |c| format!("{c:.1}"));
        let mem = pct(x.rss as f64, total_mem).map_or("n/a".into(), |m| format!("{m:.1}"));
        let name_w = w.saturating_sub(23);
        lines.push(Line::from(vec![
            Span::raw(format!("{:>7} ", x.pid)),
            Span::styled(
                format!("{cpu:>6} "),
                level(x.cpu_pct.unwrap_or(0.0).min(100.0)),
            ),
            Span::raw(format!("{mem:>5}  ")),
            Span::raw(truncate(&x.comm, name_w)),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(block("Top processes (CPU)")),
        area,
    );
}
