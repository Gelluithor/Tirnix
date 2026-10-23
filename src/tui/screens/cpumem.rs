//! CPU & Memory details.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Sparkline};

use super::super::App;
use super::super::widgets::*;
use super::overview::tail;
use crate::metrics::Psi;
use crate::util::*;

fn psi_line(name: &str, p: Option<Psi>) -> Line<'static> {
    match p {
        Some(p) => {
            let mut s = vec![Span::styled(format!("{name:<9}"), dim())];
            s.push(Span::styled(
                format!("some {:>6}", fmt_pct(p.some_avg10)),
                level(p.some_avg10 * 3.0),
            ));
            s.push(Span::styled(
                format!(" (60s {})", fmt_pct(p.some_avg60)),
                dim(),
            ));
            if let Some(full) = p.full_avg10 {
                s.push(Span::raw(format!("  full {}", fmt_pct(full))));
            }
            Line::from(s)
        }
        None => Line::from(vec![Span::styled(format!("{name:<9}"), dim()), na()]),
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let wide = area.width >= 100;
    let spark_h = if area.height >= 30 { 5 } else { 0 };
    let [main, sparks] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(spark_h)]).areas(area);
    let (cpu_area, mem_area) = if wide {
        let [a, b] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
            .areas(main);
        (a, b)
    } else {
        let [a, b] =
            Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(main);
        (a, b)
    };
    draw_cpu(f, cpu_area, app);
    draw_mem(f, mem_area, app);
    if spark_h > 0 {
        let [l, r] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(sparks);
        let n = l.width.saturating_sub(2) as usize;
        f.render_widget(
            Sparkline::default()
                .block(block("CPU busy % (session)"))
                .data(spark_data(&tail(app, "cpu", n), 1.0))
                .max(100)
                .style(accent()),
            l,
        );
        let mem: Vec<Option<f64>> = app
            .window
            .iter()
            .rev()
            .take(n)
            .map(|r| pct(r.mem_used?, r.mem_total?))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        f.render_widget(
            Sparkline::default()
                .block(block("Memory used % (session)"))
                .data(spark_data(&mem, 1.0))
                .max(100)
                .style(fg(ratatui::style::Color::Green)),
            r,
        );
    }
}

fn draw_cpu(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.snap;
    let inner = area.width.saturating_sub(2) as usize;
    let bw = (inner.saturating_sub(20)).clamp(5, 40);
    let mut lines = Vec::new();
    match s.cpu.as_ref().and_then(|c| c.total) {
        Some(u) => {
            for (name, v) in [
                ("user", u.user),
                ("nice", u.nice),
                ("system", u.system),
                ("irq", u.irq),
                ("iowait", u.iowait),
                ("steal", u.steal),
                ("idle", u.idle),
            ] {
                let mut sp = vec![Span::styled(format!("{name:<7}"), dim())];
                sp.extend(bar(v, bw, if name == "idle" { dim() } else { level(v) }));
                sp.push(Span::raw(format!(" {:>6}", fmt_pct(v))));
                lines.push(Line::from(sp));
            }
        }
        None if s.cpu.is_some() => lines.push(super::collecting()),
        None => lines.push(super::unavailable("CPU statistics")),
    }
    lines.push(Line::from(""));
    let mut l2 = Vec::new();
    match s.load {
        Some(l) => l2.extend(kv(
            "load",
            format!("{:.2} {:.2} {:.2}", l.one, l.five, l.fifteen),
        )),
        None => l2.extend(kv("load", "n/a")),
    }
    l2.extend(kv("  CPUs", s.host.ncpu.to_string()));
    lines.push(Line::from(l2));
    if let Some(c) = &s.cpu {
        let mut l3 = Vec::new();
        l3.extend(kv("ctx switches", format!("{}/s", opt_count(c.ctxt_per_s))));
        l3.extend(kv("  forks", format!("{}/s", opt_count(c.forks_per_s))));
        lines.push(Line::from(l3));
        let mut l4 = Vec::new();
        l4.extend(kv(
            "running",
            c.procs_running.map_or("n/a".into(), |v| v.to_string()),
        ));
        l4.extend(kv(
            "  blocked on I/O",
            c.procs_blocked.map_or("n/a".into(), |v| v.to_string()),
        ));
        lines.push(Line::from(l4));
    }
    lines.push(psi_line("CPU PSI", s.psi_cpu));

    // Per-core grid in the remaining space.
    let used = lines.len() as u16 + 2;
    if let Some(c) = &s.cpu
        && !c.per_core.is_empty()
        && area.height > used + 1
    {
        lines.push(Line::from(Span::styled("per core", dim())));
        let cell = 16usize;
        let cols = (inner / cell).max(1);
        let rows_avail = area.height.saturating_sub(used + 3) as usize;
        let rows_needed = c.per_core.len().div_ceil(cols);
        for row in 0..rows_needed.min(rows_avail) {
            let mut sp = Vec::new();
            for col in 0..cols {
                let i = row + col * rows_needed;
                if let Some(v) = c.per_core.get(i) {
                    sp.push(Span::styled(format!("{i:>3} "), dim()));
                    sp.extend(bar(*v, 7, level(*v)));
                    sp.push(Span::raw(format!("{:>4.0}%", v)));
                }
            }
            lines.push(Line::from(sp));
        }
        if rows_needed > rows_avail {
            lines.push(Line::from(Span::styled(
                format!(
                    "… {} more cores (enlarge the terminal)",
                    c.per_core.len() - rows_avail * cols
                ),
                dim(),
            )));
        }
    }
    f.render_widget(Paragraph::new(lines).block(block("CPU")), area);
}

fn draw_mem(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.snap;
    let Some(m) = &s.mem else {
        f.render_widget(
            Paragraph::new(super::unavailable("Memory statistics")).block(block("Memory")),
            area,
        );
        return;
    };
    let i = &m.info;
    let b = |v: u64| fmt_bytes(v as f64);
    let row = |label: &str, value: String, note: &str| {
        Line::from(vec![
            Span::styled(format!("{label:<13}"), dim()),
            Span::raw(format!("{value:>11}")),
            Span::styled(format!("  {note}"), dim()),
        ])
    };
    let total = i.total as f64;
    let share = |v: u64| pct(v as f64, total).map_or(String::new(), fmt_pct);
    let mut lines = vec![
        row("Total", b(i.total), ""),
        row("Used", b(i.used()), &share(i.used())),
        row(
            "Available",
            i.available.map_or("n/a".into(), b),
            if i.available.is_some() {
                "kernel estimate"
            } else {
                "kernel < 3.14"
            },
        ),
        row("Free", b(i.free), "low is normal"),
        row("Page cache", b(i.cached + i.buffers), "mostly reclaimable"),
        row("Shmem/tmpfs", b(i.shmem), ""),
        row("Dirty", b(i.dirty), "not yet written"),
        row("Writeback", b(i.writeback), ""),
        Line::from(""),
    ];
    if i.swap_total == 0 {
        lines.push(row("Swap", "none".into(), "no swap configured"));
    } else {
        lines.push(row(
            "Swap used",
            b(i.swap_used()),
            &format!("of {}", b(i.swap_total)),
        ));
        lines.push(row("Swap cached", b(i.swap_cached), ""));
    }
    lines.push(row(
        "Swap in/out",
        format!(
            "{}/{}",
            opt_count(m.swap_in_per_s),
            opt_count(m.swap_out_per_s)
        ),
        "pages/s",
    ));
    lines.push(row(
        "Major faults",
        opt_count(m.major_faults_per_s),
        "/s from disk",
    ));
    lines.push(row(
        "OOM kills",
        m.oom_kills.map_or("n/a".into(), |v| v.to_string()),
        if m.oom_kills.is_some() {
            "since boot"
        } else {
            "needs Linux 4.13+"
        },
    ));
    lines.push(Line::from(""));
    lines.push(psi_line("Mem PSI", s.psi_mem));
    lines.push(psi_line("I/O PSI", s.psi_io));
    if let Some((a, mx)) = s.file_handles {
        lines.push(row(
            "File handles",
            a.to_string(),
            &format!(
                "of {}",
                if mx > 1 << 40 {
                    "unlimited".to_string()
                } else {
                    mx.to_string()
                }
            ),
        ));
    }
    f.render_widget(Paragraph::new(lines).block(block("Memory")), area);
}
