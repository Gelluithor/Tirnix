//! Screen rendering. `draw` lays out the frame shared by all screens
//! (header, tabs, footer) and delegates the body to the active screen.

mod cpumem;
mod diag;
mod disks;
mod history;
mod net;
mod overview;
mod procs;
mod settings;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Tabs, Wrap};

use super::widgets::*;
use super::{App, InputKind, Screen};
use crate::diagnose::Severity;
use crate::util::{fmt_duration, fmt_pct};

pub const MIN_W: u16 = 30;
pub const MIN_H: u16 = 8;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    if area.width < MIN_W || area.height < MIN_H {
        let msg = Paragraph::new(format!(
            "Terminal too small ({}×{}). Need at least {MIN_W}×{MIN_H}.",
            area.width, area.height
        ))
        .wrap(Wrap { trim: true });
        f.render_widget(msg, area);
        return;
    }
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, header, app);
    draw_tabs(f, tabs, app);
    match app.screen {
        Screen::Overview => overview::draw(f, body, app),
        Screen::CpuMem => cpumem::draw(f, body, app),
        Screen::Disks => disks::draw(f, body, app),
        Screen::Processes => procs::draw(f, body, app),
        Screen::Network => net::draw(f, body, app),
        Screen::Diagnostics => diag::draw(f, body, app),
        Screen::History => history::draw(f, body, app),
        Screen::Settings => settings::draw(f, body, app),
    }
    draw_footer(f, footer, app);
    if app.show_help {
        draw_help(f, area);
    }
}

/// Add spans to `line` while they fit into `width`, in priority order.
fn push_fitting(
    line: &mut Vec<Span<'static>>,
    used: &mut usize,
    width: usize,
    part: Vec<Span<'static>>,
) {
    let w: usize = part.iter().map(|s| s.content.chars().count()).sum();
    if *used + w <= width {
        *used += w;
        line.extend(part);
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.snap;
    let width = area.width as usize;
    let mut left: Vec<Span> = vec![Span::styled(
        " Tirnix ",
        accent().add_modifier(ratatui::style::Modifier::BOLD),
    )];
    let mut used = 8;
    push_fitting(
        &mut left,
        &mut used,
        width,
        vec![Span::raw(s.host.hostname.clone())],
    );
    if let Some(up) = s.host.uptime {
        push_fitting(
            &mut left,
            &mut used,
            width,
            vec![Span::styled(format!("  up {}", fmt_duration(up)), dim())],
        );
    }

    // Right side: the most important numbers, visible on every screen.
    let mut right: Vec<Vec<Span>> = Vec::new();
    if app.paused {
        right.push(vec![Span::styled(
            " PAUSED ",
            fg(Color::Black).bg(Color::Yellow),
        )]);
    }
    let crit = app
        .findings
        .iter()
        .filter(|x| x.severity == Severity::Critical)
        .count();
    let warn = app
        .findings
        .iter()
        .filter(|x| x.severity == Severity::Warning)
        .count();
    if crit > 0 {
        right.push(vec![Span::styled(
            format!(" {} {crit} critical ", severity_symbol(Severity::Critical)),
            severity(Severity::Critical),
        )]);
    }
    if warn > 0 {
        right.push(vec![Span::styled(
            format!(" {} {warn} warning ", severity_symbol(Severity::Warning)),
            severity(Severity::Warning),
        )]);
    }
    if let Some(u) = s.cpu.as_ref().and_then(|c| c.total) {
        right.push(vec![
            Span::styled(" CPU ", dim()),
            Span::styled(fmt_pct(u.busy), level(u.busy)),
        ]);
    }
    if let Some(m) = &s.mem
        && let Some(p) = crate::util::pct(m.info.used() as f64, m.info.total as f64)
    {
        right.push(vec![
            Span::styled(" MEM ", dim()),
            Span::styled(fmt_pct(p), level(p)),
        ]);
    }
    if let Some(l) = s.load {
        right.push(vec![
            Span::styled(" LOAD ", dim()),
            Span::raw(format!("{:.2}", l.one)),
        ]);
    }
    let log = if app.logger.running {
        vec![Span::styled(
            if utf8() { " ● LOG" } else { " * LOG" },
            fg(Color::Green),
        )]
    } else {
        vec![Span::styled(
            if utf8() { " ○ log off" } else { " - log off" },
            dim(),
        )]
    };
    right.push(log);
    right.push(vec![Span::styled(
        format!(" {}s ", app.cfg.ui.refresh_ms as f64 / 1000.0),
        dim(),
    )]);

    let mut rspans = Vec::new();
    let mut rused = 0;
    let avail = width.saturating_sub(used + 1);
    for part in right {
        push_fitting(&mut rspans, &mut rused, avail, part);
    }
    let pad = width.saturating_sub(used + rused);
    left.push(Span::raw(" ".repeat(pad)));
    left.extend(rspans);
    f.render_widget(Paragraph::new(Line::from(left)), area);
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    // Each tab is "N title" plus padding and a divider; drop the padding
    // before falling back to short names.
    let titles_w: usize = Screen::ALL.iter().map(|s| s.title().len() + 2).sum();
    let width = area.width as usize;
    let padded = titles_w + 3 * Screen::ALL.len() <= width;
    let use_full = padded || titles_w + Screen::ALL.len() <= width;
    let titles: Vec<Line> = Screen::ALL
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let name = if use_full { s.title() } else { s.short() };
            let mut spans = vec![
                Span::styled(format!("{}", i + 1), accent()),
                Span::raw(format!(" {name}")),
            ];
            if *s == Screen::Diagnostics && !app.findings.is_empty() {
                let sev = app.findings[0].severity;
                spans.push(Span::styled(
                    format!(" {}", app.findings.len()),
                    severity(sev),
                ));
            }
            Line::from(spans)
        })
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.screen.index())
        .highlight_style(selected())
        .divider(Span::styled("│", dim()));
    let tabs = if padded || !use_full {
        tabs.padding(" ", " ")
    } else {
        tabs.padding("", "")
    };
    f.render_widget(tabs, area);
}

fn hints(app: &App) -> &'static str {
    match app.screen {
        Screen::Processes => "↑↓ select  s sort  / filter  Esc clear",
        Screen::Disks | Screen::Network => "↑↓ scroll",
        Screen::Diagnostics => "↑↓ select  PgUp/PgDn scroll  a active checks",
        Screen::History => "←→ range  ↑↓ metric  c compare  r reload",
        Screen::Settings => "↑↓ select  ←→/Enter change",
        _ => "",
    }
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    if let Some(input) = &app.input {
        let prompt = match input.kind {
            InputKind::ProcFilter => "Filter (name, PID or user): ",
            InputKind::LogDir => "Data directory (empty = default): ",
            InputKind::Targets => "Targets, comma separated host:port: ",
        };
        let cursor = if utf8() { "▏" } else { "_" };
        let line = Line::from(vec![
            Span::styled(prompt, accent()),
            Span::raw(input.buf.clone()),
            Span::styled(cursor, accent()),
            Span::styled("   Enter confirm  Esc cancel", dim()),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    if let Some((msg, err)) = app.message() {
        let style = if err {
            fg(Color::Red)
        } else {
            fg(Color::Green)
        };
        f.render_widget(Paragraph::new(Span::styled(format!(" {msg}"), style)), area);
        return;
    }
    let mut spans = vec![
        Span::styled(" q", accent()),
        Span::raw(" quit  "),
        Span::styled("?", accent()),
        Span::raw(" help  "),
        Span::styled("Tab/1-8", accent()),
        Span::raw(" screens  "),
        Span::styled("p", accent()),
        Span::raw(if app.paused { " resume  " } else { " pause  " }),
    ];
    let h = hints(app);
    if !h.is_empty() {
        spans.push(Span::styled("│ ", dim()));
        spans.push(Span::raw(if utf8() {
            h.to_string()
        } else {
            h.replace('↑', "Up")
                .replace('↓', "Dn")
                .replace('←', "Lt")
                .replace('→', "Rt")
        }));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

const HELP: &[(&str, &str)] = &[
    ("Global", ""),
    (
        "q, Ctrl-C",
        "Quit (background logging, if enabled, keeps running)",
    ),
    ("Tab / Shift-Tab, ←/→", "Next / previous screen"),
    ("1 … 8", "Jump to screen"),
    ("p", "Pause / resume sampling"),
    ("+ / -", "Faster / slower refresh (this session)"),
    ("?", "This help"),
    ("Processes", ""),
    ("↑↓ PgUp PgDn Home End", "Move selection"),
    ("s", "Cycle sort: CPU, memory, I/O, PID, name"),
    ("/  Esc", "Filter by name, PID or user / clear"),
    ("Diagnostics", ""),
    ("↑↓  PgUp/PgDn", "Select finding / scroll details"),
    ("a", "Run active checks (DNS + TCP to configured targets)"),
    ("History", ""),
    ("←/→  ↑/↓", "Time range / metric"),
    ("c", "Compare with the previous period of equal length"),
    ("Settings", ""),
    (
        "↑↓  ←/→ Enter",
        "Select / change; changes are saved immediately",
    ),
];

fn draw_help(f: &mut Frame, area: Rect) {
    let w = 72.min(area.width.saturating_sub(2));
    let h = (HELP.len() as u16 + 4).min(area.height.saturating_sub(2));
    let r = centered(area, w, h);
    f.render_widget(Clear, r);
    let lines: Vec<Line> = HELP
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                Line::from(Span::styled(
                    k.to_string(),
                    accent().add_modifier(ratatui::style::Modifier::BOLD),
                ))
            } else {
                Line::from(vec![
                    Span::styled(format!("  {k:<24}"), bold()),
                    Span::raw(v.to_string()),
                ])
            }
        })
        .chain([
            Line::from(""),
            Line::from(Span::styled("Press any key to close.", dim())),
        ])
        .collect();
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Keys"))
            .wrap(Wrap { trim: false }),
        r,
    );
}

/// Placeholder line for a missing data source.
pub fn unavailable(what: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("{what}: not available on this system"),
        dim(),
    ))
}

/// Text shown until the second sample arrives.
pub fn collecting() -> Line<'static> {
    Line::from(Span::styled("collecting…", dim()))
}
