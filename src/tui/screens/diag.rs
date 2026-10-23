//! Diagnostics: findings with measured facts, hypotheses and checks, plus
//! optional active connectivity checks.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};

use super::super::widgets::*;
use super::super::{App, SUSTAIN_SECS};
use crate::diagnose;
use crate::util::fmt_duration;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let active_h = (app.cfg.active_checks.targets.len() as u16 + 3)
        .max(3)
        .min(area.height / 3);
    let [main, active] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(active_h)]).areas(area);

    if app.findings.is_empty() {
        draw_all_clear(f, main, app);
    } else {
        let wide = main.width >= 100;
        let (list_area, detail_area) = if wide {
            let [a, b] =
                Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)])
                    .areas(main);
            (a, b)
        } else {
            let lh = (app.findings.len() as u16 + 2).min(main.height / 3).max(3);
            let [a, b] = Layout::vertical([Constraint::Length(lh), Constraint::Min(0)]).areas(main);
            (a, b)
        };
        let items: Vec<ListItem> = app
            .findings
            .iter()
            .map(|x| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{} ", severity_symbol(x.severity)),
                        severity(x.severity),
                    ),
                    Span::raw(x.title.clone()),
                ]))
            })
            .collect();
        let mut state = ListState::default();
        state.select(Some(app.diag_sel));
        f.render_stateful_widget(
            List::new(items)
                .block(block(&format!("Findings ({})", app.findings.len())))
                .highlight_style(selected()),
            list_area,
            &mut state,
        );
        draw_detail(f, detail_area, app);
    }
    draw_active(f, active, app);
}

fn section(title: &str, color: Color) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        fg(color).add_modifier(ratatui::style::Modifier::BOLD),
    ))
}

fn draw_detail(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(x) = app.findings.get(app.diag_sel) else {
        return;
    };
    let bullet = if utf8() { "•" } else { "-" };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!("{} ", x.severity.label()), severity(x.severity)),
            Span::styled(x.title.clone(), bold()),
        ]),
        Line::from(""),
        section("Measured", Color::Cyan),
    ];
    lines.extend(x.facts.iter().map(|s| Line::from(format!(" {bullet} {s}"))));
    lines.push(Line::from(""));
    lines.push(section(
        "Possible causes (hypotheses, not verified)",
        Color::Yellow,
    ));
    lines.extend(
        x.causes
            .iter()
            .map(|s| Line::from(format!(" {bullet} {s}"))),
    );
    lines.push(Line::from(""));
    lines.push(section("How to verify", Color::Green));
    lines.extend(x.checks.iter().map(|s| {
        Line::from(vec![
            Span::styled(" $ ", dim()),
            Span::styled(s.clone(), accent()),
        ])
    }));
    // Clamp scrolling to the content (approximation: no wrap accounting).
    let max = (lines.len() as u16).saturating_sub(area.height.saturating_sub(2));
    app.diag_scroll = app.diag_scroll.min(max);
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Details"))
            .wrap(Wrap { trim: false })
            .scroll((app.diag_scroll, 0)),
        area,
    );
}

fn draw_all_clear(f: &mut Frame, area: Rect, app: &App) {
    let span = app
        .window
        .last()
        .zip(app.window.first())
        .map_or(0, |(a, b)| a.t - b.t);
    let headline = if diagnose::has_data(&app.snap) {
        Span::styled(
            "No anomalies detected.",
            fg(Color::Green).add_modifier(ratatui::style::Modifier::BOLD),
        )
    } else {
        Span::styled(
            "Diagnostics not evaluated: no system data could be read.",
            fg(Color::Red).add_modifier(ratatui::style::Modifier::BOLD),
        )
    };
    let mut lines = vec![
        Line::from(headline),
        Line::from(""),
        Line::from(format!(
            "Rate-based rules (CPU, I/O, memory, swap, network, TCP) report a problem only when it persists for most of {}; \
             point-in-time facts (full filesystems, OOM kills) are reported immediately.",
            fmt_duration(SUSTAIN_SECS as f64)
        )),
    ];
    if span < SUSTAIN_SECS {
        lines.push(Line::from(Span::styled(
            format!("Collected {} s of samples so far.", span),
            dim(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Data sources", bold())));
    for (name, ok, note) in diagnose::coverage(&app.snap) {
        let (sym, style) = if ok {
            (if utf8() { "✓" } else { "+" }, fg(Color::Green))
        } else {
            (if utf8() { "✗" } else { "x" }, fg(Color::Red))
        };
        let mut sp = vec![Span::styled(format!(" {sym} "), style), Span::raw(name)];
        if !note.is_empty() && (!ok || name == "Per-process I/O") {
            sp.push(Span::styled(format!("  ({note})"), dim()));
        }
        lines.push(Line::from(sp));
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Diagnostics"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_active(f: &mut Frame, area: Rect, app: &App) {
    let title = "Active checks — optional, sends DNS/TCP traffic only when you press a";
    let mut lines = Vec::new();
    if app.cfg.active_checks.targets.is_empty() {
        lines.push(Line::from(Span::styled(
            "No targets configured (Settings → Active checks). Passive monitoring never contacts the network.",
            dim(),
        )));
    } else if app.active_running() {
        lines.push(Line::from(Span::styled("Running…", accent())));
    } else if let Some((t, results)) = &app.active_results {
        let ago = crate::util::now_unix() as i64 - t;
        lines.push(Line::from(Span::styled(
            format!("Results from {} ago:", fmt_duration(ago as f64)),
            dim(),
        )));
        for r in results {
            let mut sp = vec![Span::styled(
                format!(" {:<28}", truncate(&r.target, 28)),
                bold(),
            )];
            match &r.dns {
                Ok((d, addrs)) => sp.push(Span::raw(format!(
                    "DNS {:.0} ms ({} addr)  ",
                    d.as_secs_f64() * 1000.0,
                    addrs.len()
                ))),
                Err(e) => sp.push(Span::styled(format!("DNS failed: {e}"), fg(Color::Red))),
            }
            match &r.connect {
                Some(Ok((d, a))) => sp.push(Span::styled(
                    format!("TCP connect {:.0} ms to {a}", d.as_secs_f64() * 1000.0),
                    fg(Color::Green),
                )),
                Some(Err(e)) => sp.push(Span::styled(format!("TCP failed: {e}"), fg(Color::Red))),
                None => {}
            }
            lines.push(Line::from(sp));
        }
    } else {
        lines.push(Line::from(format!(
            "Targets: {}  — press a to run.",
            app.cfg.active_checks.targets.join(", ")
        )));
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(block(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}
