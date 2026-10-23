//! Settings: monitoring options, long-term logging, active check targets.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::super::widgets::*;
use super::super::{App, SettingItem, SettingRow, setting_rows};
use crate::util::*;

fn check(on: bool) -> &'static str {
    match (on, utf8()) {
        (true, true) => "[✓]",
        (true, false) => "[x]",
        (false, _) => "[ ]",
    }
}

fn item_text(app: &App, item: SettingItem) -> (String, String, &'static str) {
    let c = &app.cfg;
    match item {
        SettingItem::Refresh => (
            "Refresh interval".into(),
            format!("{} s", c.ui.refresh_ms as f64 / 1000.0),
            "How often the TUI samples and redraws",
        ),
        SettingItem::NetFs => (
            "Network filesystems".into(),
            check(c.collection.include_network_fs).into(),
            "Include NFS/CIFS/FUSE mounts (statvfs can hang on dead servers)",
        ),
        SettingItem::LogEnabled => (
            "Background logging".into(),
            if c.logging.enabled || app.logger.running {
                "ON".into()
            } else {
                "OFF".into()
            },
            "Enter/Space toggles; starts/stops a separate logger process",
        ),
        SettingItem::LogInterval => (
            "Logging interval".into(),
            format!("{} s", c.logging.interval_secs),
            "Seconds between stored samples",
        ),
        SettingItem::LogDir => (
            "Data directory".into(),
            if c.logging.directory.is_empty() {
                format!("(default) {}", c.data_dir().display())
            } else {
                c.logging.directory.clone()
            },
            "Enter to edit",
        ),
        SettingItem::Retention => (
            "Retention".into(),
            format!("{} days", c.logging.retention_days),
            "Older data files are deleted",
        ),
        SettingItem::MaxSize => (
            "Size limit".into(),
            format!("{} MiB", c.logging.max_size_mb),
            "Oldest files are deleted above this total",
        ),
        SettingItem::Metric(g) => (
            format!("  {}", g.key()),
            check(c.logging.metrics.iter().any(|m| m == g.key())).into(),
            g.description(),
        ),
        SettingItem::Targets => (
            "Targets".into(),
            if c.active_checks.targets.is_empty() {
                "(none)".into()
            } else {
                c.active_checks.targets.join(", ")
            },
            "host:port list for the Diagnostics 'a' key; Enter to edit",
        ),
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let status_h = 7u16.min(area.height / 2);
    let [list_area, status_area] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(status_h)]).areas(area);

    let sel = app.selected_setting();
    let inner_w = list_area.width.saturating_sub(2) as usize;
    let mut lines = Vec::new();
    let mut sel_line = 0usize;
    for row in setting_rows() {
        match row {
            SettingRow::Header(h) => {
                if !lines.is_empty() {
                    lines.push(Line::from(""));
                }
                lines.push(Line::from(Span::styled(
                    h,
                    accent().add_modifier(ratatui::style::Modifier::BOLD),
                )));
            }
            SettingRow::Item(item) => {
                let (label, value, hint) = item_text(app, item);
                let is_sel = item == sel;
                if is_sel {
                    sel_line = lines.len();
                }
                let marker = if is_sel {
                    if utf8() { "▶ " } else { "> " }
                } else {
                    "  "
                };
                let value_style = match (item, value.as_str()) {
                    (SettingItem::LogEnabled, "ON") => {
                        fg(Color::Green).add_modifier(ratatui::style::Modifier::BOLD)
                    }
                    (SettingItem::LogEnabled, _) => dim(),
                    _ => ratatui::style::Style::new(),
                };
                let mut sp = vec![
                    Span::styled(marker, accent()),
                    Span::styled(
                        format!("{label:<22}"),
                        if is_sel {
                            bold()
                        } else {
                            ratatui::style::Style::new()
                        },
                    ),
                    // Values share one column so the hints line up.
                    Span::styled(
                        format!(
                            "{:<10}",
                            truncate(&value, inner_w.saturating_sub(26).max(8))
                        ),
                        value_style,
                    ),
                ];
                let used: usize = sp.iter().map(|s| s.content.chars().count()).sum();
                if inner_w > used + 6 {
                    sp.push(Span::styled(
                        format!("   {}", truncate(hint, inner_w - used - 3)),
                        dim(),
                    ));
                }
                let mut line = Line::from(sp);
                if is_sel {
                    line = line.style(selected());
                }
                lines.push(line);
            }
        }
    }
    // Scroll so the selected line is visible.
    let visible = list_area.height.saturating_sub(2) as usize;
    let scroll = sel_line.saturating_sub(visible.saturating_sub(2)) as u16;
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Settings — changes are saved immediately"))
            .scroll((scroll, 0)),
        list_area,
    );

    draw_status(f, status_area, app);
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let st = &app.logger;
    let mut lines = Vec::new();
    let mut l = vec![Span::styled("Logger  ", dim())];
    if st.running {
        l.push(Span::styled(
            format!("{} running", if utf8() { "●" } else { "*" }),
            fg(Color::Green).add_modifier(ratatui::style::Modifier::BOLD),
        ));
        if let Some(p) = st.pid {
            l.push(Span::raw(format!(" (pid {p})")));
        }
        if let Some(t) = st.last_write {
            let ago = (now_unix() as i64 - t).max(0);
            l.push(Span::styled(
                format!(", last write {} ago", fmt_duration(ago as f64)),
                dim(),
            ));
        }
    } else {
        l.push(Span::styled(
            format!("{} not running", if utf8() { "○" } else { "-" }),
            dim(),
        ));
        if app.cfg.logging.enabled {
            l.push(Span::styled(
                "  (enabled in config but not running — press Enter on Background logging to start)",
                fg(Color::Yellow),
            ));
        }
    }
    lines.push(Line::from(l));
    let mut l2 = vec![Span::styled("Stored  ", dim())];
    l2.push(Span::raw(format!(
        "{} file(s), {} of {} MiB limit",
        st.usage.files,
        fmt_bytes(st.usage.bytes as f64),
        app.cfg.logging.max_size_mb
    )));
    if let (Some(a), Some(b)) = (st.usage.oldest_hour, st.usage.newest_hour) {
        l2.push(Span::styled(
            format!("  {} → {}", fmt_local_mdhm(a), fmt_local_mdhm(b + 3599)),
            dim(),
        ));
    }
    lines.push(Line::from(l2));
    lines.push(Line::from(vec![
        Span::styled("Data    ", dim()),
        Span::raw(st.dir.display().to_string()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Config  ", dim()),
        Span::raw(app.cfg_path.display().to_string()),
        Span::styled(
            if app.cfg_path.exists() {
                ""
            } else {
                "  (not created yet — defaults in use)"
            },
            dim(),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "Logging continues after quitting Tirnix. Stop it here or with `tirnix logger stop`.",
        dim(),
    )));
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Logging status"))
            .wrap(Wrap { trim: true }),
        area,
    );
}
