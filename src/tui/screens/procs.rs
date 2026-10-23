//! Process list.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};

use super::super::widgets::*;
use super::super::{App, ProcSort};
use crate::util::*;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let [info, table_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    let Some(p) = &app.snap.procs else {
        f.render_widget(
            Paragraph::new(super::unavailable("Process list (/proc)")),
            area,
        );
        return;
    };

    let mut sp = vec![
        Span::styled(" tasks ", dim()),
        Span::raw(p.total.to_string()),
        Span::styled("  threads ", dim()),
        Span::raw(p.threads.to_string()),
        Span::styled("  running ", dim()),
        Span::raw(p.running.to_string()),
        Span::styled("  D-state ", dim()),
        Span::raw(p.uninterruptible.to_string()),
        Span::styled("  zombie ", dim()),
        Span::raw(p.zombies.to_string()),
        Span::styled("   sort: ", dim()),
        Span::styled(app.proc_sort.label(), accent()),
    ];
    if !app.proc_filter.is_empty() {
        sp.push(Span::styled("  filter: ", dim()));
        sp.push(Span::styled(app.proc_filter.clone(), accent()));
        sp.push(Span::styled(
            format!(" ({} match)", app.proc_rows.len()),
            dim(),
        ));
    }
    if p.io_denied > 0 {
        sp.push(Span::styled(
            format!("   I/O n/a for {} processes (needs root)", p.io_denied),
            dim(),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(sp)), info);

    let w = table_area.width as usize;
    let show_user = w >= 60;
    let show_io = w >= 90;
    let show_thr = w >= 100;
    let visible = table_area.height.saturating_sub(3) as usize;
    let n = app.proc_rows.len();

    // Keep the selection visible.
    if app.proc_sel < app.proc_offset {
        app.proc_offset = app.proc_sel;
    } else if visible > 0 && app.proc_sel >= app.proc_offset + visible {
        app.proc_offset = app.proc_sel + 1 - visible;
    }
    app.proc_offset = app.proc_offset.min(n.saturating_sub(visible));

    let total_mem = app.snap.mem.as_ref().map_or(0, |m| m.info.total) as f64;
    let rows_idx: Vec<usize> = app
        .proc_rows
        .iter()
        .skip(app.proc_offset)
        .take(visible)
        .copied()
        .collect();
    let mut rows = Vec::with_capacity(rows_idx.len());
    for i in rows_idx {
        let x = app
            .snap
            .procs
            .as_ref()
            .map(|p| p.list[i].clone())
            .unwrap_or_default();
        let cmd = app
            .cmdline(x.pid)
            .unwrap_or_else(|| format!("[{}]", x.comm));
        let cpu = x.cpu_pct.unwrap_or(0.0);
        let mut cells = vec![Cell::from(format!("{:>7}", x.pid))];
        if show_user {
            cells.push(Cell::from(truncate(&app.user_name(x.uid), 9)));
        }
        let state_style = match x.state {
            'R' => fg(ratatui::style::Color::Green),
            'D' => fg(ratatui::style::Color::Yellow),
            'Z' => fg(ratatui::style::Color::Red),
            _ => dim(),
        };
        cells.push(Cell::from(Span::styled(x.state.to_string(), state_style)));
        cells.push(Cell::from(Span::styled(
            x.cpu_pct.map_or("–".into(), |c| format!("{c:>5.1}")),
            level(cpu.min(100.0)),
        )));
        cells.push(Cell::from(
            pct(x.rss as f64, total_mem).map_or("n/a".into(), |m| format!("{m:>4.1}")),
        ));
        cells.push(Cell::from(format!("{:>9}", fmt_bytes(x.rss as f64))));
        if show_thr {
            cells.push(Cell::from(format!("{:>4}", x.threads)));
        }
        if show_io {
            let io = |v: Option<f64>| match v {
                Some(v) if v > 0.0 => Span::raw(format!("{:>10}", fmt_rate(v))),
                Some(_) => Span::styled(format!("{:>10}", "0"), dim()),
                None => Span::styled(format!("{:>10}", "n/a"), dim()),
            };
            cells.push(Cell::from(io(x.read_bps)));
            cells.push(Cell::from(io(x.write_bps)));
        }
        cells.push(Cell::from(cmd));
        rows.push(Row::new(cells));
    }

    let mut header = vec!["    PID"];
    let mut widths = vec![Constraint::Length(7)];
    if show_user {
        header.push("USER");
        widths.push(Constraint::Length(9));
    }
    header.extend(["S", " CPU%", "MEM%", "      RSS"]);
    widths.extend([
        Constraint::Length(1),
        Constraint::Length(5),
        Constraint::Length(4),
        Constraint::Length(9),
    ]);
    if show_thr {
        header.push(" THR");
        widths.push(Constraint::Length(4));
    }
    if show_io {
        header.extend(["    READ/s", "   WRITE/s"]);
        widths.extend([Constraint::Length(10), Constraint::Length(10)]);
    }
    header.push("COMMAND");
    widths.push(Constraint::Min(10));

    let sort_col = match app.proc_sort {
        ProcSort::Cpu => " CPU%",
        ProcSort::Mem => "      RSS",
        ProcSort::Io => "    READ/s",
        ProcSort::Pid => "    PID",
        ProcSort::Name => "COMMAND",
    };
    let header_cells: Vec<Cell> = header
        .iter()
        .map(|h| {
            if *h == sort_col {
                Cell::from(Span::styled(
                    h.to_string(),
                    accent().add_modifier(ratatui::style::Modifier::BOLD),
                ))
            } else {
                Cell::from(Span::styled(h.to_string(), dim()))
            }
        })
        .collect();
    let title = format!(
        "Processes ({}{})",
        n,
        if n > visible && visible > 0 {
            format!(
                ", {}–{}",
                app.proc_offset + 1,
                (app.proc_offset + visible).min(n)
            )
        } else {
            String::new()
        }
    );
    let table = Table::new(rows, widths)
        .header(Row::new(header_cells))
        .block(block(&title))
        .column_spacing(1)
        .row_highlight_style(selected());
    let mut state = TableState::default();
    if n > 0 {
        state.select(Some(app.proc_sel - app.proc_offset));
    }
    f.render_stateful_widget(table, table_area, &mut state);
}
