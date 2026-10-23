//! Block devices and filesystems.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};

use super::super::App;
use super::super::widgets::*;
use crate::util::*;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let s = &app.snap;
    let dev_rows = s.disks.len().max(1) as u16;
    let dev_h = (dev_rows + 3).min(area.height / 2).max(4);
    let [dev_area, fs_area] =
        Layout::vertical([Constraint::Length(dev_h), Constraint::Min(0)]).areas(area);

    // --- block devices ---
    let title = match s.psi_io {
        Some(p) => format!(
            "Block devices — I/O pressure {} (avg10)",
            fmt_pct(p.some_avg10)
        ),
        None => "Block devices".to_string(),
    };
    if !s.disks_available {
        f.render_widget(
            Paragraph::new(super::unavailable("/proc/diskstats")).block(block(&title)),
            dev_area,
        );
    } else if s.interval.is_none() {
        f.render_widget(
            Paragraph::new(super::collecting()).block(block(&title)),
            dev_area,
        );
    } else if s.disks.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "No active block devices found.",
                dim(),
            )))
            .block(block(&title)),
            dev_area,
        );
    } else {
        let narrow = area.width < 90;
        let header = if narrow {
            vec!["Device", "Read/s", "Write/s", "Util"]
        } else {
            vec![
                "Device", "Read/s", "Write/s", "r IOPS", "w IOPS", "Await", "Util",
            ]
        };
        let util_w = if narrow { 14 } else { 22 };
        let rows: Vec<Row> = s
            .disks
            .iter()
            .map(|d| {
                let mut util = bar(d.util_pct, util_w - 6, level(d.util_pct));
                util.push(Span::styled(
                    format!(" {:>5}", fmt_pct(d.util_pct)),
                    level(d.util_pct),
                ));
                let name = if d.stacked {
                    Line::from(vec![Span::raw(d.label.clone()), Span::styled(" ↳", dim())])
                } else {
                    Line::from(d.label.clone())
                };
                let mut cells = vec![
                    Cell::from(name),
                    Cell::from(fmt_rate(d.read_bps)),
                    Cell::from(fmt_rate(d.write_bps)),
                ];
                if !narrow {
                    cells.push(Cell::from(fmt_count(d.read_iops)));
                    cells.push(Cell::from(fmt_count(d.write_iops)));
                    cells.push(Cell::from(
                        d.await_ms.map_or("–".into(), |a| format!("{a:.1} ms")),
                    ));
                }
                cells.push(Cell::from(Line::from(util)));
                Row::new(cells)
            })
            .collect();
        let widths: Vec<Constraint> = if narrow {
            vec![
                Constraint::Min(8),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(util_w as u16),
            ]
        } else {
            vec![
                Constraint::Min(10),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(util_w as u16),
            ]
        };
        let t = Table::new(rows, widths)
            .header(Row::new(header).style(dim()))
            .block(block(&title));
        f.render_widget(t, dev_area);
    }

    // --- filesystems ---
    if !s.fs_available {
        f.render_widget(
            Paragraph::new(super::unavailable("Filesystem list")).block(block("Filesystems")),
            fs_area,
        );
        return;
    }
    let visible = fs_area.height.saturating_sub(3) as usize;
    let max_scroll = s.filesystems.len().saturating_sub(visible);
    app.disk_scroll = app.disk_scroll.min(max_scroll);
    let narrow = area.width < 90;
    let rows: Vec<Row> = s
        .filesystems
        .iter()
        .skip(app.disk_scroll)
        .take(visible)
        .map(|fs| {
            let p = fs.used_pct().unwrap_or(0.0);
            let mut used = bar(p, if narrow { 8 } else { 14 }, level(p));
            used.push(Span::styled(format!(" {:>5}", fmt_pct(p)), level(p)));
            let inodes = match fs.inode_pct() {
                Some(i) => Span::styled(fmt_pct(i), level(i)),
                None => na(),
            };
            let mut mount = vec![Span::raw(fs.mount_point.clone())];
            if fs.readonly {
                mount.push(Span::styled(" (ro)", dim()));
            }
            let mut cells = vec![Cell::from(Line::from(mount))];
            if !narrow {
                cells.push(Cell::from(Span::styled(fs.fstype.clone(), dim())));
            }
            cells.push(Cell::from(fmt_bytes(fs.total as f64)));
            cells.push(Cell::from(fmt_bytes(fs.avail as f64)));
            cells.push(Cell::from(Line::from(used)));
            cells.push(Cell::from(inodes));
            Row::new(cells)
        })
        .collect();
    let mut header = vec!["Mount"];
    if !narrow {
        header.push("Type");
    }
    header.extend(["Size", "Avail", "Used", "Inodes"]);
    let mut widths = vec![Constraint::Min(12)];
    if !narrow {
        widths.push(Constraint::Length(9));
    }
    widths.extend([
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(if narrow { 15 } else { 21 }),
        Constraint::Length(7),
    ]);
    let title = if max_scroll > 0 {
        format!(
            "Filesystems ({}–{} of {}, ↑↓ to scroll)",
            app.disk_scroll + 1,
            (app.disk_scroll + visible).min(s.filesystems.len()),
            s.filesystems.len()
        )
    } else {
        format!("Filesystems ({})", s.filesystems.len())
    };
    let t = Table::new(rows, widths)
        .header(Row::new(header).style(dim()))
        .block(block(&title));
    f.render_widget(t, fs_area);
}
