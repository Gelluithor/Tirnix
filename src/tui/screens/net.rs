//! Network interfaces and TCP statistics.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Sparkline, Table};

use super::super::App;
use super::super::widgets::*;
use super::overview::tail;
use crate::util::*;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let wide = area.width >= 110;
    let tcp_h = if wide { 0 } else { 12 };
    let spark_h = if area.height >= 28 { 5 } else { 0 };
    let [top, tcp_area, sparks] = Layout::vertical([
        Constraint::Min(4),
        Constraint::Length(tcp_h),
        Constraint::Length(spark_h),
    ])
    .areas(area);
    let (if_area, tcp_area) = if wide {
        let [a, b] = Layout::horizontal([Constraint::Min(60), Constraint::Length(44)]).areas(top);
        (a, b)
    } else {
        (top, tcp_area)
    };
    draw_ifaces(f, if_area, app);
    draw_tcp(f, tcp_area, app);
    if spark_h > 0 {
        let [l, r] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(sparks);
        let n = l.width.saturating_sub(2) as usize;
        for (key, title, area, color) in [
            ("net_rx", "RX", l, ratatui::style::Color::Green),
            ("net_tx", "TX", r, ratatui::style::Color::Magenta),
        ] {
            let v = tail(app, key, n);
            let peak = v.iter().flatten().copied().fold(0.0, f64::max);
            f.render_widget(
                Sparkline::default()
                    .block(block(&format!("{title} total (peak {})", fmt_rate(peak))))
                    .data(spark_data(&v, 1.0))
                    .style(fg(color)),
                area,
            );
        }
    }
}

fn draw_ifaces(f: &mut Frame, area: Rect, app: &mut App) {
    let s = &app.snap;
    if !s.nets_available {
        f.render_widget(
            Paragraph::new(super::unavailable("/proc/net/dev")).block(block("Interfaces")),
            area,
        );
        return;
    }
    if s.interval.is_none() {
        f.render_widget(
            Paragraph::new(super::collecting()).block(block("Interfaces")),
            area,
        );
        return;
    }
    let narrow = area.width < 80;
    let visible = area.height.saturating_sub(3) as usize;
    app.net_scroll = app.net_scroll.min(s.nets.len().saturating_sub(visible));
    let rows: Vec<Row> = s
        .nets
        .iter()
        .skip(app.net_scroll)
        .take(visible)
        .map(|n| {
            let name = if n.is_virtual {
                Line::from(vec![Span::raw(n.name.clone()), Span::styled(" v", dim())])
            } else {
                Line::from(n.name.clone())
            };
            let err = n.rx_errs_per_s + n.tx_errs_per_s;
            let drop = n.rx_drop_per_s + n.tx_drop_per_s;
            let warn = |v: f64| if v > 0.0 { level(75.0) } else { dim() };
            let mut cells = vec![
                Cell::from(name),
                Cell::from(fmt_rate(n.rx_bps)),
                Cell::from(fmt_rate(n.tx_bps)),
            ];
            if !narrow {
                cells.push(Cell::from(fmt_count(n.rx_pps)));
                cells.push(Cell::from(fmt_count(n.tx_pps)));
            }
            cells.push(Cell::from(Span::styled(format!("{err:.1}"), warn(err))));
            cells.push(Cell::from(Span::styled(format!("{drop:.1}"), warn(drop))));
            if !narrow {
                cells.push(Cell::from(Span::styled(
                    format!(
                        "{}/{}",
                        fmt_count(n.total_errs as f64),
                        fmt_count(n.total_drops as f64)
                    ),
                    dim(),
                )));
            }
            Row::new(cells)
        })
        .collect();
    let (header, widths): (Vec<&str>, Vec<Constraint>) = if narrow {
        (
            vec!["Iface", "RX/s", "TX/s", "Err/s", "Drop/s"],
            vec![
                Constraint::Min(8),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(6),
                Constraint::Length(6),
            ],
        )
    } else {
        (
            vec![
                "Interface",
                "RX/s",
                "TX/s",
                "RX pkt/s",
                "TX pkt/s",
                "Err/s",
                "Drop/s",
                "Err/Drop total",
            ],
            vec![
                Constraint::Min(10),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(14),
            ],
        )
    };
    let any_physical = s.nets.iter().any(|n| !n.is_virtual);
    let title = if any_physical {
        "Interfaces (v = virtual, excluded from totals)"
    } else {
        "Interfaces (v = virtual; no physical NIC, totals use all but lo)"
    };
    let t = Table::new(rows, widths)
        .header(Row::new(header).style(dim()))
        .block(block(title));
    f.render_widget(t, area);
}

fn draw_tcp(f: &mut Frame, area: Rect, app: &App) {
    if area.height < 3 {
        return;
    }
    let s = &app.snap;
    let Some(t) = &s.tcp else {
        f.render_widget(
            Paragraph::new(super::unavailable("/proc/net/snmp")).block(block("TCP")),
            area,
        );
        return;
    };
    let opt = |v: Option<u64>| v.map_or("n/a".into(), |v| v.to_string());
    let rate = |v: f64| format!("{}/s", fmt_count(v));
    let rate_opt = |v: Option<f64>| v.map_or("n/a".into(), rate);
    let row = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("{label:<22}"), dim()),
            Span::raw(value),
        ])
    };
    let have_rates = s.interval.is_some();
    let mut lines = vec![
        row("Established", t.established.to_string()),
        row(
            "TIME_WAIT / orphan",
            format!("{} / {}", opt(t.sockets.tcp_tw), opt(t.sockets.tcp_orphan)),
        ),
        row(
            "Sockets in use",
            format!(
                "TCP {}  UDP {}",
                opt(t.sockets.tcp_inuse),
                opt(t.sockets.udp_inuse)
            ),
        ),
    ];
    if have_rates {
        let mut retr = vec![
            Span::styled(format!("{:<22}", "Retransmits"), dim()),
            Span::raw(rate(t.retrans_per_s)),
        ];
        if let Some(p) = t.retrans_pct() {
            retr.push(Span::styled(
                format!("  ({} of sent)", fmt_pct(p)),
                level(p * 20.0),
            ));
        }
        lines.push(Line::from(retr));
        lines.push(row(
            "Opens active/passive",
            format!(
                "{} / {}",
                rate(t.active_opens_per_s),
                rate(t.passive_opens_per_s)
            ),
        ));
        lines.push(row(
            "Failed / resets",
            format!(
                "{} / {}",
                rate(t.attempt_fails_per_s),
                rate(t.estab_resets_per_s)
            ),
        ));
        lines.push(row(
            "In errors / RST sent",
            format!("{} / {}", rate(t.in_errs_per_s), rate(t.out_rsts_per_s)),
        ));
        lines.push(row(
            "Listen ovf/drops",
            format!(
                "{} / {}",
                rate_opt(t.listen_overflows_per_s),
                rate_opt(t.listen_drops_per_s)
            ),
        ));
        lines.push(row(
            "Segments in/out",
            format!("{} / {}", rate(t.in_segs_per_s), rate(t.out_segs_per_s)),
        ));
    } else {
        lines.push(super::collecting());
    }
    f.render_widget(Paragraph::new(lines).block(block("TCP")), area);
}
