//! History: chart of one metric over a time range, optionally compared with
//! the previous period of the same length.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Chart, Dataset, GraphType, Paragraph, Wrap};

use super::super::widgets::*;
use super::super::{App, RANGES, Series, history_metrics};
use crate::util::*;
use crate::window::Stats;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let metrics = history_metrics();
    app.hist.metric = app.hist.metric.min(metrics.len() - 1);
    let field = metrics[app.hist.metric];
    let (range_name, span) = RANGES[app.hist.range];

    let stats_h = if area.height >= 16 { 5 } else { 0 };
    let [sel, chart_area, stats_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Length(stats_h),
    ])
    .areas(area);

    // Range / metric selector.
    let mut ranges = vec![Span::styled(" Range ", dim())];
    for (i, (name, _)) in RANGES.iter().enumerate() {
        let st = if i == app.hist.range {
            selected()
        } else {
            ratatui::style::Style::new()
        };
        ranges.push(Span::styled(format!(" {name} "), st));
    }
    ranges.push(Span::styled("  ←→", dim()));
    let mut m = vec![
        Span::styled(" Metric ", dim()),
        Span::styled(
            field.label,
            accent().add_modifier(ratatui::style::Modifier::BOLD),
        ),
        Span::styled(format!(" ({})  ↑↓", field.key), dim()),
        Span::styled("   Compare ", dim()),
    ];
    if span == 0 {
        m.push(Span::styled("n/a for session", dim()));
    } else {
        m.push(Span::raw(if app.hist.compare {
            "previous period"
        } else {
            "off"
        }));
        m.push(Span::styled(" (c)", dim()));
    }
    if app.hist.loading {
        m.push(Span::styled("   loading…", accent()));
    }
    f.render_widget(Paragraph::new(vec![Line::from(ranges), Line::from(m)]), sel);

    // Resolution: braille gives two points per terminal column.
    app.hist.width = (chart_area.width.saturating_sub(12) as usize * 2).max(10);
    if let Some(e) = &app.hist.error {
        f.render_widget(
            Paragraph::new(Span::styled(e.clone(), fg(Color::Red)))
                .block(block("History"))
                .wrap(Wrap { trim: true }),
            chart_area,
        );
        return;
    }
    let Some(res) = app.hist.result.clone() else {
        f.render_widget(
            Paragraph::new(Span::styled("loading…", dim())).block(block("History")),
            chart_area,
        );
        return;
    };

    let has_data = res.current.stats.is_some();
    if !has_data {
        let mut lines = vec![Line::from(Span::styled(
            format!(
                "No {} data for \"{}\" in this range.",
                if res.stored { "stored" } else { "session" },
                field.label
            ),
            dim(),
        ))];
        if res.stored {
            if app.logger.usage.files == 0 {
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Long-term history is recorded only while background logging is enabled. \
                     Turn it on in Settings (8) → Long-term logging. It is off by default.",
                ));
            } else if !app
                .cfg
                .logging
                .metrics
                .iter()
                .any(|g| g == field.group.key())
            {
                lines.push(Line::from(format!(
                    "The \"{}\" metric group is not selected for logging (Settings → Metrics to store).",
                    field.group.key()
                )));
            }
            lines.push(Line::from(Span::styled(
                format!("Data directory: {}", app.cfg.data_dir().display()),
                dim(),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "This metric is not available on this system, or no samples were taken yet.",
                dim(),
            )));
        }
        f.render_widget(
            Paragraph::new(lines)
                .block(block("History"))
                .wrap(Wrap { trim: true }),
            chart_area,
        );
        return;
    }

    let to_points = |s: &Series, shift: i64| -> Vec<(f64, f64)> {
        s.buckets
            .iter()
            .flatten()
            .map(|b| ((b.t + shift - res.from) as f64, b.avg))
            .collect()
    };
    let cur = to_points(&res.current, 0);
    let prev = res.previous.as_ref().map(|p| to_points(p, span));
    let ymax = res
        .current
        .stats
        .map(|s| s.max)
        .into_iter()
        .chain(res.previous.as_ref().and_then(|p| p.stats.map(|s| s.max)))
        .fold(0.0, f64::max);
    let ymax = if field.unit == crate::metrics::Unit::Percent {
        if ymax <= 0.0 {
            100.0
        } else {
            (ymax * 1.1).clamp(1.0, 100.0)
        }
    } else if ymax <= 0.0 {
        1.0
    } else {
        ymax * 1.1
    };

    let marker = if utf8() { Marker::Braille } else { Marker::Dot };
    let mut datasets = Vec::new();
    if let Some(p) = &prev {
        push_series(&mut datasets, p, "previous period", dim(), marker);
    }
    push_series(&mut datasets, &cur, range_name, accent(), marker);
    let xspan = (res.to - res.from) as f64;
    let tfmt = |t: i64| {
        let span = res.to - res.from;
        if span > 86_400 {
            fmt_local_mdhm(t)
        } else if span > 3600 {
            fmt_local_hm(t)
        } else {
            fmt_local_hms(t)
        }
    };
    let x_labels = vec![
        Span::styled(tfmt(res.from), dim()),
        Span::styled(tfmt(res.from + (res.to - res.from) / 2), dim()),
        Span::styled(tfmt(res.to), dim()),
    ];
    let y_labels = vec![
        Span::styled(field.unit.format(0.0), dim()),
        Span::styled(field.unit.format(ymax / 2.0), dim()),
        Span::styled(field.unit.format(ymax), dim()),
    ];
    let title = format!("{} — {} (average per point)", field.label, range_name);
    let chart = Chart::new(datasets)
        .block(block(&title))
        .x_axis(Axis::default().bounds([0.0, xspan]).labels(x_labels))
        .y_axis(Axis::default().bounds([0.0, ymax]).labels(y_labels))
        .hidden_legend_constraints((Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)));
    // A legend only helps when two series are drawn.
    let chart = if prev.is_some() {
        chart
    } else {
        chart.legend_position(None)
    };
    f.render_widget(chart, chart_area);

    if stats_h > 0 {
        draw_stats(
            f,
            stats_area,
            field.unit,
            &res.current,
            res.previous.as_ref(),
        );
    }
}

fn stat_cells(unit: crate::metrics::Unit, s: Option<Stats>) -> Vec<Span<'static>> {
    match s {
        Some(s) => vec![
            Span::raw(format!("{:>12}", unit.format(s.avg))),
            Span::raw(format!("{:>12}", unit.format(s.p95))),
            Span::raw(format!("{:>12}", unit.format(s.max))),
            Span::styled(format!("{:>10}", s.n), dim()),
        ],
        None => vec![Span::styled(format!("{:>12}", "no data"), dim())],
    }
}

fn draw_stats(
    f: &mut Frame,
    area: Rect,
    unit: crate::metrics::Unit,
    cur: &Series,
    prev: Option<&Series>,
) {
    let mut lines = vec![Line::from(Span::styled(
        format!(
            "{:<18}{:>12}{:>12}{:>12}{:>10}",
            "", "average", "p95", "max", "samples"
        ),
        dim(),
    ))];
    let mut l = vec![Span::raw(format!("{:<18}", "This period"))];
    l.extend(stat_cells(unit, cur.stats));
    lines.push(Line::from(l));
    if let Some(p) = prev {
        let mut l = vec![Span::raw(format!("{:<18}", "Previous period"))];
        l.extend(stat_cells(unit, p.stats));
        lines.push(Line::from(l));
        if let (Some(a), Some(b)) = (cur.stats, p.stats) {
            let change = if b.avg.abs() > f64::EPSILON {
                format!("{:+.0}%", (a.avg - b.avg) / b.avg * 100.0)
            } else {
                "n/a".into()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{:<18}", "Change of average"), dim()),
                Span::styled(format!("{change:>12}"), bold()),
            ]));
        }
    }
    f.render_widget(Paragraph::new(lines).block(block("Statistics")), area);
}

/// One line per contiguous run, so gaps in the data stay visible.
fn push_series<'a>(
    out: &mut Vec<Dataset<'a>>,
    pts: &'a [(f64, f64)],
    name: &'a str,
    style: ratatui::style::Style,
    marker: Marker,
) {
    for (i, seg) in segments(pts).into_iter().enumerate() {
        let kind = if seg.len() > 1 {
            GraphType::Line
        } else {
            GraphType::Scatter
        };
        let mut d = Dataset::default()
            .marker(marker)
            .graph_type(kind)
            .style(style)
            .data(seg);
        if i == 0 {
            d = d.name(name);
        }
        out.push(d);
    }
}

/// Split points into runs, breaking where the spacing is much larger than
/// usual (missing samples, logger not running).
fn segments(points: &[(f64, f64)]) -> Vec<&[(f64, f64)]> {
    if points.len() < 2 {
        return if points.is_empty() {
            Vec::new()
        } else {
            vec![points]
        };
    }
    let mut gaps: Vec<f64> = points.windows(2).map(|w| w[1].0 - w[0].0).collect();
    gaps.sort_by(f64::total_cmp);
    let limit = gaps[gaps.len() / 2] * 3.0;
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..points.len() {
        if points[i].0 - points[i - 1].0 > limit {
            out.push(&points[start..i]);
            start = i;
        }
    }
    out.push(&points[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::segments;

    #[test]
    fn gaps_split_lines() {
        let pts: Vec<(f64, f64)> = [0.0, 1.0, 2.0, 3.0, 20.0, 21.0, 22.0]
            .iter()
            .map(|x| (*x, 1.0))
            .collect();
        let s = segments(&pts);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].len(), 4);
        assert_eq!(s[1].len(), 3);
        assert_eq!(segments(&pts[..1]).len(), 1);
        assert!(segments(&[]).is_empty());
    }
}
