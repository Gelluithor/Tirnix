//! Shared drawing helpers: theme, bars, key/value spans.

use std::sync::OnceLock;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders};

use crate::diagnose::Severity;

struct Theme {
    color: bool,
    utf8: bool,
}

fn theme() -> &'static Theme {
    static T: OnceLock<Theme> = OnceLock::new();
    T.get_or_init(|| {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        // https://no-color.org
        let color = env("NO_COLOR").is_none();
        let locale = env("LC_ALL")
            .or_else(|| env("LC_CTYPE"))
            .or_else(|| env("LANG"));
        let utf8 = env("TIRNIX_ASCII").is_none()
            && locale.is_none_or(|l| {
                let l = l.to_ascii_lowercase();
                l.contains("utf-8") || l.contains("utf8")
            });
        Theme { color, utf8 }
    })
}

pub fn utf8() -> bool {
    theme().utf8
}

pub fn fg(c: Color) -> Style {
    if theme().color {
        Style::new().fg(c)
    } else {
        Style::new()
    }
}

pub fn dim() -> Style {
    if theme().color {
        Style::new().fg(Color::DarkGray)
    } else {
        Style::new().add_modifier(Modifier::DIM)
    }
}

pub fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    fg(Color::Cyan)
}

pub fn selected() -> Style {
    // Reverse video works with every terminal palette and keeps dimmed or
    // coloured text in the selected row readable.
    Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

/// Green / yellow / red for a utilisation percentage.
pub fn level(pct: f64) -> Style {
    if pct >= 90.0 {
        fg(Color::Red)
    } else if pct >= 70.0 {
        fg(Color::Yellow)
    } else {
        fg(Color::Green)
    }
}

pub fn severity(s: Severity) -> Style {
    match s {
        Severity::Critical => fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::Warning => fg(Color::Yellow).add_modifier(Modifier::BOLD),
        Severity::Info => fg(Color::Blue),
    }
}

pub fn severity_symbol(s: Severity) -> &'static str {
    match (s, utf8()) {
        (Severity::Critical, true) => "✖",
        (Severity::Warning, true) => "▲",
        (Severity::Info, true) => "●",
        (Severity::Critical, false) => "X",
        (Severity::Warning, false) => "!",
        (Severity::Info, false) => "i",
    }
}

pub fn block(title: &str) -> Block<'static> {
    let b = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), bold()))
        .border_style(dim());
    if utf8() {
        b.border_type(BorderType::Rounded)
    } else {
        b
    }
}

/// A horizontal bar of `width` cells, filled to `pct` (0–100). Uses
/// eighth-block characters for sub-cell precision when UTF-8 is available.
pub fn bar(pct: f64, width: usize, style: Style) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let pct = if pct.is_finite() {
        pct.clamp(0.0, 100.0)
    } else {
        0.0
    };
    let exact = pct / 100.0 * width as f64;
    let full = exact.floor() as usize;
    let mut filled = String::new();
    let mut empty = String::new();
    if utf8() {
        const PARTS: [&str; 8] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
        filled.push_str(&"█".repeat(full));
        let mut used = full;
        let part = ((exact - full as f64) * 8.0).floor() as usize;
        if full < width && part > 0 {
            filled.push_str(PARTS[part]);
            used += 1;
        }
        empty.push_str(&"·".repeat(width - used));
    } else {
        filled.push_str(&"#".repeat(full));
        empty.push_str(&".".repeat(width - full));
    }
    vec![Span::styled(filled, style), Span::styled(empty, dim())]
}

/// `label  [bar] 45%  detail` on one line.
pub fn meter(label: &str, pct: Option<f64>, bar_width: usize, detail: String) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("{label:<5}"), bold())];
    match pct {
        Some(p) => {
            spans.extend(bar(p, bar_width, level(p)));
            spans.push(Span::styled(
                format!(" {:>5}", crate::util::fmt_pct(p)),
                level(p),
            ));
        }
        None => {
            spans.push(Span::styled(
                format!("{:<w$}", "n/a", w = bar_width + 6),
                dim(),
            ));
        }
    }
    if !detail.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::raw(detail));
    }
    Line::from(spans)
}

/// `label value` pair, label dimmed.
pub fn kv(label: &str, value: impl Into<String>) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!("{label} "), dim()),
        Span::raw(value.into()),
    ]
}

pub fn na() -> Span<'static> {
    Span::styled("n/a", dim())
}

/// Truncate to `width` characters, adding an ellipsis.
pub fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let ell = if utf8() { "…" } else { "~" };
    let mut out: String = s.chars().take(width - 1).collect();
    out.push_str(ell);
    out
}

/// Rect centred in `area` with the given size (clamped to the area).
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// Convert optional values to sparkline bars scaled to integers.
pub fn spark_data(values: &[Option<f64>], scale: f64) -> Vec<Option<u64>> {
    values
        .iter()
        .map(|v| v.map(|x| (x.max(0.0) * scale).round() as u64))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(spans: &[Span]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn bar_widths_are_exact() {
        for pct in [0.0, 12.5, 50.0, 99.9, 100.0, 150.0, f64::NAN] {
            for w in [1, 7, 20] {
                assert_eq!(
                    text(&bar(pct, w, Style::new())).chars().count(),
                    w,
                    "{pct} {w}"
                );
            }
        }
        assert!(bar(50.0, 0, Style::new()).is_empty());
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5).chars().count(), 5);
        assert_eq!(truncate("x", 0), "");
    }

    #[test]
    fn centering() {
        let a = Rect::new(0, 0, 100, 40);
        assert_eq!(centered(a, 20, 10), Rect::new(40, 15, 20, 10));
        assert_eq!(centered(a, 200, 100), a);
    }
}
