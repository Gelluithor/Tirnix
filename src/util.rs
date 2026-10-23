//! Small helpers: number formatting and calendar arithmetic.
//!
//! Tirnix avoids a date/time dependency; the conversions below implement the
//! proleptic Gregorian calendar (Howard Hinnant's `days_from_civil`).

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds (fractional).
pub fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Format a byte count using binary units, e.g. `1.5 GiB`.
pub fn fmt_bytes(bytes: f64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if !bytes.is_finite() || bytes < 0.0 {
        return "n/a".into();
    }
    let mut v = bytes;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{v:.0} B")
    } else if v < 10.0 {
        format!("{v:.2} {}", UNITS[unit])
    } else if v < 100.0 {
        format!("{v:.1} {}", UNITS[unit])
    } else {
        format!("{v:.0} {}", UNITS[unit])
    }
}

/// Format a byte rate, e.g. `12.3 MiB/s`.
pub fn fmt_rate(bytes_per_sec: f64) -> String {
    format!("{}/s", fmt_bytes(bytes_per_sec))
}

/// Format a plain count rate with an SI suffix, e.g. `1.2k`.
pub fn fmt_count(v: f64) -> String {
    if !v.is_finite() {
        return "n/a".into();
    }
    let a = v.abs();
    if a >= 1e9 {
        format!("{:.1}G", v / 1e9)
    } else if a >= 1e6 {
        format!("{:.1}M", v / 1e6)
    } else if a >= 1e4 {
        format!("{:.0}k", v / 1e3)
    } else if a >= 1e3 {
        format!("{:.1}k", v / 1e3)
    } else if a >= 10.0 || v == 0.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

pub fn opt_count(v: Option<f64>) -> String {
    v.map_or_else(|| "n/a".into(), fmt_count)
}

pub fn fmt_pct(v: f64) -> String {
    if v < 10.0 {
        format!("{v:.1}%")
    } else {
        format!("{v:.0}%")
    }
}

pub fn opt_pct(v: Option<f64>) -> String {
    v.map_or_else(|| "n/a".into(), fmt_pct)
}

/// Human readable duration, e.g. `3d 4h`, `5m 10s`.
pub fn fmt_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "n/a".into();
    }
    let s = secs as u64;
    let (d, h, m, s) = (s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Ratio as a percentage, `None` when the denominator is zero.
pub fn pct(part: f64, whole: f64) -> Option<f64> {
    (whole > 0.0).then(|| (part / whole * 100.0).clamp(0.0, 100.0))
}

/// Round to two decimals; keeps stored JSON compact.
pub fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------
// Calendar arithmetic
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 for a civil date.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date for days since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Broken-down time: (year, month, day, hour, minute, second).
pub type Civil = (i64, u32, u32, u32, u32, u32);

pub fn civil_from_unix(ts: i64) -> Civil {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (secs / 3600) as u32,
        ((secs % 3600) / 60) as u32,
        (secs % 60) as u32,
    )
}

/// Offset of local time from UTC in seconds at the given instant.
pub fn local_offset(ts: i64) -> i64 {
    let t = ts as _;
    // SAFETY: `tm` is plain data; localtime_r only writes into it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if ok { tm.tm_gmtoff as i64 } else { 0 }
}

/// `YYYY-MM-DD HH:MM:SS` in local time.
pub fn fmt_local_datetime(ts: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(ts + local_offset(ts));
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// `HH:MM` in local time.
pub fn fmt_local_hm(ts: i64) -> String {
    let (_, _, _, h, mi, _) = civil_from_unix(ts + local_offset(ts));
    format!("{h:02}:{mi:02}")
}

/// `HH:MM:SS` in local time.
pub fn fmt_local_hms(ts: i64) -> String {
    let (_, _, _, h, mi, s) = civil_from_unix(ts + local_offset(ts));
    format!("{h:02}:{mi:02}:{s:02}")
}

/// `MM-DD HH:MM` in local time.
pub fn fmt_local_mdhm(ts: i64) -> String {
    let (_, mo, d, h, mi, _) = civil_from_unix(ts + local_offset(ts));
    format!("{mo:02}-{d:02} {h:02}:{mi:02}")
}

/// Parse a duration like `90s`, `15m`, `6h`, `7d` (a bare number means seconds).
pub fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86_400),
        'w' => (&s[..s.len() - 1], 604_800),
        _ => (s, 1),
    };
    let n: i64 = num.parse().ok()?;
    (n >= 0).then_some(n * mult)
}

/// Parse a point in time given as Unix seconds or as UTC
/// `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM` or `YYYY-MM-DDTHH:MM:SS`
/// (a space may be used instead of `T`).
pub fn parse_timestamp(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let (date, time) = match s.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t.trim_end_matches('Z'))),
        None => (s, None),
    };
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let m: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut secs = 0i64;
    if let Some(t) = time {
        let mut tp = t.split(':');
        let h: i64 = tp.next()?.parse().ok()?;
        let mi: i64 = tp.next().unwrap_or("0").parse().ok()?;
        let se: i64 = tp.next().unwrap_or("0").parse().ok()?;
        if tp.next().is_some() || h > 23 || mi > 59 || se > 60 {
            return None;
        }
        secs = h * 3600 + mi * 60 + se;
    }
    Some(days_from_civil(y, m, d) * 86_400 + secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_formatting() {
        assert_eq!(fmt_bytes(0.0), "0 B");
        assert_eq!(fmt_bytes(1023.0), "1023 B");
        assert_eq!(fmt_bytes(1536.0), "1.50 KiB");
        assert_eq!(fmt_bytes(50.0 * 1024.0 * 1024.0), "50.0 MiB");
        assert_eq!(fmt_bytes(-1.0), "n/a");
    }

    #[test]
    fn count_formatting() {
        assert_eq!(fmt_count(0.0), "0");
        assert_eq!(fmt_count(3.25), "3.2");
        assert_eq!(fmt_count(1500.0), "1.5k");
        assert_eq!(fmt_count(25_000.0), "25k");
        assert_eq!(fmt_count(2_500_000.0), "2.5M");
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(fmt_duration(5.0), "5s");
        assert_eq!(fmt_duration(65.0), "1m 5s");
        assert_eq!(fmt_duration(3.0 * 3600.0 + 120.0), "3h 2m");
        assert_eq!(fmt_duration(90_000.0), "1d 1h");
    }

    #[test]
    fn civil_roundtrip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        for days in [-1000, 0, 59, 60, 11_016, 19_000, 20_000, 60_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        // 2024-02-29 12:34:56 UTC
        assert_eq!(civil_from_unix(1_709_210_096), (2024, 2, 29, 12, 34, 56));
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("90"), Some(90));
        assert_eq!(parse_duration("15m"), Some(900));
        assert_eq!(parse_duration("24h"), Some(86_400));
        assert_eq!(parse_duration("7d"), Some(604_800));
        assert_eq!(parse_duration("x"), None);
        assert_eq!(parse_duration("-5m"), None);
    }

    #[test]
    fn timestamps_parse() {
        assert_eq!(parse_timestamp("1700000000"), Some(1_700_000_000));
        assert_eq!(parse_timestamp("2024-02-29"), Some(1_709_164_800));
        assert_eq!(parse_timestamp("2024-02-29T12:34:56"), Some(1_709_210_096));
        assert_eq!(parse_timestamp("2024-02-29 12:34"), Some(1_709_210_040));
        assert_eq!(parse_timestamp("2024-13-01"), None);
        assert_eq!(parse_timestamp("garbage"), None);
    }

    #[test]
    fn pct_handles_zero() {
        assert_eq!(pct(1.0, 0.0), None);
        assert_eq!(pct(1.0, 4.0), Some(25.0));
    }
}
