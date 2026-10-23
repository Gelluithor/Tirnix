//! In-memory history of recent [`Record`]s plus statistics helpers used by
//! diagnostics and the History screen.

use std::collections::VecDeque;

use crate::metrics::Record;

pub struct Window {
    buf: VecDeque<Record>,
    cap: usize,
}

impl Window {
    pub fn new(cap: usize) -> Self {
        Window {
            buf: VecDeque::with_capacity(cap.min(4096)),
            cap: cap.max(1),
        }
    }

    pub fn push(&mut self, r: Record) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(r);
    }

    pub fn last(&self) -> Option<&Record> {
        self.buf.back()
    }

    pub fn first(&self) -> Option<&Record> {
        self.buf.front()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Record> {
        self.buf.iter()
    }

    /// Records with `t >= since`.
    pub fn since(&self, since: i64) -> impl Iterator<Item = &Record> {
        // Records are appended in time order, so scan from the back.
        let start = self.buf.len() - self.buf.iter().rev().take_while(|r| r.t >= since).count();
        self.buf.range(start..)
    }

    /// True when `pred` held for at least 80 % of the samples in the last
    /// `secs` seconds, and those samples actually cover most of that span.
    /// Samples for which the metric is unknown (`None`) are ignored.
    ///
    /// This is the main guard against false alarms: a single spike never
    /// satisfies a sustained condition.
    pub fn sustained(&self, now: i64, secs: i64, pred: impl Fn(&Record) -> Option<bool>) -> bool {
        let since = now - secs;
        let mut known = 0usize;
        let mut hits = 0usize;
        let mut oldest = i64::MAX;
        for r in self.since(since) {
            if let Some(b) = pred(r) {
                known += 1;
                hits += usize::from(b);
                oldest = oldest.min(r.t);
            }
        }
        let covered = now - oldest;
        known >= 3 && covered * 10 >= secs * 7 && hits * 10 >= known * 8
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    pub n: usize,
    pub min: f64,
    pub avg: f64,
    pub p95: f64,
    pub max: f64,
}

/// Summary statistics; `None` for an empty input.
pub fn stats(values: &[f64]) -> Option<Stats> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    // Nearest-rank percentile.
    let rank = ((0.95 * n as f64).ceil() as usize).clamp(1, n);
    Some(Stats {
        n,
        min: v[0],
        avg: v.iter().sum::<f64>() / n as f64,
        p95: v[rank - 1],
        max: v[n - 1],
    })
}

/// One downsampled bucket: average and maximum of the values inside it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bucket {
    pub t: i64,
    pub avg: f64,
    pub max: f64,
}

/// Split `[from, to)` into `n` equal buckets and aggregate the `(t, value)`
/// points in each. Empty buckets are `None` (a gap, not a zero).
pub fn downsample(
    points: impl IntoIterator<Item = (i64, f64)>,
    from: i64,
    to: i64,
    n: usize,
) -> Vec<Option<Bucket>> {
    if n == 0 || to <= from {
        return Vec::new();
    }
    let span = (to - from) as f64;
    let mut acc = vec![(0.0f64, 0usize, f64::MIN); n];
    for (t, v) in points {
        if t < from || t >= to {
            continue;
        }
        let i = (((t - from) as f64 / span) * n as f64) as usize;
        let a = &mut acc[i.min(n - 1)];
        a.0 += v;
        a.1 += 1;
        a.2 = a.2.max(v);
    }
    acc.into_iter()
        .enumerate()
        .map(|(i, (sum, cnt, max))| {
            (cnt > 0).then(|| Bucket {
                t: from + (span * i as f64 / n as f64) as i64,
                avg: sum / cnt as f64,
                max,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(t: i64, cpu: f64) -> Record {
        Record {
            t,
            cpu: Some(cpu),
            ..Default::default()
        }
    }

    #[test]
    fn ring_buffer_caps() {
        let mut w = Window::new(3);
        for i in 0..5 {
            w.push(rec(i, i as f64));
        }
        assert_eq!(w.iter().count(), 3);
        assert_eq!(w.first().unwrap().t, 2);
        assert_eq!(w.last().unwrap().cpu, Some(4.0));
    }

    #[test]
    fn since_filters_by_time() {
        let mut w = Window::new(10);
        for i in 0..10 {
            w.push(rec(i * 10, 0.0));
        }
        assert_eq!(w.since(70).count(), 3);
        assert_eq!(w.since(1000).count(), 0);
        assert_eq!(w.since(-5).count(), 10);
    }

    #[test]
    fn sustained_requires_duration_and_majority() {
        let mut w = Window::new(100);
        // 30 s of high CPU sampled every 2 s.
        for i in 0..=15 {
            w.push(rec(1000 + i * 2, 95.0));
        }
        let now = 1030;
        assert!(w.sustained(now, 30, |r| r.cpu.map(|c| c > 90.0)));
        // Not enough history for a 60 s window.
        assert!(!w.sustained(now, 60, |r| r.cpu.map(|c| c > 90.0)));
    }

    #[test]
    fn single_spike_is_not_sustained() {
        let mut w = Window::new(100);
        for i in 0..=15 {
            let v = if i == 10 { 100.0 } else { 5.0 };
            w.push(rec(1000 + i * 2, v));
        }
        assert!(!w.sustained(1030, 30, |r| r.cpu.map(|c| c > 90.0)));
    }

    #[test]
    fn unknown_values_are_ignored() {
        let mut w = Window::new(100);
        for i in 0..=15 {
            w.push(Record {
                t: 1000 + i * 2,
                ..Default::default()
            });
        }
        assert!(!w.sustained(1030, 30, |r| r.cpu.map(|c| c > 90.0)));
    }

    #[test]
    fn stats_percentiles() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        let s = stats(&v).unwrap();
        assert_eq!(s.n, 100);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.max, 100.0);
        assert_eq!(s.p95, 95.0);
        assert!((s.avg - 50.5).abs() < 1e-9);
        assert!(stats(&[]).is_none());
        assert_eq!(stats(&[7.0]).unwrap().p95, 7.0);
    }

    #[test]
    fn downsample_buckets_and_gaps() {
        let pts = vec![(0, 10.0), (1, 20.0), (5, 50.0), (9, 90.0), (10, 1.0)];
        let b = downsample(pts, 0, 10, 5);
        assert_eq!(b.len(), 5);
        assert_eq!(b[0].unwrap().avg, 15.0);
        assert_eq!(b[0].unwrap().max, 20.0);
        assert!(b[1].is_none());
        assert_eq!(b[2].unwrap().avg, 50.0);
        assert_eq!(b[4].unwrap().max, 90.0);
    }
}
