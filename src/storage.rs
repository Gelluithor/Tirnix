//! Persistent history: hourly JSON Lines files.
//!
//! Layout: `<dir>/metrics-YYYYMMDD-HH.jsonl` (hour in UTC), one [`Record`]
//! per line. Retention works on whole files, so it never rewrites data.
//! Files that do not match the naming pattern are never touched.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::metrics::Record;
use crate::util;

const PREFIX: &str = "metrics-";
const SUFFIX: &str = ".jsonl";

/// Name of the file holding records for the hour containing `ts`.
pub fn file_name_for(ts: i64) -> String {
    let (y, m, d, h, _, _) = util::civil_from_unix(ts);
    format!("{PREFIX}{y:04}{m:02}{d:02}-{h:02}{SUFFIX}")
}

/// Start of the hour encoded in a data file name.
pub fn parse_file_name(name: &str) -> Option<i64> {
    let core = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    let (date, hour) = core.split_once('-')?;
    if date.len() != 8 || hour.len() != 2 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let y: i64 = date[0..4].parse().ok()?;
    let m: u32 = date[4..6].parse().ok()?;
    let d: u32 = date[6..8].parse().ok()?;
    let h: i64 = hour.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 {
        return None;
    }
    Some(util::days_from_civil(y, m, d) * 86_400 + h * 3600)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFile {
    pub hour_start: i64,
    pub path: PathBuf,
    pub size: u64,
}

/// All data files in `dir`, oldest first. A missing directory is empty.
pub fn list_files(dir: &Path) -> io::Result<Vec<DataFile>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out: Vec<DataFile> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let hour_start = parse_file_name(name.to_str()?)?;
            let meta = e.metadata().ok()?;
            meta.is_file().then(|| DataFile {
                hour_start,
                path: e.path(),
                size: meta.len(),
            })
        })
        .collect();
    out.sort_by_key(|f| f.hour_start);
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    pub files: usize,
    pub bytes: u64,
    pub oldest_hour: Option<i64>,
    pub newest_hour: Option<i64>,
}

/// Delete files older than `retention_days` and then the oldest files until
/// the total size is at most `max_bytes`. The file for the current hour is
/// never deleted by the size rule. Returns the number of removed files.
pub fn enforce_retention(
    dir: &Path,
    retention_days: u64,
    max_bytes: u64,
    now: i64,
) -> io::Result<usize> {
    let files = list_files(dir)?;
    let cutoff = now - retention_days as i64 * 86_400;
    let current_hour = now - now.rem_euclid(3600);
    let mut total: u64 = files.iter().map(|f| f.size).sum();
    let mut removed = 0;
    for f in &files {
        // A file covers [hour_start, hour_start + 1h).
        let expired = f.hour_start + 3600 <= cutoff;
        let over = total > max_bytes && f.hour_start < current_hour;
        if expired || over {
            match fs::remove_file(&f.path) {
                Ok(()) => {
                    total = total.saturating_sub(f.size);
                    removed += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(removed)
}

/// Read all records with `from <= t < to`, in time order. Lines that do not
/// parse (e.g. a line torn by a crash) are skipped.
pub fn read_range(dir: &Path, from: i64, to: i64) -> io::Result<Vec<Record>> {
    let mut out = Vec::new();
    for_each_in_range(dir, from, to, |r| out.push(r))?;
    out.sort_by_key(|r| r.t);
    Ok(out)
}

/// Stream records with `from <= t < to` file by file (roughly time order)
/// without keeping them in memory.
pub fn for_each_in_range(
    dir: &Path,
    from: i64,
    to: i64,
    mut f: impl FnMut(Record),
) -> io::Result<()> {
    let mut line = String::new();
    for file in list_files(dir)? {
        if file.hour_start + 3600 <= from || file.hour_start >= to {
            continue;
        }
        let handle = match File::open(&file.path) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let mut rd = BufReader::new(handle);
        loop {
            line.clear();
            match rd.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if let Ok(r) = serde_json::from_str::<Record>(line.trim_end())
                && r.t >= from
                && r.t < to
            {
                f(r);
            }
        }
    }
    Ok(())
}

/// Appends records to the file for the current hour, switching files on
/// hour boundaries. Flushes at most every `flush_every` to limit writes.
pub struct Writer {
    dir: PathBuf,
    hour: i64,
    file: Option<BufWriter<File>>,
    last_flush: Instant,
    flush_every: Duration,
}

impl Writer {
    pub fn new(dir: &Path, flush_every: Duration) -> Self {
        Writer {
            dir: dir.to_path_buf(),
            hour: i64::MIN,
            file: None,
            last_flush: Instant::now(),
            flush_every,
        }
    }

    pub fn append(&mut self, r: &Record) -> io::Result<()> {
        let hour = r.t - r.t.rem_euclid(3600);
        if self.file.is_none() || hour != self.hour {
            self.flush()?;
            let path = self.dir.join(file_name_for(r.t));
            let f = open_append(&path)?;
            self.file = Some(BufWriter::with_capacity(16 * 1024, f));
            self.hour = hour;
        }
        let w = self.file.as_mut().expect("file opened above");
        serde_json::to_writer(&mut *w, r).map_err(io::Error::other)?;
        w.write_all(b"\n")?;
        if self.last_flush.elapsed() >= self.flush_every {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.flush()?;
        }
        self.last_flush = Instant::now();
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o640);
    }
    opts.open(path)
}

/// Create the data directory (owner-only permissions) if it is missing.
pub fn ensure_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A unique temporary directory removed on drop.
    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "tirnix-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rec(t: i64) -> Record {
        Record {
            t,
            cpu: Some(t as f64 % 100.0),
            ..Default::default()
        }
    }

    #[test]
    fn file_names() {
        // 2024-02-29 12:34:56 UTC
        let ts = 1_709_210_096;
        let n = file_name_for(ts);
        assert_eq!(n, "metrics-20240229-12.jsonl");
        assert_eq!(parse_file_name(&n), Some(ts - ts % 3600));
        assert_eq!(parse_file_name("metrics-2024022-12.jsonl"), None);
        assert_eq!(parse_file_name("notes.txt"), None);
        assert_eq!(parse_file_name("metrics-20241301-00.jsonl"), None);
    }

    #[test]
    fn write_and_read_back_across_hours() {
        let d = TempDir::new("store");
        let base = 1_700_000_000 - 1_700_000_000 % 3600;
        {
            let mut w = Writer::new(&d.0, Duration::ZERO);
            for i in 0..10 {
                w.append(&rec(base + i * 900)).unwrap(); // every 15 min
            }
        }
        let files = list_files(&d.0).unwrap();
        assert_eq!(files.len(), 3);
        let all = read_range(&d.0, 0, i64::MAX).unwrap();
        assert_eq!(all.len(), 10);
        let part = read_range(&d.0, base + 1800, base + 4500).unwrap();
        assert_eq!(
            part.iter().map(|r| r.t).collect::<Vec<_>>(),
            vec![base + 1800, base + 2700, base + 3600]
        );
    }

    #[test]
    fn torn_lines_are_skipped() {
        let d = TempDir::new("torn");
        let t = 1_700_000_000;
        let path = d.0.join(file_name_for(t));
        fs::write(
            &path,
            format!("{{\"t\":{t},\"cpu\":5}}\n{{\"t\":{},\"cp", t + 1),
        )
        .unwrap();
        let r = read_range(&d.0, 0, i64::MAX).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].cpu, Some(5.0));
    }

    #[test]
    fn retention_by_age() {
        let d = TempDir::new("ret-age");
        let now = 1_700_000_000;
        for h in 0..72 {
            let t = now - h * 3600;
            fs::write(d.0.join(file_name_for(t)), "{}\n").unwrap();
        }
        fs::write(d.0.join("keep-me.txt"), "user file").unwrap();
        let removed = enforce_retention(&d.0, 1, u64::MAX, now).unwrap();
        let left = list_files(&d.0).unwrap();
        assert_eq!(removed + left.len(), 72);
        assert!(left.iter().all(|f| f.hour_start + 3600 > now - 86_400));
        assert!(d.0.join("keep-me.txt").exists());
    }

    #[test]
    fn retention_by_size_keeps_current_hour() {
        let d = TempDir::new("ret-size");
        let now = 1_700_000_000;
        for h in 0..5 {
            fs::write(d.0.join(file_name_for(now - h * 3600)), vec![b'x'; 100]).unwrap();
        }
        enforce_retention(&d.0, 365, 250, now).unwrap();
        let left = list_files(&d.0).unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(left.last().unwrap().hour_start, now - now % 3600);
        // Even a limit of zero keeps the file currently being written.
        enforce_retention(&d.0, 365, 0, now).unwrap();
        assert_eq!(list_files(&d.0).unwrap().len(), 1);
    }

    #[test]
    fn missing_dir_is_empty() {
        assert!(
            list_files(Path::new("/nonexistent/tirnix"))
                .unwrap()
                .is_empty()
        );
        assert!(
            read_range(Path::new("/nonexistent/tirnix"), 0, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }
}
