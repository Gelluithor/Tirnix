//! Long-term logging process (`tirnix logger run`).
//!
//! The logger is a separate process so that it keeps running after the TUI
//! exits. Exactly one logger may run per data directory: it holds an
//! exclusive `flock` on `<data_dir>/logger.lock` for its whole lifetime.
//! The lock (not the pid file) is the source of truth for "is it running".

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::collect::{self, Collector};
use crate::config::Config;
use crate::metrics::{Group, Record};
use crate::storage;
use crate::util;

/// Exit status when logging is disabled in the config. The systemd unit
/// lists it in `RestartPreventExitStatus` so it does not restart in a loop.
pub const EXIT_DISABLED: i32 = 78;

const RETENTION_EVERY: Duration = Duration::from_secs(600);
const MAX_LOG_FILE: u64 = 1024 * 1024;

pub fn lock_path(dir: &Path) -> PathBuf {
    dir.join("logger.lock")
}

pub fn pid_path(dir: &Path) -> PathBuf {
    dir.join("logger.pid")
}

pub fn log_path(dir: &Path) -> PathBuf {
    dir.join("logger.log")
}

fn flock(f: &File, op: libc::c_int) -> io::Result<bool> {
    // SAFETY: valid fd owned by `f`.
    if unsafe { libc::flock(f.as_raw_fd(), op | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// Try to take the exclusive lock. `Ok(None)` means another process has it.
fn acquire_lock(dir: &Path) -> io::Result<Option<File>> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path(dir))?;
    Ok(flock(&f, libc::LOCK_EX)?.then_some(f))
}

#[derive(Debug, Clone, Default)]
pub struct Status {
    pub running: bool,
    pub pid: Option<u32>,
    pub dir: PathBuf,
    pub usage: storage::Usage,
    /// Modification time of the newest data file.
    pub last_write: Option<i64>,
}

pub fn status(dir: &Path) -> Status {
    let running = match File::open(lock_path(dir)) {
        // If we can take a shared lock, nobody holds the exclusive one.
        // The temporary lock is released when `f` is dropped.
        Ok(f) => matches!(flock(&f, libc::LOCK_SH), Ok(false)),
        Err(_) => false,
    };
    let pid = if running {
        fs::read_to_string(pid_path(dir))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    } else {
        None
    };
    let files = storage::list_files(dir).unwrap_or_default();
    let last_write = files.last().and_then(|f| {
        fs::metadata(&f.path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
    });
    Status {
        running,
        pid,
        dir: dir.to_path_buf(),
        usage: storage::Usage {
            files: files.len(),
            bytes: files.iter().map(|f| f.size).sum(),
            oldest_hour: files.first().map(|f| f.hour_start),
            newest_hour: files.last().map(|f| f.hour_start),
        },
        last_write,
    }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    // Only async-signal-safe operations: atomic stores.
    if sig == libc::SIGHUP {
        RELOAD.store(true, Ordering::SeqCst);
    } else {
        STOP.store(true, Ordering::SeqCst);
    }
}

fn install_signal_handlers() {
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: a zeroed sigaction is valid; the handler only touches atomics.
        // No SA_RESTART, so a signal interrupts nanosleep immediately.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Sleep until `deadline` or until a signal arrives, whichever is first.
fn sleep_until(deadline: Instant) {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return;
    }
    let ts = libc::timespec {
        tv_sec: left.as_secs() as _,
        tv_nsec: left.subsec_nanos() as _,
    };
    // SAFETY: plain syscall; EINTR is the expected way to wake up early.
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
}

fn log(msg: impl AsRef<str>) {
    eprintln!(
        "{} tirnix-logger: {}",
        util::fmt_local_datetime(util::now_unix() as i64),
        msg.as_ref()
    );
}

fn config_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

/// Run the logger in the foreground until stopped. Returns the exit code.
pub fn run(config_path: &Path) -> i32 {
    let mut cfg = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            log(format!("error: {e}"));
            return 1;
        }
    };
    if !cfg.logging.enabled {
        log(format!(
            "logging is disabled in {} (set [logging] enabled = true, or enable it in the TUI Settings screen)",
            config_path.display()
        ));
        return EXIT_DISABLED;
    }
    if !collect::procfs_available() {
        log("warning: /proc is not available; most metrics will be missing");
    }
    let dir = cfg.data_dir();
    if let Err(e) = storage::ensure_dir(&dir) {
        log(format!(
            "error: cannot create data directory {}: {e}",
            dir.display()
        ));
        return 1;
    }
    // The TUI may briefly hold a shared lock while checking status; retry.
    let mut lock = None;
    for _ in 0..10 {
        match acquire_lock(&dir) {
            Ok(Some(f)) => {
                lock = Some(f);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => {
                log(format!(
                    "error: cannot lock {}: {e}",
                    lock_path(&dir).display()
                ));
                return 1;
            }
        }
    }
    let Some(_lock) = lock else {
        let pid = fs::read_to_string(pid_path(&dir)).unwrap_or_default();
        log(format!(
            "another logger is already running for {} (pid {})",
            dir.display(),
            pid.trim()
        ));
        return 1;
    };
    if let Err(e) = fs::write(pid_path(&dir), format!("{}\n", std::process::id())) {
        log(format!("warning: cannot write pid file: {e}"));
    }
    install_signal_handlers();

    let mut groups = cfg.log_groups();
    let mut collector = Collector::new(collector_options(&cfg, &groups));
    let mut writer = storage::Writer::new(&dir, flush_interval(&cfg));
    let mut mtime = config_mtime(config_path);
    log(format!(
        "started (pid {}): every {} s into {}, metrics: {}",
        std::process::id(),
        cfg.logging.interval_secs,
        dir.display(),
        cfg.logging.metrics.join(",")
    ));
    retention(&cfg, &dir);
    let mut last_retention = Instant::now();

    // Prime the counters so the first stored record already has rates.
    collector.sample();
    let mut interval = Duration::from_secs(cfg.logging.interval_secs);
    let mut next = Instant::now() + interval;
    let mut write_failing = false;
    let mut exit_reason = "stopped by signal";

    loop {
        sleep_until(next);
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        let changed = config_mtime(config_path) != mtime;
        if RELOAD.swap(false, Ordering::SeqCst) || changed {
            mtime = config_mtime(config_path);
            match Config::load(config_path) {
                Ok(new) if !new.logging.enabled => {
                    exit_reason = "logging disabled in config";
                    break;
                }
                Ok(new) if new.data_dir() != dir => {
                    exit_reason = "data directory changed in config; restart the logger";
                    break;
                }
                Ok(new) => {
                    if new != cfg {
                        cfg = new;
                        groups = cfg.log_groups();
                        collector.opts = collector_options(&cfg, &groups);
                        interval = Duration::from_secs(cfg.logging.interval_secs);
                        next = Instant::now() + interval;
                        log(format!(
                            "configuration reloaded: every {} s, metrics: {}",
                            cfg.logging.interval_secs,
                            cfg.logging.metrics.join(",")
                        ));
                        continue;
                    }
                }
                Err(e) => log(format!(
                    "config reload failed, keeping previous settings: {e}"
                )),
            }
        }
        let now = Instant::now();
        if now < next {
            continue; // woken early by a signal
        }

        let snap = collector.sample();
        let mut rec = Record::from_snapshot(&snap);
        rec.retain_groups(&groups);
        match writer.append(&rec) {
            Ok(()) if write_failing => {
                log("writing works again");
                write_failing = false;
            }
            Ok(()) => {}
            Err(e) if !write_failing => {
                log(format!("error writing data (will keep retrying): {e}"));
                write_failing = true;
            }
            Err(_) => {}
        }

        if last_retention.elapsed() >= RETENTION_EVERY {
            retention(&cfg, &dir);
            last_retention = Instant::now();
        }
        next += interval;
        if next <= Instant::now() {
            // We fell behind (suspend, heavy load): do not try to catch up.
            next = Instant::now() + interval;
        }
    }

    let _ = writer.flush();
    let _ = fs::remove_file(pid_path(&dir));
    log(exit_reason);
    0
}

fn collector_options(cfg: &Config, groups: &[Group]) -> collect::Options {
    collect::Options {
        processes: false,
        process_io: false,
        filesystems: groups.contains(&Group::Filesystem),
        include_network_fs: cfg.collection.include_network_fs,
    }
}

/// Short intervals are buffered to reduce write syscalls.
fn flush_interval(cfg: &Config) -> Duration {
    if cfg.logging.interval_secs >= 5 {
        Duration::ZERO
    } else {
        Duration::from_secs(5)
    }
}

fn retention(cfg: &Config, dir: &Path) {
    let now = util::now_unix() as i64;
    match storage::enforce_retention(dir, cfg.logging.retention_days, cfg.max_size_bytes(), now) {
        Ok(0) => {}
        Ok(n) => log(format!("retention: removed {n} old data file(s)")),
        Err(e) => log(format!("retention failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Control from the TUI / CLI
// ---------------------------------------------------------------------------

/// Start `tirnix logger run` as a detached background process (new session,
/// so it survives the terminal or SSH connection closing). Its stdout and
/// stderr go to `<data_dir>/logger.log`.
pub fn spawn_detached(config_path: &Path, cfg: &Config) -> Result<Child, String> {
    let dir = cfg.data_dir();
    storage::ensure_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let lp = log_path(&dir);
    if fs::metadata(&lp).is_ok_and(|m| m.len() > MAX_LOG_FILE) {
        let _ = fs::rename(&lp, dir.join("logger.log.old"));
    }
    let logf = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&lp)
        .map_err(|e| format!("cannot open {}: {e}", lp.display()))?;
    let logf2 = logf.try_clone().map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot find own executable: {e}"))?;
    let mut cmd = Command::new(exe);
    cmd.arg("logger")
        .arg("run")
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(logf)
        .stderr(logf2)
        .current_dir("/");
    // SAFETY: setsid is async-signal-safe and allowed between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start logger: {e}"))?;

    // Wait until it holds the lock, or report why it exited.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if status(&dir).running {
            return Ok(child);
        }
        if let Ok(Some(code)) = child.try_wait() {
            let tail = fs::read_to_string(&lp)
                .ok()
                .and_then(|s| s.lines().last().map(str::to_string))
                .unwrap_or_default();
            return Err(format!("logger exited ({code}): {tail}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(child)
}

/// Ask the running logger for `dir` to stop and wait for it to exit.
pub fn stop(dir: &Path) -> Result<bool, String> {
    let st = status(dir);
    if !st.running {
        return Ok(false);
    }
    let pid = st.pid.filter(|p| *p > 1).ok_or_else(|| {
        format!(
            "logger is running but {} is missing",
            pid_path(dir).display()
        )
    })?;
    // SAFETY: plain syscall.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } != 0 {
        return Err(format!(
            "cannot signal pid {pid}: {} (is it running as another user, e.g. the systemd service?)",
            io::Error::last_os_error()
        ));
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if !status(dir).running {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("logger (pid {pid}) did not stop within 5 s"))
}

/// Human readable status, used by `tirnix logger status`.
pub fn describe(st: &Status, cfg: &Config) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Logger:     {}",
        match (st.running, st.pid) {
            (true, Some(p)) => format!("running (pid {p})"),
            (true, None) => "running".into(),
            (false, _) => "not running".into(),
        }
    );
    let _ = writeln!(
        out,
        "Enabled:    {} (config)",
        if cfg.logging.enabled { "yes" } else { "no" }
    );
    let _ = writeln!(out, "Directory:  {}", st.dir.display());
    let _ = writeln!(
        out,
        "Interval:   {} s, retention {} days, max {} MiB",
        cfg.logging.interval_secs, cfg.logging.retention_days, cfg.logging.max_size_mb
    );
    let _ = writeln!(out, "Metrics:    {}", cfg.logging.metrics.join(", "));
    let _ = writeln!(
        out,
        "Stored:     {} file(s), {}",
        st.usage.files,
        util::fmt_bytes(st.usage.bytes as f64)
    );
    if let (Some(a), Some(b)) = (st.usage.oldest_hour, st.usage.newest_hour) {
        let _ = writeln!(
            out,
            "Range:      {} .. {}",
            util::fmt_local_datetime(a),
            util::fmt_local_datetime(b + 3599)
        );
    }
    if let Some(t) = st.last_write {
        let ago = util::now_unix() as i64 - t;
        let _ = writeln!(
            out,
            "Last write: {} ago",
            util::fmt_duration(ago.max(0) as f64)
        );
    }
    out
}

use std::fmt::Write as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::TempDir;

    #[test]
    fn lock_is_exclusive_and_status_sees_it() {
        let d = TempDir::new("lock");
        assert!(!status(&d.0).running);
        let held = acquire_lock(&d.0).unwrap().expect("first lock");
        fs::write(pid_path(&d.0), "4242\n").unwrap();
        // Same process, second open file description: flock conflicts too.
        assert!(acquire_lock(&d.0).unwrap().is_none());
        let st = status(&d.0);
        assert!(st.running);
        assert_eq!(st.pid, Some(4242));
        drop(held);
        assert!(!status(&d.0).running);
    }

    #[test]
    fn disabled_logging_refuses_to_start() {
        let d = TempDir::new("disabled");
        let cfg_path = d.0.join("config.toml");
        let mut cfg = Config::default();
        cfg.logging.directory = d.0.join("data").display().to_string();
        cfg.save(&cfg_path).unwrap();
        assert_eq!(run(&cfg_path), EXIT_DISABLED);
        assert!(
            !d.0.join("data").exists(),
            "nothing may be written when disabled"
        );
    }
}
