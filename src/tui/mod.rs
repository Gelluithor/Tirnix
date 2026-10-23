//! Interactive terminal UI.

mod screens;
mod widgets;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Child;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::active::{self, CheckResult};
use crate::collect::{self, Collector, process};
use crate::config::{self, Config};
use crate::diagnose::{Engine, Finding};
use crate::logger;
use crate::metrics::{FIELDS, Group, Record, Snapshot};
use crate::storage;
use crate::util;
use crate::window::{self, Bucket, Stats, Window};

/// Sustain window for diagnostics in the TUI.
const SUSTAIN_SECS: i64 = 30;
/// In-memory samples kept for the "Session" history range.
const WINDOW_CAP: usize = 1800;
const MESSAGE_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Overview,
    CpuMem,
    Disks,
    Processes,
    Network,
    Diagnostics,
    History,
    Settings,
}

impl Screen {
    pub const ALL: [Screen; 8] = [
        Screen::Overview,
        Screen::CpuMem,
        Screen::Disks,
        Screen::Processes,
        Screen::Network,
        Screen::Diagnostics,
        Screen::History,
        Screen::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Overview => "Overview",
            Screen::CpuMem => "CPU & Memory",
            Screen::Disks => "Disks",
            Screen::Processes => "Processes",
            Screen::Network => "Network",
            Screen::Diagnostics => "Diagnostics",
            Screen::History => "History",
            Screen::Settings => "Settings",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Screen::Overview => "Ovw",
            Screen::CpuMem => "CPU",
            Screen::Disks => "Disk",
            Screen::Processes => "Proc",
            Screen::Network => "Net",
            Screen::Diagnostics => "Diag",
            Screen::History => "Hist",
            Screen::Settings => "Set",
        }
    }

    fn index(self) -> usize {
        Screen::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcSort {
    Cpu,
    Mem,
    Io,
    Pid,
    Name,
}

impl ProcSort {
    pub fn label(self) -> &'static str {
        match self {
            ProcSort::Cpu => "CPU",
            ProcSort::Mem => "memory",
            ProcSort::Io => "disk I/O",
            ProcSort::Pid => "PID",
            ProcSort::Name => "name",
        }
    }

    fn next(self) -> ProcSort {
        match self {
            ProcSort::Cpu => ProcSort::Mem,
            ProcSort::Mem => ProcSort::Io,
            ProcSort::Io => ProcSort::Pid,
            ProcSort::Pid => ProcSort::Name,
            ProcSort::Name => ProcSort::Cpu,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    ProcFilter,
    LogDir,
    Targets,
}

pub struct Input {
    pub kind: InputKind,
    pub buf: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingItem {
    Refresh,
    NetFs,
    LogEnabled,
    LogInterval,
    LogDir,
    Retention,
    MaxSize,
    Metric(Group),
    Targets,
}

pub enum SettingRow {
    Header(&'static str),
    Item(SettingItem),
}

pub fn setting_rows() -> Vec<SettingRow> {
    let mut v = vec![
        SettingRow::Header("Monitoring"),
        SettingRow::Item(SettingItem::Refresh),
        SettingRow::Item(SettingItem::NetFs),
        SettingRow::Header("Long-term logging"),
        SettingRow::Item(SettingItem::LogEnabled),
        SettingRow::Item(SettingItem::LogInterval),
        SettingRow::Item(SettingItem::LogDir),
        SettingRow::Item(SettingItem::Retention),
        SettingRow::Item(SettingItem::MaxSize),
        SettingRow::Header("Metrics to store"),
    ];
    v.extend(
        Group::ALL
            .iter()
            .map(|g| SettingRow::Item(SettingItem::Metric(*g))),
    );
    v.push(SettingRow::Header("Active checks (on demand only)"));
    v.push(SettingRow::Item(SettingItem::Targets));
    v
}

fn setting_items() -> Vec<SettingItem> {
    setting_rows()
        .into_iter()
        .filter_map(|r| match r {
            SettingRow::Item(i) => Some(i),
            SettingRow::Header(_) => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

pub const RANGES: &[(&str, i64)] = &[
    ("Session", 0),
    ("1 hour", 3600),
    ("6 hours", 6 * 3600),
    ("24 hours", 86_400),
    ("7 days", 7 * 86_400),
    ("30 days", 30 * 86_400),
];

/// Metrics offered on the History screen.
pub fn history_metrics() -> Vec<&'static crate::metrics::FieldInfo> {
    FIELDS
        .iter()
        .filter(|f| !matches!(f.key, "mem_total" | "swap_total" | "load5" | "load15"))
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct Series {
    pub buckets: Vec<Option<Bucket>>,
    pub stats: Option<Stats>,
}

#[derive(Debug, Clone, Default)]
pub struct HistResult {
    pub from: i64,
    pub to: i64,
    pub current: Series,
    pub previous: Option<Series>,
    pub stored: bool,
}

#[derive(Default)]
pub struct HistoryState {
    pub range: usize,
    pub metric: usize,
    pub compare: bool,
    pub result: Option<HistResult>,
    pub error: Option<String>,
    pub loading: bool,
    /// Requested chart resolution (buckets), set by the renderer.
    pub width: usize,
    rx: Option<Receiver<Result<HistResult, String>>>,
    loaded: Option<(usize, usize, bool, usize, Instant)>,
}

fn series(points: Vec<(i64, f64)>, from: i64, to: i64, n: usize) -> Series {
    let values: Vec<f64> = points.iter().map(|p| p.1).collect();
    Series {
        stats: window::stats(&values),
        buckets: window::downsample(points, from, to, n),
    }
}

fn load_stored(
    dir: PathBuf,
    key: &'static str,
    span: i64,
    compare: bool,
    n: usize,
) -> Result<HistResult, String> {
    let now = util::now_unix() as i64;
    let (from, to) = (now - span, now + 1);
    let collect = |a: i64, b: i64| -> Result<Vec<(i64, f64)>, String> {
        let mut pts = Vec::new();
        storage::for_each_in_range(&dir, a, b, |r| {
            if let Some(v) = r.get(key) {
                pts.push((r.t, v));
            }
        })
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        pts.sort_by_key(|p| p.0);
        Ok(pts)
    };
    let current = series(collect(from, to)?, from, to, n);
    let previous = if compare {
        Some(series(collect(from - span, from)?, from - span, from, n))
    } else {
        None
    };
    Ok(HistResult {
        from,
        to,
        current,
        previous,
        stored: true,
    })
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub cfg: Config,
    pub cfg_path: PathBuf,
    collector: Collector,
    pub snap: Snapshot,
    pub window: Window,
    engine: Engine,
    pub findings: Vec<Finding>,
    pub screen: Screen,
    pub paused: bool,
    next_sample: Instant,
    pub show_help: bool,
    message: Option<(String, Instant, bool)>,
    pub input: Option<Input>,

    pub proc_sort: ProcSort,
    pub proc_filter: String,
    /// Indices into `snap.procs.list` in display order.
    pub proc_rows: Vec<usize>,
    pub proc_sel: usize,
    pub proc_offset: usize,
    selected_pid: Option<u32>,
    pub users: HashMap<u32, String>,
    cmdlines: HashMap<u32, Option<String>>,

    pub disk_scroll: usize,
    pub net_scroll: usize,
    pub diag_sel: usize,
    pub diag_scroll: u16,

    pub settings_sel: usize,
    pub logger: logger::Status,
    logger_checked: Option<Instant>,
    logger_child: Option<Child>,

    pub hist: HistoryState,

    active_rx: Option<Receiver<Vec<CheckResult>>>,
    pub active_results: Option<(i64, Vec<CheckResult>)>,
}

impl App {
    pub fn new(cfg: Config, cfg_path: PathBuf) -> App {
        let collector = Collector::new(collect::Options {
            processes: true,
            process_io: false,
            filesystems: true,
            include_network_fs: cfg.collection.include_network_fs,
        });
        let logger = logger::status(&cfg.data_dir());
        App {
            cfg,
            cfg_path,
            collector,
            snap: Snapshot::default(),
            window: Window::new(WINDOW_CAP),
            engine: Engine::new(SUSTAIN_SECS),
            findings: Vec::new(),
            screen: Screen::Overview,
            paused: false,
            next_sample: Instant::now(),
            show_help: false,
            message: None,
            input: None,
            proc_sort: ProcSort::Cpu,
            proc_filter: String::new(),
            proc_rows: Vec::new(),
            proc_sel: 0,
            proc_offset: 0,
            selected_pid: None,
            users: process::load_users(),
            cmdlines: HashMap::new(),
            disk_scroll: 0,
            net_scroll: 0,
            diag_sel: 0,
            diag_scroll: 0,
            settings_sel: 0,
            logger,
            logger_checked: Some(Instant::now()),
            logger_child: None,
            hist: HistoryState::default(),
            active_rx: None,
            active_results: None,
        }
    }

    pub fn refresh(&self) -> Duration {
        Duration::from_millis(self.cfg.ui.refresh_ms)
    }

    pub fn message(&self) -> Option<(&str, bool)> {
        self.message
            .as_ref()
            .filter(|(_, t, _)| t.elapsed() < MESSAGE_TTL)
            .map(|(m, _, err)| (m.as_str(), *err))
    }

    fn info(&mut self, m: impl Into<String>) {
        self.message = Some((m.into(), Instant::now(), false));
    }

    fn error(&mut self, m: impl Into<String>) {
        self.message = Some((m.into(), Instant::now(), true));
    }

    pub fn sample(&mut self) {
        // Per-process I/O is only read while the Processes screen is open.
        self.collector.opts.process_io = self.screen == Screen::Processes;
        self.snap = self.collector.sample();
        self.window.push(Record::from_snapshot(&self.snap));
        self.findings = self.engine.evaluate(&self.snap, &self.window);
        self.diag_sel = self.diag_sel.min(self.findings.len().saturating_sub(1));
        self.update_proc_rows();
        // Forget command lines of processes that are gone.
        if let Some(p) = &self.snap.procs
            && self.cmdlines.len() > 4 * p.list.len().max(64)
        {
            self.cmdlines.clear();
        }
    }

    pub fn user_name(&self, uid: u32) -> String {
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }

    /// Command line for a visible row (cached; read lazily).
    pub fn cmdline(&mut self, pid: u32) -> Option<String> {
        self.cmdlines
            .entry(pid)
            .or_insert_with(|| process::read_cmdline(pid))
            .clone()
    }

    pub fn update_proc_rows(&mut self) {
        let Some(p) = &self.snap.procs else {
            self.proc_rows.clear();
            return;
        };
        let filter = self.proc_filter.to_lowercase();
        let mut rows: Vec<usize> = (0..p.list.len())
            .filter(|&i| {
                if filter.is_empty() {
                    return true;
                }
                let x = &p.list[i];
                x.comm.to_lowercase().contains(&filter)
                    || x.pid.to_string() == filter
                    || self
                        .users
                        .get(&x.uid)
                        .is_some_and(|u| u.to_lowercase() == filter)
            })
            .collect();
        let l = &p.list;
        let io = |i: usize| l[i].read_bps.unwrap_or(0.0) + l[i].write_bps.unwrap_or(0.0);
        match self.proc_sort {
            ProcSort::Cpu => rows.sort_by(|&a, &b| {
                l[b].cpu_pct
                    .unwrap_or(0.0)
                    .total_cmp(&l[a].cpu_pct.unwrap_or(0.0))
                    .then(l[b].rss.cmp(&l[a].rss))
            }),
            ProcSort::Mem => rows.sort_by(|&a, &b| l[b].rss.cmp(&l[a].rss)),
            ProcSort::Io => {
                rows.sort_by(|&a, &b| io(b).total_cmp(&io(a)).then(l[a].pid.cmp(&l[b].pid)))
            }
            ProcSort::Pid => rows.sort_by_key(|&i| l[i].pid),
            ProcSort::Name => {
                rows.sort_by(|&a, &b| l[a].comm.to_lowercase().cmp(&l[b].comm.to_lowercase()))
            }
        }
        // Keep the cursor on the same process across refreshes.
        if let Some(pid) = self.selected_pid
            && let Some(pos) = rows.iter().position(|&i| l[i].pid == pid)
        {
            self.proc_sel = pos;
        }
        self.proc_sel = self.proc_sel.min(rows.len().saturating_sub(1));
        self.proc_rows = rows;
    }

    fn set_proc_sel(&mut self, sel: usize) {
        self.proc_sel = sel.min(self.proc_rows.len().saturating_sub(1));
        self.selected_pid = self
            .proc_rows
            .get(self.proc_sel)
            .and_then(|&i| self.snap.procs.as_ref().map(|p| p.list[i].pid));
    }

    /// Periodic housekeeping between samples.
    fn tick(&mut self) {
        let every = if self.screen == Screen::Settings {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(5)
        };
        if self.logger_checked.is_none_or(|t| t.elapsed() >= every) {
            self.logger = logger::status(&self.cfg.data_dir());
            self.logger_checked = Some(Instant::now());
        }
        if let Some(c) = self.logger_child.as_mut() {
            // Reap the child if it exited, so it does not linger as a zombie.
            if let Ok(Some(_)) = c.try_wait() {
                self.logger_child = None;
            }
        }
        if let Some(rx) = &self.active_rx {
            match rx.try_recv() {
                Ok(r) => {
                    self.active_results = Some((util::now_unix() as i64, r));
                    self.active_rx = None;
                    self.info("Active checks finished.");
                }
                Err(TryRecvError::Disconnected) => self.active_rx = None,
                Err(TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.hist.rx {
            match rx.try_recv() {
                Ok(r) => {
                    self.hist.loading = false;
                    self.hist.rx = None;
                    match r {
                        Ok(res) => {
                            self.hist.result = Some(res);
                            self.hist.error = None;
                        }
                        Err(e) => self.hist.error = Some(e),
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    self.hist.loading = false;
                    self.hist.rx = None;
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if self.screen == Screen::History {
            self.maybe_load_history();
        }
    }

    pub fn active_running(&self) -> bool {
        self.active_rx.is_some()
    }

    fn busy(&self) -> bool {
        self.active_rx.is_some() || self.hist.rx.is_some() || self.message().is_some()
    }

    fn maybe_load_history(&mut self) {
        let metrics = history_metrics();
        self.hist.metric = self.hist.metric.min(metrics.len() - 1);
        let key = metrics[self.hist.metric].key;
        let (_, span) = RANGES[self.hist.range];
        let n = self.hist.width.max(10);
        if span == 0 {
            // Session: computed from the in-memory window on every call.
            let to = self.snap.time as i64 + 1;
            let from = self.window.first().map_or(to - 60, |r| r.t).min(to - 60);
            let pts: Vec<(i64, f64)> = self
                .window
                .iter()
                .filter_map(|r| Some((r.t, r.get(key)?)))
                .collect();
            self.hist.result = Some(HistResult {
                from,
                to,
                current: series(pts, from, to, n),
                previous: None,
                stored: false,
            });
            self.hist.error = None;
            self.hist.loaded = None;
            return;
        }
        if self.hist.rx.is_some() {
            return;
        }
        let refresh = if span <= 86_400 {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(300)
        };
        let fresh = self.hist.loaded.is_some_and(|(r, m, c, w, t)| {
            r == self.hist.range
                && m == self.hist.metric
                && c == self.hist.compare
                && w == n
                && t.elapsed() < refresh
        });
        if fresh {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let dir = self.cfg.data_dir();
        let compare = self.hist.compare;
        std::thread::spawn(move || {
            let _ = tx.send(load_stored(dir, key, span, compare, n));
        });
        self.hist.rx = Some(rx);
        self.hist.loading = true;
        self.hist.loaded = Some((
            self.hist.range,
            self.hist.metric,
            compare,
            n,
            Instant::now(),
        ));
    }

    // -----------------------------------------------------------------------
    // Settings actions
    // -----------------------------------------------------------------------

    fn save_config(&mut self) -> bool {
        match self.cfg.save(&self.cfg_path) {
            Ok(()) => {
                self.info(format!("Saved {}", self.cfg_path.display()));
                true
            }
            Err(e) => {
                self.error(format!("Cannot save {}: {e}", self.cfg_path.display()));
                false
            }
        }
    }

    fn refresh_logger_status(&mut self) {
        self.logger = logger::status(&self.cfg.data_dir());
        self.logger_checked = Some(Instant::now());
    }

    fn start_logger(&mut self) {
        match logger::spawn_detached(&self.cfg_path, &self.cfg) {
            Ok(child) => {
                self.logger_child = Some(child);
                self.info(format!(
                    "Logging started; it keeps running after you quit. Data: {}",
                    self.cfg.data_dir().display()
                ));
            }
            Err(e) => {
                self.cfg.logging.enabled = false;
                let _ = self.cfg.save(&self.cfg_path);
                self.error(e);
            }
        }
        self.refresh_logger_status();
    }

    fn toggle_logging(&mut self) {
        if self.cfg.logging.enabled || self.logger.running {
            self.cfg.logging.enabled = false;
            self.save_config();
            match logger::stop(&self.cfg.data_dir()) {
                Ok(true) => self.info("Logging stopped."),
                Ok(false) => self.info("Logging disabled."),
                Err(e) => self.error(e),
            }
            self.refresh_logger_status();
        } else {
            self.cfg.logging.enabled = true;
            if self.save_config() {
                self.start_logger();
            } else {
                self.cfg.logging.enabled = false;
            }
        }
    }

    fn adjust_setting(&mut self, item: SettingItem, forward: bool) {
        let l = &mut self.cfg.logging;
        match item {
            SettingItem::Refresh => {
                self.cfg.ui.refresh_ms =
                    config::cycle(config::REFRESH_CHOICES_MS, self.cfg.ui.refresh_ms, forward);
                self.next_sample = Instant::now() + self.refresh();
            }
            SettingItem::NetFs => {
                self.cfg.collection.include_network_fs = !self.cfg.collection.include_network_fs;
                self.collector.opts.include_network_fs = self.cfg.collection.include_network_fs;
                self.collector.invalidate_fs();
            }
            SettingItem::LogEnabled => return self.toggle_logging(),
            SettingItem::LogInterval => {
                l.interval_secs =
                    config::cycle(config::LOG_INTERVAL_CHOICES, l.interval_secs, forward)
            }
            SettingItem::Retention => {
                l.retention_days =
                    config::cycle(config::RETENTION_CHOICES, l.retention_days, forward)
            }
            SettingItem::MaxSize => {
                l.max_size_mb = config::cycle(config::MAX_SIZE_CHOICES_MB, l.max_size_mb, forward)
            }
            SettingItem::Metric(g) => {
                let k = g.key().to_string();
                if let Some(i) = l.metrics.iter().position(|m| *m == k) {
                    if l.metrics.len() == 1 {
                        self.error("At least one metric group must stay selected.");
                        return;
                    }
                    l.metrics.remove(i);
                } else {
                    // Keep the canonical order.
                    l.metrics.push(k);
                    l.metrics.sort_by_key(|m| {
                        Group::ALL
                            .iter()
                            .position(|g| g.key() == m)
                            .unwrap_or(usize::MAX)
                    });
                }
            }
            SettingItem::LogDir | SettingItem::Targets => return self.begin_edit(item),
        }
        self.save_config();
    }

    fn begin_edit(&mut self, item: SettingItem) {
        let (kind, buf) = match item {
            SettingItem::LogDir => (InputKind::LogDir, self.cfg.logging.directory.clone()),
            SettingItem::Targets => (
                InputKind::Targets,
                self.cfg.active_checks.targets.join(", "),
            ),
            _ => return,
        };
        self.input = Some(Input { kind, buf });
    }

    fn commit_input(&mut self, input: Input) {
        match input.kind {
            InputKind::ProcFilter => {
                self.proc_filter = input.buf.trim().to_string();
                self.update_proc_rows();
            }
            InputKind::LogDir => {
                let new = input.buf.trim().to_string();
                if new == self.cfg.logging.directory {
                    return;
                }
                let was_running = self.logger.running;
                if was_running && let Err(e) = logger::stop(&self.cfg.data_dir()) {
                    return self.error(e);
                }
                self.cfg.logging.directory = new;
                if self.save_config() && was_running && self.cfg.logging.enabled {
                    self.start_logger();
                }
                self.refresh_logger_status();
            }
            InputKind::Targets => {
                let targets: Vec<String> = input
                    .buf
                    .split([',', ' '])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();
                if let Some(e) = targets
                    .iter()
                    .find_map(|t| active::validate_target(t).err())
                {
                    return self.error(e);
                }
                self.cfg.active_checks.targets = targets;
                self.save_config();
            }
        }
    }

    fn run_active_checks(&mut self) {
        if self.active_rx.is_some() {
            return;
        }
        if self.cfg.active_checks.targets.is_empty() {
            self.error(
                "No targets configured. Add host:port targets in Settings (8) → Active checks.",
            );
            return;
        }
        self.active_rx = Some(active::spawn(
            self.cfg.active_checks.targets.clone(),
            Duration::from_millis(self.cfg.active_checks.timeout_ms),
        ));
        self.info("Running active checks (DNS + TCP connect)…");
    }

    // -----------------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------------

    fn switch(&mut self, s: Screen) {
        if s != self.screen {
            self.screen = s;
            // Processes screen needs I/O counters: take a fresh sample soon.
            if s == Screen::Processes {
                self.next_sample = Instant::now() + Duration::from_millis(300);
            }
            if s == Screen::Settings {
                self.refresh_logger_status();
            }
        }
    }

    /// Returns true when the app should quit.
    pub fn on_key(&mut self, k: KeyEvent) -> bool {
        if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c')) {
            return true;
        }
        if let Some(mut input) = self.input.take() {
            match k.code {
                KeyCode::Enter => self.commit_input(input),
                KeyCode::Esc => {
                    if input.kind == InputKind::ProcFilter {
                        self.proc_filter.clear();
                        self.update_proc_rows();
                    }
                }
                KeyCode::Backspace => {
                    input.buf.pop();
                    self.live_filter(&input);
                    self.input = Some(input);
                }
                KeyCode::Char(c) => {
                    input.buf.push(c);
                    self.live_filter(&input);
                    self.input = Some(input);
                }
                _ => self.input = Some(input),
            }
            return false;
        }
        if self.show_help {
            self.show_help = false;
            return matches!(k.code, KeyCode::Char('q'));
        }

        match k.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('?') | KeyCode::F(1) => self.show_help = true,
            KeyCode::Tab => self.switch(Screen::ALL[(self.screen.index() + 1) % 8]),
            KeyCode::BackTab => self.switch(Screen::ALL[(self.screen.index() + 7) % 8]),
            KeyCode::Char(c @ '1'..='8') => self.switch(Screen::ALL[c as usize - '1' as usize]),
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                self.info(if self.paused { "Paused." } else { "Resumed." });
            }
            KeyCode::Char('+') | KeyCode::Char('=') => self.change_refresh(false),
            KeyCode::Char('-') => self.change_refresh(true),
            KeyCode::Left | KeyCode::Right
                if !matches!(self.screen, Screen::History | Screen::Settings) =>
            {
                let n = if k.code == KeyCode::Right { 1 } else { 7 };
                self.switch(Screen::ALL[(self.screen.index() + n) % 8]);
            }
            _ => self.screen_key(k),
        }
        false
    }

    fn live_filter(&mut self, input: &Input) {
        if input.kind == InputKind::ProcFilter {
            self.proc_filter = input.buf.trim().to_string();
            self.update_proc_rows();
        }
    }

    /// `slower = true` lengthens the interval.
    fn change_refresh(&mut self, slower: bool) {
        self.cfg.ui.refresh_ms =
            config::cycle(config::REFRESH_CHOICES_MS, self.cfg.ui.refresh_ms, slower);
        self.next_sample = Instant::now() + self.refresh();
        self.info(format!(
            "Refresh interval {} s for this session (set it permanently in Settings).",
            self.cfg.ui.refresh_ms as f64 / 1000.0
        ));
    }

    fn screen_key(&mut self, k: KeyEvent) {
        let page = 10;
        match self.screen {
            Screen::Processes => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.set_proc_sel(self.proc_sel.saturating_sub(1))
                }
                KeyCode::Down | KeyCode::Char('j') => self.set_proc_sel(self.proc_sel + 1),
                KeyCode::PageUp => self.set_proc_sel(self.proc_sel.saturating_sub(page)),
                KeyCode::PageDown => self.set_proc_sel(self.proc_sel + page),
                KeyCode::Home | KeyCode::Char('g') => self.set_proc_sel(0),
                KeyCode::End | KeyCode::Char('G') => self.set_proc_sel(usize::MAX),
                KeyCode::Char('s') => {
                    self.proc_sort = self.proc_sort.next();
                    self.update_proc_rows();
                    self.set_proc_sel(0);
                }
                KeyCode::Char('/') => {
                    self.input = Some(Input {
                        kind: InputKind::ProcFilter,
                        buf: self.proc_filter.clone(),
                    })
                }
                KeyCode::Esc => {
                    self.proc_filter.clear();
                    self.update_proc_rows();
                }
                _ => {}
            },
            Screen::Disks => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.disk_scroll = self.disk_scroll.saturating_sub(1)
                }
                KeyCode::Down | KeyCode::Char('j') => self.disk_scroll += 1,
                KeyCode::PageUp => self.disk_scroll = self.disk_scroll.saturating_sub(page),
                KeyCode::PageDown => self.disk_scroll += page,
                _ => {}
            },
            Screen::Network => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.net_scroll = self.net_scroll.saturating_sub(1)
                }
                KeyCode::Down | KeyCode::Char('j') => self.net_scroll += 1,
                KeyCode::PageUp => self.net_scroll = self.net_scroll.saturating_sub(page),
                KeyCode::PageDown => self.net_scroll += page,
                _ => {}
            },
            Screen::Diagnostics => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.diag_sel = self.diag_sel.saturating_sub(1);
                    self.diag_scroll = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.diag_sel = (self.diag_sel + 1).min(self.findings.len().saturating_sub(1));
                    self.diag_scroll = 0;
                }
                KeyCode::PageDown => self.diag_scroll = self.diag_scroll.saturating_add(5),
                KeyCode::PageUp => self.diag_scroll = self.diag_scroll.saturating_sub(5),
                KeyCode::Char('a') => self.run_active_checks(),
                _ => {}
            },
            Screen::History => {
                let n = history_metrics().len();
                match k.code {
                    KeyCode::Left | KeyCode::Char('h') => {
                        self.hist.range = self.hist.range.saturating_sub(1)
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        self.hist.range = (self.hist.range + 1).min(RANGES.len() - 1)
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.hist.metric = (self.hist.metric + n - 1) % n
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.hist.metric = (self.hist.metric + 1) % n
                    }
                    KeyCode::Char('c') => self.hist.compare = !self.hist.compare,
                    KeyCode::Char('r') => self.hist.loaded = None,
                    _ => return,
                }
                self.maybe_load_history();
            }
            Screen::Settings => {
                let items = setting_items();
                let item = items[self.settings_sel.min(items.len() - 1)];
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.settings_sel = self.settings_sel.saturating_sub(1)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.settings_sel = (self.settings_sel + 1).min(items.len() - 1)
                    }
                    // Starting a background process needs a deliberate Enter/Space,
                    // never an arrow key pressed while browsing values.
                    KeyCode::Right | KeyCode::Char('l') if item != SettingItem::LogEnabled => {
                        self.adjust_setting(item, true)
                    }
                    KeyCode::Left | KeyCode::Char('h') if item != SettingItem::LogEnabled => {
                        self.adjust_setting(item, false)
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => self.adjust_setting(item, true),
                    KeyCode::Char('w') => {
                        self.save_config();
                    }
                    _ => {}
                }
            }
            Screen::Overview | Screen::CpuMem => {}
        }
    }

    pub fn selected_setting(&self) -> SettingItem {
        let items = setting_items();
        items[self.settings_sel.min(items.len() - 1)]
    }
}

pub fn run(cfg: Config, cfg_path: PathBuf) -> std::io::Result<()> {
    let mut app = App::new(cfg, cfg_path);
    app.sample();
    // Rates need two samples; take the second one quickly.
    app.next_sample = Instant::now() + Duration::from_millis(500);

    let mut terminal = ratatui::try_init()?;
    let result = (|| -> std::io::Result<()> {
        loop {
            terminal.draw(|f| screens::draw(f, &mut app))?;
            let now = Instant::now();
            let mut timeout = app.next_sample.saturating_duration_since(now);
            if app.busy() {
                // Poll background results and expire messages promptly.
                timeout = timeout.min(Duration::from_millis(250));
            }
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release && app.on_key(k) => {
                        return Ok(());
                    }
                    _ => {} // resize etc.: just redraw
                }
            }
            if Instant::now() >= app.next_sample {
                if !app.paused {
                    app.sample();
                }
                app.next_sample = Instant::now() + app.refresh();
            }
            app.tick();
        }
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn app() -> App {
        let mut cfg = Config::default();
        // Never touch the real user's data directory in tests.
        cfg.logging.directory = std::env::temp_dir()
            .join(format!("tirnix-tui-test-{}", std::process::id()))
            .display()
            .to_string();
        let mut a = App::new(cfg, std::env::temp_dir().join("tirnix-tui-test.toml"));
        a.sample();
        std::thread::sleep(Duration::from_millis(30));
        a.sample();
        a
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn every_screen_renders_at_many_sizes() {
        let mut a = app();
        for (w, h) in [
            (80, 24),
            (120, 40),
            (200, 60),
            (60, 20),
            (40, 12),
            (20, 6),
            (1, 1),
        ] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            for s in Screen::ALL {
                a.screen = s;
                for help in [false, true] {
                    a.show_help = help;
                    t.draw(|f| screens::draw(f, &mut a)).unwrap();
                }
            }
        }
    }

    #[test]
    fn navigation_keys() {
        let mut a = app();
        a.on_key(key(KeyCode::Char('4')));
        assert_eq!(a.screen, Screen::Processes);
        a.on_key(key(KeyCode::Tab));
        assert_eq!(a.screen, Screen::Network);
        a.on_key(key(KeyCode::BackTab));
        a.on_key(key(KeyCode::BackTab));
        assert_eq!(a.screen, Screen::Disks);
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.screen, Screen::Processes);
        a.on_key(key(KeyCode::Char('?')));
        assert!(a.show_help);
        assert!(!a.on_key(key(KeyCode::Esc)));
        assert!(!a.show_help);
        assert!(a.on_key(key(KeyCode::Char('q'))));
    }

    #[test]
    fn process_filter_input() {
        let mut a = app();
        a.on_key(key(KeyCode::Char('4')));
        a.on_key(key(KeyCode::Char('/')));
        assert!(a.input.is_some());
        for c in "zzzz-no-such-process".chars() {
            a.on_key(key(KeyCode::Char(c)));
        }
        // Typing 'q' inside the filter must not quit.
        assert!(!a.on_key(key(KeyCode::Char('q'))));
        assert!(a.proc_rows.is_empty() || a.snap.procs.is_none());
        a.on_key(key(KeyCode::Esc));
        assert!(a.input.is_none());
        assert!(a.proc_filter.is_empty());
    }

    #[test]
    fn arrow_keys_never_toggle_background_logging() {
        let mut a = app();
        a.screen = Screen::Settings;
        a.settings_sel = setting_items()
            .iter()
            .position(|i| *i == SettingItem::LogEnabled)
            .unwrap();
        for k in [
            KeyCode::Right,
            KeyCode::Left,
            KeyCode::Char('l'),
            KeyCode::Char('h'),
        ] {
            a.on_key(key(k));
        }
        assert!(!a.cfg.logging.enabled);
        assert!(a.logger_child.is_none());
    }

    #[test]
    fn history_session_range_uses_window() {
        let mut a = app();
        a.screen = Screen::History;
        a.hist.width = 40;
        a.maybe_load_history();
        let r = a.hist.result.as_ref().expect("session result");
        assert!(!r.stored);
        assert_eq!(r.current.buckets.len(), 40);
    }
}
