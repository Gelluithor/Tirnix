//! Configuration file handling.
//!
//! A missing file means "all defaults"; Tirnix never creates the file on its
//! own. It is written only when the user changes a setting in the TUI, and
//! always from a commented template so it stays readable.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::metrics::Group;

pub const REFRESH_CHOICES_MS: &[u64] = &[500, 1000, 2000, 5000, 10_000];
pub const LOG_INTERVAL_CHOICES: &[u64] = &[1, 5, 10, 30, 60];
pub const RETENTION_CHOICES: &[u64] = &[1, 3, 7, 14, 30, 90, 365];
pub const MAX_SIZE_CHOICES_MB: &[u64] = &[10, 50, 100, 250, 500, 1000, 5000];

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Config {
    pub ui: UiConfig,
    pub collection: CollectionConfig,
    pub logging: LoggingConfig,
    pub active_checks: ActiveChecksConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Screen refresh / sampling interval of the TUI in milliseconds.
    pub refresh_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct CollectionConfig {
    /// Include NFS/CIFS/FUSE filesystems (statvfs may block on dead servers).
    pub include_network_fs: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    /// Empty means the default data directory.
    pub directory: String,
    pub retention_days: u64,
    pub max_size_mb: u64,
    pub metrics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveChecksConfig {
    /// `host:port` targets for the on-demand DNS + TCP connect check.
    pub targets: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig { refresh_ms: 2000 }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            enabled: false,
            interval_secs: 10,
            directory: String::new(),
            retention_days: 7,
            max_size_mb: 100,
            metrics: Group::ALL.iter().map(|g| g.key().to_string()).collect(),
        }
    }
}

impl Default for ActiveChecksConfig {
    fn default() -> Self {
        ActiveChecksConfig {
            targets: Vec::new(),
            timeout_ms: 2000,
        }
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(fallback)))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `$TIRNIX_CONFIG`, else `$XDG_CONFIG_HOME/tirnix/config.toml`,
/// else `~/.config/tirnix/config.toml`.
pub fn default_config_path() -> PathBuf {
    if let Some(p) = std::env::var_os("TIRNIX_CONFIG").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    xdg("XDG_CONFIG_HOME", ".config")
        .join("tirnix")
        .join("config.toml")
}

/// `$XDG_STATE_HOME/tirnix`, else `~/.local/state/tirnix`.
pub fn default_data_dir() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join("tirnix")
}

impl Config {
    /// Load from `path`. A missing file yields defaults.
    pub fn load(path: &Path) -> Result<Config, String> {
        match fs::read_to_string(path) {
            Ok(text) => Config::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut c: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        c.normalize();
        Ok(c)
    }

    fn validate(&self) -> Result<(), String> {
        for m in &self.logging.metrics {
            if Group::from_key(m).is_none() {
                let valid: Vec<&str> = Group::ALL.iter().map(|g| g.key()).collect();
                return Err(format!(
                    "unknown metric group \"{m}\" in logging.metrics (valid: {})",
                    valid.join(", ")
                ));
            }
        }
        Ok(())
    }

    /// Clamp values to sane ranges instead of failing on odd input.
    fn normalize(&mut self) {
        self.ui.refresh_ms = self.ui.refresh_ms.clamp(250, 60_000);
        self.logging.interval_secs = self.logging.interval_secs.clamp(1, 3600);
        self.logging.retention_days = self.logging.retention_days.clamp(1, 3650);
        self.logging.max_size_mb = self.logging.max_size_mb.max(1);
        self.active_checks.timeout_ms = self.active_checks.timeout_ms.clamp(100, 30_000);
    }

    pub fn data_dir(&self) -> PathBuf {
        let d = self.logging.directory.trim();
        if d.is_empty() {
            default_data_dir()
        } else if let Some(rest) = d.strip_prefix("~/") {
            home().map_or_else(|| PathBuf::from(d), |h| h.join(rest))
        } else {
            PathBuf::from(d)
        }
    }

    pub fn log_groups(&self) -> Vec<Group> {
        self.logging
            .metrics
            .iter()
            .filter_map(|m| Group::from_key(m))
            .collect()
    }

    pub fn max_size_bytes(&self) -> u64 {
        self.logging.max_size_mb.saturating_mul(1024 * 1024)
    }

    /// Render as a commented TOML document.
    pub fn to_toml(&self) -> String {
        let q = |s: &str| toml_string(s);
        let list = |v: &[String]| {
            let items: Vec<String> = v.iter().map(|s| q(s)).collect();
            format!("[{}]", items.join(", "))
        };
        let groups: Vec<&str> = Group::ALL.iter().map(|g| g.key()).collect();
        format!(
            "# Tirnix configuration.
# This file is written by the Settings screen; manual edits are fine too.

[ui]
# Sampling and screen refresh interval of the TUI, in milliseconds.
refresh_ms = {refresh}

[collection]
# Include network/FUSE filesystems (NFS, CIFS, sshfs, ...) in disk usage.
# Off by default: statvfs() on an unreachable server can block.
include_network_fs = {netfs}

[logging]
# Long-term logging runs as a separate process (`tirnix logger run`) and
# keeps running after the TUI exits. It is never enabled automatically.
enabled = {enabled}
# Seconds between stored samples.
interval_secs = {interval}
# Where data files are written. Empty = {default_dir}
directory = {dir}
# Files older than this are deleted.
retention_days = {retention}
# Upper bound for all data files together; oldest files are deleted first.
max_size_mb = {max_size}
# Metric groups to store. Available: {groups}
metrics = {metrics}

[active_checks]
# Targets for the on-demand connectivity check on the Diagnostics screen,
# as \"host:port\" (e.g. \"example.com:443\"). Nothing is contacted unless you
# press the key for it; passive monitoring never generates network traffic.
targets = {targets}
timeout_ms = {timeout}
",
            refresh = self.ui.refresh_ms,
            netfs = self.collection.include_network_fs,
            enabled = self.logging.enabled,
            interval = self.logging.interval_secs,
            default_dir = default_data_dir().display(),
            dir = q(&self.logging.directory),
            retention = self.logging.retention_days,
            max_size = self.logging.max_size_mb,
            groups = groups.join(", "),
            metrics = list(&self.logging.metrics),
            targets = list(&self.active_checks.targets),
            timeout = self.active_checks.timeout_ms,
        )
    }

    /// Write atomically (temp file + rename) so a crash never leaves a
    /// half-written config behind.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("toml.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(self.to_toml().as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }
}

fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Pick the next/previous value from a list of choices, starting from the
/// closest match to `current`.
pub fn cycle(choices: &[u64], current: u64, forward: bool) -> u64 {
    let idx = choices
        .iter()
        .enumerate()
        .min_by_key(|(_, v)| v.abs_diff(current))
        .map_or(0, |(i, _)| i);
    let n = choices.len();
    let next = if forward {
        (idx + 1).min(n - 1)
    } else {
        idx.saturating_sub(1)
    };
    choices[next]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_logging_off() {
        let c = Config::default();
        assert!(!c.logging.enabled);
        assert!(c.active_checks.targets.is_empty());
        assert_eq!(c.log_groups().len(), Group::ALL.len());
    }

    #[test]
    fn template_roundtrips() {
        let mut c = Config::default();
        c.logging.enabled = true;
        c.logging.directory = "/var/lib/tir \"nix\"".into();
        c.logging.metrics = vec!["cpu".into(), "tcp".into()];
        c.active_checks.targets = vec!["example.com:443".into()];
        let text = c.to_toml();
        let back = Config::parse(&text).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn partial_file_uses_defaults() {
        let c = Config::parse("[logging]\ninterval_secs = 60\n").unwrap();
        assert_eq!(c.logging.interval_secs, 60);
        assert_eq!(c.ui.refresh_ms, 2000);
        assert!(!c.logging.enabled);
    }

    #[test]
    fn rejects_unknown_groups_and_keys() {
        assert!(Config::parse("[logging]\nmetrics = [\"cpu\", \"gpu\"]\n").is_err());
        assert!(Config::parse("[logging]\nenable = true\n").is_err());
    }

    #[test]
    fn values_are_clamped() {
        let c = Config::parse("[ui]\nrefresh_ms = 1\n[logging]\ninterval_secs = 0\n").unwrap();
        assert_eq!(c.ui.refresh_ms, 250);
        assert_eq!(c.logging.interval_secs, 1);
    }

    #[test]
    fn missing_file_is_default() {
        let c = Config::load(Path::new("/nonexistent/tirnix/config.toml")).unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn cycling_choices() {
        assert_eq!(cycle(&[1, 5, 10], 5, true), 10);
        assert_eq!(cycle(&[1, 5, 10], 10, true), 10);
        assert_eq!(cycle(&[1, 5, 10], 1, false), 1);
        assert_eq!(cycle(&[1, 5, 10], 7, false), 1);
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join(format!("tirnix-cfg-test-{}", std::process::id()));
        let path = dir.join("config.toml");
        let mut c = Config::default();
        c.ui.refresh_ms = 5000;
        c.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), c);
        fs::remove_dir_all(&dir).unwrap();
    }
}
