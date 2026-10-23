//! Tirnix — Linux system monitoring and diagnostics in the terminal.

mod active;
mod collect;
mod config;
mod diagnose;
mod export;
mod logger;
mod metrics;
mod report;
mod storage;
mod tui;
mod util;
mod window;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() -> String {
    format!(
        "tirnix {VERSION} — Linux system monitoring and diagnostics

Usage:
  tirnix [--config PATH]                 Start the interactive TUI
  tirnix report [--seconds N]            Sample for N seconds (default 5) and print a report
  tirnix logger status                   Show the state of long-term logging
  tirnix logger start                    Enable logging and start it in the background
  tirnix logger stop                     Stop background logging and disable it
  tirnix logger run                      Run the logger in the foreground (for systemd)
  tirnix export [OPTIONS]                Export stored history
      --since DURATION                   e.g. 30m, 6h, 7d (default 24h)
      --from TIME --to TIME              Unix seconds or UTC YYYY-MM-DD[THH:MM[:SS]]
      --format jsonl|csv                 Output format (default jsonl)
      --output FILE                      Write to FILE instead of stdout
  tirnix config path                     Print the config file location
  tirnix config show                     Print the effective configuration

Global options:
  --config PATH   Use this config file (default: {})
  -h, --help      Show this help
  -V, --version   Show the version
",
        config::default_config_path().display()
    )
}

struct Args {
    config: Option<PathBuf>,
    rest: Vec<String>,
}

fn parse_global(argv: Vec<String>) -> Result<Args, String> {
    let mut config = None;
    let mut rest = Vec::new();
    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        if a == "--config" {
            config = Some(PathBuf::from(it.next().ok_or("--config needs a path")?));
        } else if let Some(v) = a.strip_prefix("--config=") {
            config = Some(PathBuf::from(v));
        } else {
            rest.push(a);
        }
    }
    Ok(Args { config, rest })
}

/// Pull `--name VALUE` out of `args`.
fn take_opt(args: &mut Vec<String>, name: &str) -> Result<Option<String>, String> {
    let Some(i) = args.iter().position(|a| a == name) else {
        let prefix = format!("{name}=");
        if let Some(i) = args.iter().position(|a| a.starts_with(&prefix)) {
            let v = args.remove(i)[prefix.len()..].to_string();
            return Ok(Some(v));
        }
        return Ok(None);
    };
    args.remove(i);
    if i >= args.len() {
        return Err(format!("{name} needs a value"));
    }
    Ok(Some(args.remove(i)))
}

fn no_more(args: &[String]) -> Result<(), String> {
    match args.first() {
        Some(a) => Err(format!(
            "unexpected argument: {a}\nRun `tirnix --help` for usage."
        )),
        None => Ok(()),
    }
}

fn load_config(path: &Path) -> Result<Config, String> {
    Config::load(path).map_err(|e| format!("invalid configuration: {e}"))
}

fn real_main() -> Result<ExitCode, String> {
    let args = parse_global(std::env::args().skip(1).collect())?;
    let config_path = args.config.unwrap_or_else(config::default_config_path);
    let mut rest = args.rest;

    if rest
        .iter()
        .any(|a| a == "-h" || a == "--help" || a == "help")
    {
        print!("{}", usage());
        return Ok(ExitCode::SUCCESS);
    }
    if rest.iter().any(|a| a == "-V" || a == "--version") {
        println!("tirnix {VERSION}");
        return Ok(ExitCode::SUCCESS);
    }

    if rest.is_empty() {
        let cfg = load_config(&config_path)?;
        tui::run(cfg, config_path).map_err(|e| format!("terminal error: {e}"))?;
        return Ok(ExitCode::SUCCESS);
    }

    let cmd = rest.remove(0);
    match cmd.as_str() {
        "report" => {
            let secs = take_opt(&mut rest, "--seconds")?
                .map(|s| {
                    s.parse::<u64>()
                        .map_err(|_| format!("invalid --seconds: {s}"))
                })
                .transpose()?
                .unwrap_or(5);
            no_more(&rest)?;
            let cfg = load_config(&config_path)?;
            if !collect::procfs_available() {
                eprintln!("warning: /proc is not available; Tirnix supports Linux only.");
            }
            print!(
                "{}",
                report::run(secs.min(3600), cfg.collection.include_network_fs)
            );
        }
        "logger" => {
            let sub = if rest.is_empty() {
                "status".to_string()
            } else {
                rest.remove(0)
            };
            no_more(&rest)?;
            return logger_cmd(&sub, &config_path);
        }
        "export" => {
            let since = take_opt(&mut rest, "--since")?;
            let from = take_opt(&mut rest, "--from")?;
            let to = take_opt(&mut rest, "--to")?;
            let format = take_opt(&mut rest, "--format")?.unwrap_or_else(|| "jsonl".into());
            let output = take_opt(&mut rest, "--output")?.or(take_opt(&mut rest, "-o")?);
            no_more(&rest)?;
            let format = export::Format::parse(&format)
                .ok_or_else(|| format!("unknown format \"{format}\" (use jsonl or csv)"))?;
            let now = util::now_unix() as i64;
            let to = match to {
                Some(t) => util::parse_timestamp(&t).ok_or(format!("invalid --to: {t}"))?,
                None => now + 1,
            };
            let from = match (from, since) {
                (Some(_), Some(_)) => return Err("use either --from or --since, not both".into()),
                (Some(f), None) => {
                    util::parse_timestamp(&f).ok_or(format!("invalid --from: {f}"))?
                }
                (None, Some(s)) => {
                    now - util::parse_duration(&s).ok_or(format!("invalid --since: {s}"))?
                }
                (None, None) => now - 86_400,
            };
            let cfg = load_config(&config_path)?;
            let dir = cfg.data_dir();
            let records = storage::read_range(&dir, from, to)
                .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
            match output {
                Some(path) => {
                    let mut f = std::io::BufWriter::new(
                        std::fs::File::create(&path).map_err(|e| format!("{path}: {e}"))?,
                    );
                    export::write(&records, format, &mut f)
                        .and_then(|_| f.flush())
                        .map_err(|e| format!("{path}: {e}"))?;
                    eprintln!("Exported {} record(s) to {path}", records.len());
                }
                None => {
                    let stdout = std::io::stdout();
                    let mut lock = std::io::BufWriter::new(stdout.lock());
                    match export::write(&records, format, &mut lock).and_then(|_| lock.flush()) {
                        Ok(()) => {}
                        // `tirnix export | head` closes the pipe early.
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                        Err(e) => return Err(e.to_string()),
                    }
                    if records.is_empty() {
                        eprintln!(
                            "No records in the selected range (data directory: {}).",
                            dir.display()
                        );
                    }
                }
            }
        }
        "config" => {
            let sub = if rest.is_empty() {
                "path".to_string()
            } else {
                rest.remove(0)
            };
            no_more(&rest)?;
            match sub.as_str() {
                "path" => println!("{}", config_path.display()),
                "show" => print!("{}", load_config(&config_path)?.to_toml()),
                other => return Err(format!("unknown config command: {other}")),
            }
        }
        other => {
            return Err(format!(
                "unknown command: {other}\nRun `tirnix --help` for usage."
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn logger_cmd(sub: &str, config_path: &Path) -> Result<ExitCode, String> {
    let mut cfg = load_config(config_path)?;
    let dir = cfg.data_dir();
    match sub {
        "run" => {
            let code = logger::run(config_path);
            return Ok(ExitCode::from(code as u8));
        }
        "status" => print!("{}", logger::describe(&logger::status(&dir), &cfg)),
        "start" => {
            if logger::status(&dir).running {
                println!("Logger is already running for {}.", dir.display());
                return Ok(ExitCode::SUCCESS);
            }
            if !cfg.logging.enabled {
                cfg.logging.enabled = true;
                cfg.save(config_path)
                    .map_err(|e| format!("cannot save {}: {e}", config_path.display()))?;
                println!("Enabled logging in {}.", config_path.display());
            }
            logger::spawn_detached(config_path, &cfg)?;
            println!(
                "Logger started: every {} s into {}.",
                cfg.logging.interval_secs,
                dir.display()
            );
        }
        "stop" => {
            if cfg.logging.enabled {
                cfg.logging.enabled = false;
                cfg.save(config_path)
                    .map_err(|e| format!("cannot save {}: {e}", config_path.display()))?;
                println!("Disabled logging in {}.", config_path.display());
            }
            match logger::stop(&dir)? {
                true => println!("Logger stopped."),
                false => println!("Logger was not running."),
            }
        }
        other => return Err(format!("unknown logger command: {other}")),
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tirnix: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn global_config_flag_anywhere() {
        let a = parse_global(v(&["logger", "--config", "/x.toml", "status"])).unwrap();
        assert_eq!(a.config, Some(PathBuf::from("/x.toml")));
        assert_eq!(a.rest, v(&["logger", "status"]));
        let a = parse_global(v(&["--config=/y.toml"])).unwrap();
        assert_eq!(a.config, Some(PathBuf::from("/y.toml")));
        assert!(parse_global(v(&["--config"])).is_err());
    }

    #[test]
    fn option_extraction() {
        let mut a = v(&["--since", "6h", "--format=csv"]);
        assert_eq!(take_opt(&mut a, "--since").unwrap(), Some("6h".into()));
        assert_eq!(take_opt(&mut a, "--format").unwrap(), Some("csv".into()));
        assert_eq!(take_opt(&mut a, "--to").unwrap(), None);
        assert!(a.is_empty());
        let mut b = v(&["--since"]);
        assert!(take_opt(&mut b, "--since").is_err());
    }
}
