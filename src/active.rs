//! Optional active connectivity checks.
//!
//! These are the only parts of Tirnix that generate network traffic. They
//! run only when the user explicitly triggers them, against targets the user
//! configured (`[active_checks] targets`). Passive monitoring never calls
//! anything in this module.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct CheckResult {
    pub target: String,
    /// Time to resolve the name, and the addresses found.
    pub dns: Result<(Duration, Vec<SocketAddr>), String>,
    /// Time to complete a TCP handshake with the first address.
    pub connect: Option<Result<(Duration, SocketAddr), String>>,
}

/// Validate a `host:port` target without contacting anything.
pub fn validate_target(t: &str) -> Result<(), String> {
    let (host, port) = t
        .rsplit_once(':')
        .ok_or_else(|| format!("\"{t}\": expected host:port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("\"{t}\": missing host"));
    }
    match port.parse::<u16>() {
        Ok(p) if p > 0 => Ok(()),
        _ => Err(format!("\"{t}\": invalid port")),
    }
}

fn check_one(target: &str, timeout: Duration) -> CheckResult {
    let start = Instant::now();
    // Note: the system resolver has its own timeout; it cannot be bounded here.
    let dns = target
        .to_socket_addrs()
        .map(|a| (start.elapsed(), a.collect::<Vec<_>>()))
        .map_err(|e| e.to_string());
    let connect = match &dns {
        Ok((_, addrs)) if !addrs.is_empty() => {
            let addr = addrs[0];
            let t = Instant::now();
            Some(
                TcpStream::connect_timeout(&addr, timeout)
                    .map(|_| (t.elapsed(), addr))
                    .map_err(|e| e.to_string()),
            )
        }
        Ok(_) => Some(Err("no addresses found".into())),
        Err(_) => None,
    };
    CheckResult {
        target: target.to_string(),
        dns,
        connect,
    }
}

/// Run all checks on a background thread; results arrive on the channel
/// once, in target order.
pub fn spawn(targets: Vec<String>, timeout: Duration) -> Receiver<Vec<CheckResult>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let results = targets.iter().map(|t| check_one(t, timeout)).collect();
        let _ = tx.send(results);
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_validation() {
        assert!(validate_target("example.com:443").is_ok());
        assert!(validate_target("[::1]:22").is_ok());
        assert!(validate_target("example.com").is_err());
        assert!(validate_target(":80").is_err());
        assert!(validate_target("host:0").is_err());
        assert!(validate_target("host:99999").is_err());
    }

    #[test]
    fn local_listener_is_reachable() {
        // Uses only the loopback interface.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target = l.local_addr().unwrap().to_string();
        let r = check_one(&target, Duration::from_secs(2));
        assert!(r.dns.is_ok());
        assert!(matches!(r.connect, Some(Ok(_))));
    }
}
