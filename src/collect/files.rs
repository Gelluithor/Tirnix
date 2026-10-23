//! Open files that explain disk usage, from `/proc/<pid>/fd`.
//!
//! Only used while a filesystem is nearly full or disk I/O is high, because
//! it touches every file descriptor of the inspected processes.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;

use crate::metrics::OpenFile;

/// Files smaller than this are not worth reporting as deleted-but-open.
pub const DELETED_MIN_SIZE: u64 = 1024 * 1024;
const DELETED_SUFFIX: &str = " (deleted)";

/// `flags:` line of `/proc/<pid>/fdinfo/<fd>` (octal): opened for writing?
pub fn fdinfo_writing(text: &str) -> Option<bool> {
    let flags = text
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())?;
    // O_ACCMODE: 1 = O_WRONLY, 2 = O_RDWR.
    Some(matches!(flags & 0o3, 1 | 2))
}

fn comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Visit regular files open in the given processes (all when `None`).
/// Each file (device + inode) is reported once. Returns whether some
/// processes could not be inspected.
fn visit(pids: Option<&[u32]>, mut f: impl FnMut(OpenFile, bool)) -> bool {
    let list: Vec<u32> = match pids {
        Some(p) => p.to_vec(),
        None => fs::read_dir("/proc")
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default(),
    };
    let mut hidden = false;
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    for pid in list {
        let dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&dir) else {
            hidden = true;
            continue;
        };
        let mut name: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy().into_owned();
            if !target.starts_with('/') {
                continue; // sockets, pipes, anon inodes
            }
            // Following the link works even for deleted files.
            let Ok(meta) = fs::metadata(fd.path()) else {
                continue;
            };
            if !meta.is_file() || !seen.insert((meta.dev(), meta.ino())) {
                continue;
            }
            let deleted = target.ends_with(DELETED_SUFFIX);
            let writing = fs::read_to_string(format!(
                "/proc/{pid}/fdinfo/{}",
                fd.file_name().to_string_lossy()
            ))
            .ok()
            .and_then(|t| fdinfo_writing(&t))
            .unwrap_or(false);
            let file = OpenFile {
                pid,
                comm: name.get_or_insert_with(|| comm(pid)).clone(),
                path: target.trim_end_matches(DELETED_SUFFIX).to_string(),
                size: meta.len(),
                dev: meta.dev(),
                writing,
            };
            f(file, deleted);
        }
    }
    hidden
}

/// Deleted files still held open, largest first.
pub fn deleted_open_files(limit: usize) -> (Vec<OpenFile>, bool) {
    let mut out = Vec::new();
    let hidden = visit(None, |file, deleted| {
        if deleted && file.size >= DELETED_MIN_SIZE {
            out.push(file);
        }
    });
    out.sort_by_key(|f| std::cmp::Reverse(f.size));
    out.truncate(limit);
    (out, hidden)
}

/// Files that the given processes have open for writing, largest first.
pub fn written_files(pids: &[u32], limit: usize) -> (Vec<OpenFile>, bool) {
    let mut out = Vec::new();
    let hidden = visit(Some(pids), |file, _| {
        if file.writing {
            out.push(file);
        }
    });
    out.sort_by_key(|f| std::cmp::Reverse(f.size));
    out.truncate(limit);
    (out, hidden)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn fdinfo_flags() {
        assert_eq!(
            fdinfo_writing("pos:\t0\nflags:\t0100001\nmnt_id:\t21\n"),
            Some(true)
        );
        assert_eq!(fdinfo_writing("pos:\t0\nflags:\t02\n"), Some(true));
        assert_eq!(fdinfo_writing("pos:\t0\nflags:\t0100000\n"), Some(false));
        assert_eq!(fdinfo_writing("pos:\t0\n"), None);
    }

    #[test]
    fn finds_own_deleted_and_written_files() {
        if !std::path::Path::new("/proc/self/fd").exists() {
            return; // not Linux
        }
        let path = std::env::temp_dir().join(format!("tirnix-deleted-{}", std::process::id()));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(&vec![0u8; 2 * DELETED_MIN_SIZE as usize])
            .unwrap();
        f.flush().unwrap();
        fs::remove_file(&path).unwrap();

        let me = std::process::id();
        let (written, _) = written_files(&[me], 50);
        assert!(
            written
                .iter()
                .any(|w| w.path == path.to_string_lossy() && w.pid == me)
        );
        let (deleted, _) = deleted_open_files(1000);
        let hit = deleted
            .iter()
            .find(|d| d.pid == me && d.path == path.to_string_lossy())
            .expect("own deleted file found");
        assert_eq!(hit.size, 2 * DELETED_MIN_SIZE);
        drop(f);
    }
}
