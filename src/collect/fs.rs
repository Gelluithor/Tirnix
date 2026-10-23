//! Filesystem usage via the mount table and `statvfs(3)`.

use std::collections::HashMap;
use std::ffi::CString;

use super::procfs::Mount;
use crate::metrics::FsStats;

/// Pseudo and read-only image filesystems that never hold user data.
const IGNORED_TYPES: &[&str] = &[
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "iso9660",
    "mqueue",
    "nsfs",
    "proc",
    "pstore",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "squashfs",
    "sysfs",
    "tracefs",
];

/// Network and FUSE filesystems. `statvfs` on an unreachable server can
/// block for a long time, so these are skipped unless explicitly enabled.
const NETWORK_TYPES: &[&str] = &[
    "9p",
    "afs",
    "ceph",
    "cifs",
    "davfs",
    "glusterfs",
    "lustre",
    "nfs",
    "nfs4",
    "smb3",
    "smbfs",
    "sshfs",
];

/// Mount points managed by container runtimes; they repeat the host
/// filesystem many times over and only add noise.
const IGNORED_PREFIXES: &[&str] = &[
    "/var/lib/docker/",
    "/var/lib/containers/",
    "/var/lib/kubelet/",
    "/run/containerd/",
    "/run/k3s/",
    "/run/docker/",
    "/snap/",
    "/var/snap/",
];

pub fn is_network_fs(fstype: &str) -> bool {
    NETWORK_TYPES.contains(&fstype) || fstype.starts_with("fuse.")
}

pub fn should_include(m: &Mount, include_network: bool) -> bool {
    if IGNORED_TYPES.contains(&m.fstype.as_str()) {
        return false;
    }
    if is_network_fs(&m.fstype) && !include_network {
        return false;
    }
    if IGNORED_PREFIXES
        .iter()
        .any(|p| m.mount_point.starts_with(p))
    {
        return false;
    }
    // Overlay mounts outside the container root are runtime internals.
    if m.fstype == "overlay" && m.mount_point != "/" {
        return false;
    }
    // Container runtimes mask parts of /proc and /sys with tmpfs mounts and
    // give /dev its own tmpfs; none of these hold user data.
    let under = |p: &str| m.mount_point == p || m.mount_point.starts_with(&format!("{p}/"));
    if under("/proc") || under("/sys") || (m.mount_point == "/dev" && m.fstype == "tmpfs") {
        return false;
    }
    true
}

/// Space and inode figures for one mount point.
pub fn statvfs(path: &str) -> Option<FsStats> {
    let c = CString::new(path).ok()?;
    // SAFETY: `st` is plain data filled in by statvfs; we check the result.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let frsize = if st.f_frsize > 0 {
        st.f_frsize as u64
    } else {
        st.f_bsize as u64
    };
    let total = st.f_blocks as u64 * frsize;
    let free = st.f_bfree as u64 * frsize;
    Some(FsStats {
        mount_point: path.to_string(),
        total,
        used: total.saturating_sub(free),
        avail: st.f_bavail as u64 * frsize,
        inodes_total: st.f_files as u64,
        inodes_free: st.f_ffree as u64,
        // `c_ulong` is 32-bit on some targets, so the casts are not redundant everywhere.
        #[allow(clippy::unnecessary_cast)]
        readonly: (st.f_flag as u64) & (libc::ST_RDONLY as u64) != 0,
        ..Default::default()
    })
}

/// Filter the mount table and de-duplicate bind mounts / subvolumes that
/// share one block device (keeping the shortest mount point).
pub fn select_mounts(mounts: &[Mount], include_network: bool) -> Vec<&Mount> {
    let mut by_device: HashMap<&str, &Mount> = HashMap::new();
    let mut others = Vec::new();
    for m in mounts.iter().filter(|m| should_include(m, include_network)) {
        if m.device.starts_with("/dev/") {
            by_device
                .entry(m.device.as_str())
                .and_modify(|cur| {
                    if m.mount_point.len() < cur.mount_point.len() {
                        *cur = m;
                    }
                })
                .or_insert(m);
        } else if !others
            .iter()
            .any(|o: &&Mount| o.mount_point == m.mount_point)
        {
            others.push(m);
        }
    }
    let mut out: Vec<&Mount> = by_device.into_values().chain(others).collect();
    out.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    out
}

pub fn collect(mounts: &[Mount], include_network: bool) -> Vec<FsStats> {
    select_mounts(mounts, include_network)
        .into_iter()
        .filter_map(|m| {
            let mut s = statvfs(&m.mount_point)?;
            if s.total == 0 {
                return None;
            }
            s.device = m.device.clone();
            s.fstype = m.fstype.clone();
            // Prefer the superblock state: statvfs also reports read-only
            // for read-only bind mounts of writable filesystems.
            if let Some(ro) = m.sb_readonly {
                s.readonly = ro;
            }
            Some(s)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::procfs::parse_mounts;

    const MOUNTS: &str = "sysfs /sys sysfs rw 0 0
proc /proc proc rw 0 0
/dev/sda2 / ext4 rw 0 0
/dev/sda2 /var/lib/docker/btrfs ext4 rw 0 0
/dev/sda2 /home ext4 rw 0 0
/dev/sda1 /boot/efi vfat rw 0 0
tmpfs /run tmpfs rw 0 0
tmpfs /run tmpfs rw 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw 0 0
nas:/export /mnt/nas nfs4 rw 0 0
sshfs#me@host: /mnt/remote fuse.sshfs rw 0 0
/dev/loop0 /snap/core/123 squashfs ro 0 0
";

    #[test]
    fn mount_selection() {
        let m = parse_mounts(MOUNTS);
        let sel: Vec<&str> = select_mounts(&m, false)
            .iter()
            .map(|m| m.mount_point.as_str())
            .collect();
        assert_eq!(sel, vec!["/", "/boot/efi", "/run"]);

        let with_net: Vec<&str> = select_mounts(&m, true)
            .iter()
            .map(|m| m.mount_point.as_str())
            .collect();
        assert!(with_net.contains(&"/mnt/nas"));
        assert!(with_net.contains(&"/mnt/remote"));
    }

    #[test]
    fn container_masks_are_skipped() {
        // Excerpt of /proc/self/mountinfo inside a Docker container.
        let text = "\
153 97 0:55 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b,workdir=/c
155 153 0:71 / /proc rw,nosuid - proc proc rw
156 153 0:72 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
160 156 0:77 / /dev/shm rw,nosuid - tmpfs shm rw,size=65536k
161 153 254:1 /docker/volumes/t/_data /target rw - ext4 /dev/vda1 rw
162 153 254:1 /docker/containers/x/hosts /etc/hosts rw - ext4 /dev/vda1 rw
170 155 0:72 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
171 155 0:78 / /proc/scsi ro,relatime - tmpfs tmpfs ro
172 157 0:79 / /sys/firmware ro,relatime - tmpfs tmpfs ro
";
        let m = crate::collect::procfs::parse_mountinfo(text);
        let sel: Vec<&str> = select_mounts(&m, false)
            .iter()
            .map(|m| m.mount_point.as_str())
            .collect();
        assert_eq!(sel, vec!["/", "/dev/shm", "/target"]);
    }

    #[test]
    fn statvfs_root_works() {
        // "/" exists on every Unix system the tests run on.
        let s = statvfs("/").expect("statvfs on /");
        assert!(s.total > 0);
        assert!(s.used <= s.total);
        assert!(statvfs("/definitely/not/here").is_none());
    }
}
