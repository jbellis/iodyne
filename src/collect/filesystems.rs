//! Filesystem (mount) enumeration via `sysinfo::Disks`.
//!
//! One entry per mount point. sysinfo provides total / available bytes,
//! file-system kind, mount path, device name on Linux. On macOS sysinfo's
//! disk name is the volume label, so we resolve mount point to BSD device via
//! `/sbin/mount`. Inode usage and 7d growth aren't in sysinfo — inode % is
//! `None` for now; growth is computed by the App from a snapshot ring.

use sysinfo::Disks;

#[cfg(target_os = "macos")]
use crate::collect::mounts;

#[derive(Debug, Clone)]
pub struct FsTick {
    pub mount: String,
    pub device: String,
    pub fs_type: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub avail_bytes: u64,
    pub inode_pct: Option<u32>,
    /// Retained as mount-level evidence for future filtering and JSON output.
    #[allow(dead_code)]
    pub is_removable: bool,
    pub is_system: bool,
}

pub fn collect() -> Vec<FsTick> {
    let disks = Disks::new_with_refreshed_list();
    #[cfg(target_os = "macos")]
    let mount_table = mounts::macos_mount_table();

    let mut out: Vec<FsTick> = disks
        .list()
        .iter()
        .map(|d| {
            let mount = d.mount_point().to_string_lossy().to_string();
            let reported_device = d.name().to_string_lossy().to_string();
            #[cfg(target_os = "macos")]
            let device = mount_table.get(&mount).cloned().unwrap_or(reported_device);
            #[cfg(not(target_os = "macos"))]
            let device = reported_device;
            let fs_type = d.file_system().to_string_lossy().to_string();
            let total = d.total_space();
            let avail = d.available_space();
            let used = total.saturating_sub(avail);
            FsTick {
                is_system: is_system_mount(&mount),
                mount,
                device,
                fs_type,
                size_bytes: total,
                used_bytes: used,
                avail_bytes: avail,
                inode_pct: None,
                is_removable: d.is_removable(),
            }
        })
        .collect();
    // Stable order: system mounts first, then user, then size desc.
    out.sort_by(|a, b| {
        b.is_system
            .cmp(&a.is_system)
            .then(b.size_bytes.cmp(&a.size_bytes))
    });
    out
}

fn is_system_mount(path: &str) -> bool {
    matches!(
        path,
        "/" | "/boot"
            | "/boot/efi"
            | "/private/var/vm"
            | "/System/Volumes/Data"
            | "/System/Volumes/Preboot"
            | "/System/Volumes/Recovery"
            | "/System/Volumes/Update"
            | "/System/Volumes/VM"
            | "/System/Volumes/iSCPreboot"
            | "/System/Volumes/Hardware"
    ) || path.starts_with("/System/Volumes/")
        || path.starts_with("/dev")
        || path.starts_with("/proc")
        || path.starts_with("/sys")
}
