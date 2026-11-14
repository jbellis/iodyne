//! Filesystem capacity from sysinfo, or native mount statistics on macOS.
//!
//! macOS includes non-browsable APFS and HFS+ mounts that sysinfo filters out.

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
    let mut out: Vec<FsTick> = mounts::macos_mount_table()
        .into_iter()
        .filter(|(_, device)| super::topology::device_name(device).starts_with("disk"))
        .filter_map(|(mount, device)| {
            let removable = disks
                .list()
                .iter()
                .find(|disk| disk.mount_point() == std::path::Path::new(&mount))
                .is_some_and(|disk| disk.is_removable());
            macos_mount(mount, device, removable)
        })
        .collect();
    #[cfg(not(target_os = "macos"))]
    let mut out: Vec<FsTick> = disks
        .list()
        .iter()
        .map(|disk| {
            let mount = disk.mount_point().to_string_lossy().to_string();
            let total = disk.total_space();
            let avail = disk.available_space();
            FsTick {
                is_system: is_system_mount(&mount),
                mount,
                device: disk.name().to_string_lossy().to_string(),
                fs_type: disk.file_system().to_string_lossy().to_string(),
                size_bytes: total,
                used_bytes: total.saturating_sub(avail),
                avail_bytes: avail,
                inode_pct: None,
                is_removable: disk.is_removable(),
            }
        })
        .collect();
    // Stable order: system mounts first, then user, then size desc.
    out.sort_by(|a, b| {
        b.is_system
            .cmp(&a.is_system)
            .then(b.size_bytes.cmp(&a.size_bytes))
            .then(a.mount.cmp(&b.mount))
    });
    out
}

#[cfg(target_os = "macos")]
fn macos_mount(mount: String, device: String, is_removable: bool) -> Option<FsTick> {
    let path = std::ffi::CString::new(mount.as_bytes()).ok()?;
    // SAFETY: path is NUL-terminated and lives through the call. stat points to
    // writable, correctly aligned storage. statfs initializes it on success;
    // the failure branch returns before any uninitialized fields are read.
    let stat = unsafe {
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if libc::statfs(path.as_ptr(), stat.as_mut_ptr()) != 0 {
            return None;
        }
        stat.assume_init()
    };
    let fs_type = stat
        .f_fstypename
        .iter()
        .take_while(|ch| **ch != 0)
        .map(|ch| *ch as u8 as char)
        .collect();
    let size_bytes = stat.f_blocks.saturating_mul(u64::from(stat.f_bsize));
    let avail_bytes = stat.f_bavail.saturating_mul(u64::from(stat.f_bsize));
    Some(FsTick {
        is_system: is_system_mount(&mount),
        mount,
        device,
        fs_type,
        size_bytes,
        used_bytes: size_bytes.saturating_sub(avail_bytes),
        avail_bytes,
        inode_pct: None,
        is_removable,
    })
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
