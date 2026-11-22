//! Cross-platform device enumeration.
//!
//! - **macOS**: `system_profiler -json` for model / firmware / serial /
//!   SMART / removability. Cached APFS metadata maps containers to physical
//!   stores; independent HFS+ partitions contribute their own capacity usage.
//! - **Other**: `sysinfo::Disks` as the sole source; metadata fields are
//!   left as placeholders until a platform-specific collector lands.

use std::collections::HashMap;

#[cfg(not(target_os = "macos"))]
use sysinfo::Disks;

#[cfg(target_os = "macos")]
use crate::collect::macos;

#[cfg(target_os = "linux")]
use crate::collect::linux;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Nvme,
    /// Reserved for Linux sysfs classification (SATA SSDs) — macOS reports
    /// these as SATA which we currently bucket as HDD until rotation_rpm
    /// distinguishes them.
    #[allow(dead_code)]
    Ssd,
    Hdd,
    UsbMassStorage,
    Unknown,
}

impl DeviceKind {
    pub fn label(&self) -> &'static str {
        match self {
            DeviceKind::Nvme => "NVMe",
            DeviceKind::Ssd => "SSD",
            DeviceKind::Hdd => "HDD",
            DeviceKind::UsbMassStorage => "USB",
            DeviceKind::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceTick {
    pub name: String,
    pub kind: DeviceKind,
    pub model: String,
    pub bus: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub is_removable: bool,
    /// Collected inventory evidence reserved for richer device facts.
    #[allow(dead_code)]
    pub firmware: Option<String>,
    /// Collected inventory evidence reserved for richer device facts.
    #[allow(dead_code)]
    pub serial: Option<String>,
    pub smart_ok: Option<bool>,
    /// Distinguishes discovered devices with no reported media capacity.
    #[allow(dead_code)]
    pub idle: bool,
}

#[allow(dead_code)] // Compatibility wrapper for callers without volume metadata.
pub fn collect() -> Vec<DeviceTick> {
    collect_with_volumes(&super::VolumeTick::default())
}

/// Collect devices using the caller's cached volume snapshot for usage
/// attribution. The TUI refreshes this snapshot at metadata cadence, so a
/// ZFS CLI process is never spawned on the faster usage refresh.
pub fn collect_with_volumes(volumes: &super::VolumeTick) -> Vec<DeviceTick> {
    let _ = volumes;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mounts_used = sysinfo_mount_used();

    #[cfg(target_os = "macos")]
    {
        let mut macs = macos::collect();
        // Apple's internal SSD reports identical model entries per
        // controller occasionally; dedupe by bsd_name.
        macs.sort_by(|a, b| a.bsd_name.cmp(&b.bsd_name));
        macs.dedup_by(|a, b| a.bsd_name == b.bsd_name);

        let used_by_phys = macos_used_by_device(volumes);

        let mut out: Vec<DeviceTick> = macs
            .into_iter()
            .map(|m| {
                let kind = match m.controller_kind {
                    macos::ControllerKind::Nvme => DeviceKind::Nvme,
                    macos::ControllerKind::Sata => DeviceKind::Hdd,
                    macos::ControllerKind::Usb => DeviceKind::UsbMassStorage,
                    macos::ControllerKind::Unknown => DeviceKind::Unknown,
                };
                let used = used_by_phys.get(&m.bsd_name).copied().unwrap_or(0);
                DeviceTick {
                    name: m.bsd_name,
                    kind,
                    model: m.model,
                    bus: m.protocol,
                    size_bytes: m.size_bytes,
                    used_bytes: used.min(m.size_bytes),
                    is_removable: m.removable,
                    firmware: m.firmware,
                    serial: m.serial,
                    smart_ok: m.smart_ok,
                    idle: m.size_bytes == 0,
                }
            })
            .collect();
        out.sort_by_key(|device| std::cmp::Reverse(device.size_bytes));
        out
    }

    #[cfg(target_os = "linux")]
    {
        let used_by_device = linux_used_by_device(volumes);
        let mut out: Vec<DeviceTick> = linux::collect()
            .into_iter()
            .map(|l| {
                let kind = match l.kind {
                    linux::LinuxKind::Nvme => DeviceKind::Nvme,
                    linux::LinuxKind::Ssd => DeviceKind::Ssd,
                    linux::LinuxKind::Hdd => DeviceKind::Hdd,
                    linux::LinuxKind::UsbMassStorage => DeviceKind::UsbMassStorage,
                    linux::LinuxKind::Unknown => DeviceKind::Unknown,
                };
                let bus = match kind {
                    DeviceKind::Nvme => "PCIe / NVMe".to_string(),
                    DeviceKind::UsbMassStorage => "USB".to_string(),
                    // sysfs rotation data distinguishes spinning from solid-state
                    // media, but says nothing about SATA. In particular, WSL often
                    // presents physical NVMe storage as a synthetic SCSI disk.
                    DeviceKind::Hdd | DeviceKind::Ssd => "—".to_string(),
                    DeviceKind::Unknown => "—".to_string(),
                };
                let used = used_by_device.get(&l.name).copied().unwrap_or(0);
                DeviceTick {
                    name: l.name,
                    kind,
                    model: l.model,
                    bus,
                    size_bytes: l.size_bytes,
                    used_bytes: used,
                    is_removable: l.removable,
                    firmware: l.firmware,
                    serial: l.serial,
                    // SMART status comes from smartctl in the separate
                    // SmartCollector; the linux collector doesn't set it.
                    smart_ok: None,
                    idle: l.size_bytes == 0,
                }
            })
            .collect();
        out.sort_by_key(|device| std::cmp::Reverse(device.size_bytes));
        out
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let mut out: Vec<DeviceTick> = mounts_used
            .into_iter()
            .map(|(name, used)| {
                let kind = classify_by_name(&name);
                DeviceTick {
                    name: name.clone(),
                    kind,
                    model: "—".to_string(),
                    bus: bus_hint(&kind),
                    size_bytes: 0,
                    used_bytes: used,
                    is_removable: false,
                    firmware: None,
                    serial: None,
                    smart_ok: None,
                    idle: false,
                }
            })
            .collect();
        let disks = Disks::new_with_refreshed_list();
        for d in disks.list() {
            let n = short_name(&d.name().to_string_lossy());
            if let Some(e) = out.iter_mut().find(|e| e.name == n) {
                e.size_bytes = e.size_bytes.max(d.total_space());
                if d.is_removable() {
                    e.is_removable = true;
                    e.kind = DeviceKind::UsbMassStorage;
                }
            }
        }
        out.sort_by_key(|device| std::cmp::Reverse(device.size_bytes));
        out
    }
}

/// Fast path: re-reads sysinfo and updates `used_bytes` on an existing
/// device list without redoing the slow `system_profiler` enrichment.
///
/// On macOS this uses the caller's cached APFS and AppleRAID topology.
#[allow(dead_code)] // Kept for callers that do not have a cached volume snapshot.
pub fn refresh_usage(devices: &mut [DeviceTick]) {
    refresh_usage_with_volumes(devices, &super::VolumeTick::default());
}

/// Fast usage refresh using the already collected volume state.
#[allow(dead_code)] // Kept for callers without resolved volume rows.
pub fn refresh_usage_with_volumes(devices: &mut [DeviceTick], volumes: &super::VolumeTick) {
    let _ = volumes;
    // Linux: shared attribution with collect() — a mount's usage lands
    // only on the device(s) it actually lives on. (v0.1.1 summed every
    // mount into every device here, so an 8-disk bcachefs box showed
    // each disk at 266% — issue #4.)
    #[cfg(target_os = "linux")]
    {
        let used = linux_used_by_device(volumes);
        for d in devices.iter_mut() {
            d.used_bytes = used.get(&d.name).copied().unwrap_or(0);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let used = macos_used_by_device(volumes);
        apply_macos_usage(devices, &used);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let mounts = sysinfo_mount_used();
        for device in devices {
            device.used_bytes = mounts
                .iter()
                .filter(|(name, _)| *name == device.name)
                .map(|(_, used)| *used)
                .max()
                .unwrap_or(0);
        }
    }
}

/// Fast usage refresh reusing already resolved volume rows when available.
pub fn refresh_usage_with_volume_rows(
    devices: &mut [DeviceTick],
    volumes: &super::VolumeTick,
    volume_rows: &[super::storage::VolumeRow],
) {
    #[cfg(target_os = "macos")]
    {
        let _ = volumes;
        let used = usage_by_disk(volume_rows);
        apply_macos_usage(devices, &used);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = volume_rows;
        refresh_usage_with_volumes(devices, volumes);
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_usage(devices: &mut [DeviceTick], used: &HashMap<String, u64>) {
    for device in devices {
        device.used_bytes = used
            .get(&device.name)
            .copied()
            .unwrap_or(0)
            .min(device.size_bytes);
    }
}

/// Linux: map whole-disk device names to used bytes, attributing each
/// mounted filesystem to the device(s) backing it.
#[cfg(target_os = "linux")]
fn linux_used_by_device(volumes: &super::VolumeTick) -> HashMap<String, u64> {
    let disks = Disks::new_with_refreshed_list();
    // Dedupe by raw mount source first: the same source mounted at
    // several points (bind mounts, btrfs subvolumes, `/` + `/nix/store`)
    // is one filesystem and must count once.
    let mut by_source: HashMap<String, u64> = HashMap::new();
    for d in disks.list() {
        let used = d.total_space().saturating_sub(d.available_space());
        if used == 0 {
            continue;
        }
        let source = d.name().to_string_lossy().to_string();
        let entry = by_source.entry(source).or_insert(0);
        if used > *entry {
            *entry = used;
        }
    }
    let mut out = attribute_sources(&by_source, &sysfs_source_members);
    for (device, used) in zfs_allocations_by_device(&volumes.zfs) {
        let entry = out.entry(device).or_insert(0);
        *entry = entry.saturating_add(used);
    }
    out
}

/// Per-leaf allocation by whole-disk name. Data, log, special, and dedup
/// allocations count as occupied storage; cache and spare allocations do not.
#[cfg(any(target_os = "linux", test))]
fn zfs_allocations_by_device(pools: &[super::volumes::ZfsPool]) -> HashMap<String, u64> {
    zfs_allocations_by_device_with_members(pools, &stacked_device_members)
}

#[cfg(any(target_os = "linux", test))]
fn zfs_allocations_by_device_with_members(
    pools: &[super::volumes::ZfsPool],
    stacked_members: &dyn Fn(&str) -> Option<Vec<String>>,
) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    for pool in pools {
        for (leaf, allocated) in pool.leaf_allocations() {
            if matches!(
                leaf.section,
                super::volumes::ZfsVdevSection::Cache | super::volumes::ZfsVdevSection::Spare
            ) {
                continue;
            }
            let members = zfs_leaf_disk_names_with(&leaf.name, stacked_members);
            let share = allocated / members.len() as u64;
            let remainder = allocated % members.len() as u64;
            for (index, member) in members.into_iter().enumerate() {
                let entry = out.entry(member).or_insert(0u64);
                *entry = entry.saturating_add(share + u64::from((index as u64) < remainder));
            }
        }
    }
    out
}

pub(crate) fn zfs_leaf_disk_names(name: &str) -> Vec<String> {
    zfs_leaf_disk_names_with(name, &stacked_device_members)
}

fn zfs_leaf_disk_names_with(
    name: &str,
    stacked_members: &dyn Fn(&str) -> Option<Vec<String>>,
) -> Vec<String> {
    let path = if name.starts_with("/dev/") {
        name.to_string()
    } else {
        format!("/dev/{name}")
    };
    let mut members = stacked_members(&path)
        .filter(|members| !members.is_empty())
        .unwrap_or_else(|| vec![short_name(name)]);
    members = members
        .into_iter()
        .map(|member| short_name(&member))
        .collect();
    members.sort();
    members.dedup();
    members
}

/// Attribute per-mount-source used bytes to whole-disk device names.
///
/// Handles the source shapes that broke v0.1.1 (issue #4):
/// - `/dev/sda1` — plain partition → parent disk.
/// - `/dev/sda:/dev/sdb:...` — bcachefs multi-device → split across members.
/// - `/dev/md0`, `/dev/mapper/vg-lv` — stacked devices → resolved to their
///   member disks via `slaves`.
/// - Btrfs sources — statfs usage split across all member whole disks.
/// - `overlay`, `tmpfs`, ZFS datasets — no `/dev/` source → attributed to
///   nothing rather than to everything. ZFS leaf allocation comes from the
///   separately cached `zpool list` snapshot.
///
/// statfs totals are filesystem-wide, so a filesystem spanning N disks is
/// split evenly — per-member truth isn't knowable from statfs alone.
///
/// `slaves` resolves a stacked block device path to its member disk names
/// (`/dev/md0` → `["sda", "sdb"]`), returning `None` for plain devices.
// Only called from Linux collection, but compiled everywhere so the
// pure-logic tests run on any development machine.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn attribute_sources(
    by_source: &HashMap<String, u64>,
    slaves: &dyn Fn(&str) -> Option<Vec<String>>,
) -> HashMap<String, u64> {
    let mut out: HashMap<String, u64> = HashMap::new();
    for (source, used) in by_source {
        let mut members: Vec<String> = source
            .split(':')
            .filter(|piece| piece.starts_with("/dev/"))
            .flat_map(|piece| match slaves(piece) {
                Some(m) if !m.is_empty() => m,
                _ => vec![short_name(piece)],
            })
            .map(|member| short_name(&member))
            .collect();
        members.sort();
        members.dedup();
        if members.is_empty() {
            continue;
        }
        let share = used / members.len() as u64;
        for m in members {
            let entry = out.entry(m).or_insert(0);
            *entry = entry.saturating_add(share);
        }
    }
    out
}

/// Resolve a stacked block device (`/dev/md0`, `/dev/mapper/vg-lv`) to its
/// member disk names via `/sys/block/<dev>/slaves`, following nesting
/// (dm-on-md) a few levels deep. Returns `None` for plain devices.
#[cfg(target_os = "linux")]
fn sysfs_slaves(dev_path: &str) -> Option<Vec<String>> {
    // /dev/mapper/* entries are symlinks to ../dm-N — resolve to the
    // kernel name that /sys/block uses.
    let kernel_name = match std::fs::read_link(dev_path) {
        Ok(target) => target.file_name()?.to_string_lossy().into_owned(),
        Err(_) => dev_path.trim_start_matches("/dev/").to_string(),
    };

    fn expand(name: &str, depth: u8, out: &mut Vec<String>) {
        let slaves_dir = format!("/sys/block/{}/slaves", name);
        let entries: Vec<String> = std::fs::read_dir(&slaves_dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        if entries.is_empty() || depth == 0 {
            out.push(short_name(name));
            return;
        }
        for slave in entries {
            // Slaves may be partitions (sda1) — fold to the parent disk.
            expand(&short_name(&slave), depth - 1, out);
        }
    }

    if !std::path::Path::new(&format!("/sys/block/{}/slaves", kernel_name)).is_dir() {
        return None;
    }
    let mut out = Vec::new();
    expand(&kernel_name, 4, &mut out);
    Some(out)
}

pub(crate) fn stacked_device_members(name: &str) -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        let path = if name.starts_with("/dev/") {
            name.to_string()
        } else {
            format!("/dev/{name}")
        };
        sysfs_slaves(&path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        None
    }
}

/// Resolve btrfs peers first, then expand any stacked peer through its slaves.
#[cfg(target_os = "linux")]
fn sysfs_source_members(dev_path: &str) -> Option<Vec<String>> {
    let source = super::btrfs::kernel_name(dev_path);
    if let Some(members) = super::btrfs::members(&source) {
        let mut out = Vec::new();
        for member in members {
            if let Some(slaves) = sysfs_slaves(&format!("/dev/{member}")) {
                out.extend(slaves);
            } else {
                out.push(member);
            }
        }
        out.sort();
        out.dedup();
        return Some(out);
    }
    sysfs_slaves(dev_path)
}

/// Returns (physical-or-container-disk, used_bytes) per sysinfo mount,
/// already deduped by short name. On macOS the disk is the synthesized
/// container (e.g. `disk3`); the caller maps it to the physical.
///
/// `sysinfo::Disk::name()` is platform-dependent: on Linux it returns
/// the device source (`/dev/sda1`), on macOS it returns the volume
/// label (`Macintosh HD`). The macOS path resolves the device path via
/// the `mount` command's mount-point → device mapping; the Linux path
/// keeps the existing behavior.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn sysinfo_mount_used() -> Vec<(String, u64)> {
    let disks = Disks::new_with_refreshed_list();
    let mut by_disk: HashMap<String, u64> = HashMap::new();
    for disk in disks.list() {
        let name = short_name(&disk.name().to_string_lossy());
        let used = disk.total_space().saturating_sub(disk.available_space());
        let entry = by_disk.entry(name).or_default();
        *entry = (*entry).max(used);
    }
    by_disk.into_iter().collect()
}

#[cfg(target_os = "macos")]
fn macos_used_by_device(volumes: &super::VolumeTick) -> HashMap<String, u64> {
    let rows = super::storage::resolve(&super::filesystems::collect(), volumes);
    usage_by_disk(&rows)
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn usage_by_disk(rows: &[super::storage::VolumeRow]) -> HashMap<String, u64> {
    let mut used = HashMap::<String, u64>::new();
    for row in rows {
        // Image capacity is already represented by its host filesystem's usage.
        if row
            .counter_sources
            .iter()
            .any(|source| !row.member_disks.contains(source))
        {
            continue;
        }
        // Shared APFS capacity is counted once per container. Multi-store
        // containers do not expose per-store allocation, so leave it unknown.
        if let [disk] = row.member_disks.as_slice() {
            let entry = used.entry(disk.clone()).or_default();
            *entry = entry.saturating_add(row.size_bytes.saturating_sub(row.free_bytes));
        }
    }
    used
}

/// Fold a device path or partition name to its whole-disk name:
/// `/dev/sda1` → `sda`, `nvme0n1p2` → `nvme0n1`, `mmcblk0p2` → `mmcblk0`,
/// `disk3s1` → `disk3` (macOS). Names with no partition suffix pass
/// through unchanged (`md0`, `mmcblk0boot0`, `overlay`).
pub(super) fn short_name(raw: &str) -> String {
    let s = super::topology::device_name(raw);
    // macOS: diskNsM → diskN
    if let Some(rest) = s.strip_prefix("disk") {
        let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !n.is_empty() {
            return format!("disk{}", n);
        }
    }
    // "<base>p<digits>" where base ends in a digit → base
    // (nvme0n1p2 → nvme0n1, mmcblk0p2 → mmcblk0, md0p1 → md0)
    if let Some(idx) = s.rfind('p') {
        let (base, part) = (&s[..idx], &s[idx + 1..]);
        if base.ends_with(|c: char| c.is_ascii_digit())
            && !part.is_empty()
            && part.chars().all(|c| c.is_ascii_digit())
        {
            return base.to_string();
        }
    }
    // Trailing partition digits on letter-named disks (sda1 → sda,
    // vdb2 → vdb, xvda1 → xvda). Digits are part of the name elsewhere
    // (md0, loop3), so only these prefixes are folded.
    if ["sd", "hd", "vd", "xvd"].iter().any(|p| s.starts_with(p)) {
        return s.chars().take_while(|c| !c.is_ascii_digit()).collect();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_folds_partitions() {
        assert_eq!(short_name("/dev/sda1"), "sda");
        assert_eq!(short_name("/dev/sda"), "sda");
        assert_eq!(short_name("/dev/nvme0n1p2"), "nvme0n1");
        assert_eq!(short_name("/dev/nvme0n1"), "nvme0n1");
        assert_eq!(short_name("/dev/mmcblk0p2"), "mmcblk0");
        assert_eq!(short_name("/dev/mmcblk0"), "mmcblk0");
        assert_eq!(short_name("/dev/mmcblk0boot0"), "mmcblk0boot0");
        assert_eq!(short_name("/dev/md0"), "md0");
        assert_eq!(short_name("/dev/md0p1"), "md0");
        assert_eq!(short_name("/dev/vdb2"), "vdb");
        assert_eq!(short_name("/dev/xvda1"), "xvda");
        for name in [
            "/dev/disk3",
            "/dev/rdisk3",
            "/dev/disk3s3",
            "/dev/rdisk3s3",
            "rdisk3s1s1",
        ] {
            assert_eq!(short_name(name), "disk3");
        }
        assert_eq!(short_name("/dev/disk3s1"), "disk3");
        assert_eq!(short_name("overlay"), "overlay");
    }

    fn no_slaves(_: &str) -> Option<Vec<String>> {
        None
    }

    fn sources(list: &[(&str, u64)]) -> HashMap<String, u64> {
        list.iter().map(|(s, u)| (s.to_string(), *u)).collect()
    }

    #[test]
    fn plain_partition_attributes_to_parent_disk() {
        let by_source = sources(&[("/dev/mmcblk0p2", 27_000), ("/dev/mmcblk0p1", 300)]);
        let out = attribute_sources(&by_source, &no_slaves);
        assert_eq!(out.get("mmcblk0"), Some(&27_300));
    }

    #[test]
    fn bcachefs_multi_device_splits_across_members() {
        // Issue #4: 8× 480 GB bcachefs. v0.1.1 credited the whole fs to
        // every attached device; the fs usage must be split across its
        // members and land nowhere else.
        let members = (b'a'..=b'h')
            .map(|c| format!("/dev/sd{}", c as char))
            .collect::<Vec<_>>()
            .join(":");
        let by_source = sources(&[(members.as_str(), 640_000_000)]);
        let out = attribute_sources(&by_source, &no_slaves);
        assert_eq!(out.get("sda"), Some(&80_000_000));
        assert_eq!(out.get("sdh"), Some(&80_000_000));
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn md_array_splits_across_slaves() {
        // Issue #4 (second report): RAID0 across USB disks. The array's
        // usage splits across its members via the slaves map.
        let slaves = |dev: &str| -> Option<Vec<String>> {
            (dev == "/dev/md0")
                .then(|| vec!["sdd".into(), "sdb".into(), "sde".into(), "sdc".into()])
        };
        let by_source = sources(&[("/dev/md0", 4_000_000), ("/dev/nvme0n1p1", 5_000)]);
        let out = attribute_sources(&by_source, &slaves);
        assert_eq!(out.get("sdd"), Some(&1_000_000));
        assert_eq!(out.get("sdc"), Some(&1_000_000));
        assert_eq!(out.get("nvme0n1"), Some(&5_000));
        assert_eq!(out.get("md0"), None);
    }

    #[test]
    fn btrfs_usage_splits_across_member_whole_disks() {
        let btrfs_members = |dev: &str| -> Option<Vec<String>> {
            (dev == "/dev/sdc").then(|| vec!["sdc".into(), "sdd".into(), "sde2".into()])
        };
        let by_source = sources(&[("/dev/sdc", 3_000)]);
        let out = attribute_sources(&by_source, &btrfs_members);

        assert_eq!(out.get("sdc"), Some(&1_000));
        assert_eq!(out.get("sdd"), Some(&1_000));
        assert_eq!(out.get("sde"), Some(&1_000));
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn zfs_allocations_sum_leaf_usage_and_skip_cache_and_spares() {
        use super::super::volumes::{ZfsPool, ZfsVdev, ZfsVdevSection};

        let pool = ZfsPool {
            name: "tank".into(),
            vdevs: vec![
                ZfsVdev {
                    name: "sdc1".into(),
                    alloc_bytes: Some(100),
                    ..Default::default()
                },
                ZfsVdev {
                    name: "sdc2".into(),
                    alloc_bytes: Some(200),
                    ..Default::default()
                },
                ZfsVdev {
                    name: "log0".into(),
                    alloc_bytes: Some(10),
                    section: ZfsVdevSection::Log,
                    ..Default::default()
                },
                ZfsVdev {
                    name: "special0".into(),
                    alloc_bytes: Some(20),
                    section: ZfsVdevSection::Special,
                    ..Default::default()
                },
                ZfsVdev {
                    name: "dedup0".into(),
                    alloc_bytes: Some(30),
                    section: ZfsVdevSection::Dedup,
                    ..Default::default()
                },
                ZfsVdev {
                    name: "cache0".into(),
                    alloc_bytes: Some(300),
                    section: ZfsVdevSection::Cache,
                    ..Default::default()
                },
                ZfsVdev {
                    name: "spare0".into(),
                    alloc_bytes: Some(400),
                    section: ZfsVdevSection::Spare,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let out = zfs_allocations_by_device(&[pool]);
        assert_eq!(out.get("sdc"), Some(&300));
        assert_eq!(out.get("log0"), Some(&10));
        assert_eq!(out.get("special0"), Some(&20));
        assert_eq!(out.get("dedup0"), Some(&30));
        assert_eq!(out.get("cache0"), None);
        assert_eq!(out.get("spare0"), None);
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn zfs_group_allocations_are_assigned_to_leaves_and_stacked_disks() {
        use super::super::volumes::{ZfsPool, ZfsVdev};

        let pool = ZfsPool {
            name: "tank".into(),
            vdevs: vec![
                ZfsVdev {
                    name: "mirror-0".into(),
                    vdev_type: "mirror".into(),
                    alloc_bytes: Some(120),
                    children: vec![
                        ZfsVdev {
                            name: "dm-0".into(),
                            ..Default::default()
                        },
                        ZfsVdev {
                            name: "sdd1".into(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                ZfsVdev {
                    name: "raidz1-0".into(),
                    vdev_type: "raidz".into(),
                    alloc_bytes: Some(302),
                    children: vec![
                        ZfsVdev {
                            name: "sde1".into(),
                            ..Default::default()
                        },
                        ZfsVdev {
                            name: "sdf1".into(),
                            ..Default::default()
                        },
                        ZfsVdev {
                            name: "sdg1".into(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let members = |path: &str| (path == "/dev/dm-0").then(|| vec!["sdc".into(), "sdb".into()]);
        let out = zfs_allocations_by_device_with_members(&[pool], &members);

        // A mirror group's 120 bytes apply to each leaf; the dm leaf's bytes
        // are split across its underlying physical members.
        assert_eq!(out.get("sdb"), Some(&60));
        assert_eq!(out.get("sdc"), Some(&60));
        assert_eq!(out.get("sdd"), Some(&120));
        // RAIDZ's raw 302 bytes are distributed evenly, including remainder.
        assert_eq!(out.get("sde"), Some(&101));
        assert_eq!(out.get("sdf"), Some(&101));
        assert_eq!(out.get("sdg"), Some(&100));
    }

    #[test]
    fn virtual_sources_attribute_to_nothing() {
        let by_source = sources(&[
            ("overlay", 640_000_000),
            ("tmpfs", 1_000),
            ("pool/dataset", 9_000),
        ]);
        let out = attribute_sources(&by_source, &no_slaves);
        assert!(out.is_empty());
    }

    #[test]
    fn same_disk_partitions_sum() {
        let by_source = sources(&[("/dev/sda1", 100), ("/dev/sda2", 250)]);
        let out = attribute_sources(&by_source, &no_slaves);
        assert_eq!(out.get("sda"), Some(&350));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn classify_by_name(name: &str) -> DeviceKind {
    if name.starts_with("nvme") {
        DeviceKind::Nvme
    } else if name.starts_with("sd") {
        DeviceKind::Ssd
    } else {
        DeviceKind::Unknown
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn bus_hint(k: &DeviceKind) -> String {
    match k {
        DeviceKind::Nvme => "PCIe".to_string(),
        DeviceKind::Ssd => "SATA / Internal".to_string(),
        DeviceKind::Hdd => "SATA".to_string(),
        DeviceKind::UsbMassStorage => "USB".to_string(),
        DeviceKind::Unknown => "—".to_string(),
    }
}
