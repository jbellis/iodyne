//! Volumes view model: one row per free-space domain.
//!
//! A row is the thing that runs out of space as a unit: a plain filesystem
//! (on a partition, md array, dm/LUKS device, or LVM logical volume), a
//! multi-device btrfs filesystem, a ZFS pool, an APFS container, or a swap
//! area. Bind mounts, btrfs subvolumes, ZFS datasets, and APFS volumes are
//! listed inside their row rather than as rows of their own, so no device IO
//! is counted in two rows.
//!
//! `collect::volumes` holds the raw APFS/mdraid/ZFS metadata; this module
//! combines it with mounts, sysfs, and swap into display-ready rows.

use std::collections::{HashMap, VecDeque};

use super::io::{DeviceHistory, IoTick, TracedLatencySample};
use super::{FsTick, VolumeTick};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    /// One filesystem on one block device (partition, whole disk, md, dm, LV).
    Filesystem,
    /// A btrfs filesystem spanning more than one device.
    Btrfs,
    ZfsPool,
    ApfsContainer,
    Swap,
}

#[derive(Debug, Clone)]
pub struct VolumeRow {
    /// Stable identity across refreshes, for example `zfs:optane`,
    /// `btrfs:<uuid>`, `fs:8:33`, `swap:sde1`, `apfs:disk3`. Also the key
    /// for `VolumeIo` maps and `IoTick::device` in `VolumeIo::latest`.
    pub id: String,
    /// Short display name: primary mount path, pool name, or `swap sde1`.
    pub label: String,
    pub kind: VolumeKind,
    /// Filesystem type (`ext4`, `btrfs`, `zfs`, `apfs`, `swap`).
    pub fs_type: String,
    /// Every mount path served by this row (datasets, subvolumes, binds),
    /// primary first. Empty for swap.
    pub mounts: Vec<String>,
    pub size_bytes: u64,
    /// Space the row's filesystems can still use. For thin LVM volumes this
    /// is the smaller of filesystem free space and thin-pool free space.
    pub free_bytes: u64,
    /// Human-readable backing chain for the detail header, outermost first,
    /// for example `zfs optane {sdc1,sdd1,sde2}` or `vg0/root → dm-3 → sda2`.
    pub backing: String,
    /// Whole-disk names (matching `IoTick::device` in the Devices view) that
    /// hold this row's data. Used for Volumes ↔ Devices selection mapping.
    pub member_disks: Vec<String>,
    /// Block-device names whose `/proc/diskstats` counters are summed for
    /// this row's workload: the row's own device when it has counters
    /// (partition, md, dm), otherwise its leaf partitions or disks.
    pub counter_sources: Vec<String>,
    /// Whole-disk names whose eBPF request histograms are summed for this
    /// row. Empty when any member disk is shared with another row, in which
    /// case the UI falls back to counter-derived await.
    pub latency_sources: Vec<String>,
    /// Why `latency_sources` is empty when histograms exist for the members,
    /// for example `sde shared with swap sde1`.
    pub latency_note: Option<String>,
    /// Filesystem `(major, minor)` IDs of the row's mounts, for VFS filtering.
    pub fs_device_ids: Vec<(u32, u32)>,
    /// Health text when the row is not healthy (`DEGRADED`, thin pool fill).
    pub warnings: Vec<String>,
}

/// Per-volume IO series, maintained by `IoCollector` after each sample.
#[derive(Debug, Default, Clone)]
pub struct VolumeIo {
    /// Latest derived rates, one per row; `IoTick::device` is `VolumeRow::id`.
    pub latest: Vec<IoTick>,
    pub history: HashMap<String, DeviceHistory>,
    /// Present only for rows with non-empty `latency_sources`.
    pub traced_history: HashMap<String, VecDeque<TracedLatencySample>>,
    /// Latest derived rates per counter source, keyed by row id; each
    /// `IoTick::device` is the source name (for example `sde2`).
    pub members: HashMap<String, Vec<IoTick>>,
}

/// Build Volumes rows from the mount list and volume metadata. Cheap enough
/// to call at the filesystem-usage cadence; reads sysfs and `/proc/swaps`
/// but runs no subprocess.
pub fn resolve(filesystems: &[FsTick], volumes: &VolumeTick) -> Vec<VolumeRow> {
    let _ = (filesystems, volumes);
    Vec::new()
}

/// The row whose `member_disks` contains `device`. When several rows share
/// a disk, the one with the largest size wins.
pub fn volume_for_device<'a>(rows: &'a [VolumeRow], device: &str) -> Option<&'a VolumeRow> {
    rows.iter()
        .filter(|row| row.member_disks.iter().any(|disk| disk == device))
        .max_by_key(|row| row.size_bytes)
}
