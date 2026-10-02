//! Volumes view model: one row per free-space domain.
//!
//! Resolution reads only mounts, sysfs, and procfs. Slow command output such
//! as `zpool` and `lvs` is supplied by [`VolumeTick`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use super::io::{DeviceHistory, IoTick, TracedLatencySample};
use super::{FsTick, VolumeTick};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    Filesystem,
    Btrfs,
    ZfsPool,
    ApfsContainer,
    Swap,
}

#[derive(Debug, Clone)]
pub struct VolumeRow {
    pub id: String,
    pub label: String,
    pub kind: VolumeKind,
    #[allow(dead_code)] // Shown as the filesystem type in the Volumes detail pane.
    pub fs_type: String,
    pub mounts: Vec<String>,
    pub size_bytes: u64,
    pub free_bytes: u64,
    pub backing: String,
    pub member_disks: Vec<String>,
    pub counter_sources: Vec<String>,
    pub latency_sources: Vec<String>,
    pub latency_note: Option<String>,
    /// Filesystem `(major, minor)` IDs used by the VFS detail filter.
    #[allow(dead_code)] // Consumed by the Volumes detail pane in the UI worktree.
    pub fs_device_ids: Vec<(u32, u32)>,
    pub warnings: Vec<String>,
}

/// Per-volume IO series, maintained by `IoCollector` after each sample.
#[derive(Debug, Default, Clone)]
pub struct VolumeIo {
    pub latest: Vec<IoTick>,
    pub history: HashMap<String, DeviceHistory>,
    pub traced_history: HashMap<String, VecDeque<TracedLatencySample>>,
    pub members: HashMap<String, Vec<IoTick>>,
}

#[derive(Debug, Default, Clone)]
pub struct StorageResolution {
    pub rows: Vec<VolumeRow>,
    /// File-backed swap is represented by its filesystem row and omitted here.
    pub notes: Vec<String>,
}

/// Resolve rows using live sysfs/procfs evidence and the cached slow metadata.
#[allow(dead_code)] // Public collection API used by the Volumes UI worktree.
pub fn resolve(filesystems: &[FsTick], volumes: &VolumeTick) -> Vec<VolumeRow> {
    resolve_detailed(filesystems, volumes).rows
}

/// Resolve rows and notes useful to the diagnostic output.
pub fn resolve_detailed(filesystems: &[FsTick], volumes: &VolumeTick) -> StorageResolution {
    let inputs = StorageInputs::live(filesystems, volumes);
    resolve_with_inputs(filesystems, volumes, &inputs)
}

/// The row whose `member_disks` contains `device`. When several rows share a
/// disk, the one with the largest size wins.
#[allow(dead_code)] // Public selection mapping used by the Volumes UI worktree.
/// Label a pool row by its root dataset's mount path, falling back to the
/// shortest mounted dataset path, then the pool name.
fn zfs_label(pool: &str, filesystems: &[FsTick], indices: &[usize]) -> String {
    let mounted = || indices.iter().map(|index| &filesystems[*index]);
    mounted()
        .find(|fs| fs.device == pool)
        .or_else(|| mounted().min_by_key(|fs| fs.mount.len()))
        .map(|fs| fs.mount.clone())
        .unwrap_or_else(|| pool.to_string())
}

pub fn volume_for_device<'a>(rows: &'a [VolumeRow], device: &str) -> Option<&'a VolumeRow> {
    rows.iter()
        .filter(|row| row.member_disks.iter().any(|disk| disk == device))
        .max_by_key(|row| row.size_bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Linux,
    MacOs,
    Other,
}

#[derive(Debug, Clone, Default)]
struct BlockInfo {
    parent: Option<String>,
    slaves: Vec<String>,
    dm_uuid: Option<String>,
    dm_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SwapEntry {
    path: String,
    kind: String,
    size_kib: u64,
    used_kib: u64,
}

#[derive(Debug, Default)]
struct StorageInputs {
    platform: Option<Platform>,
    blocks: HashMap<String, BlockInfo>,
    aliases: HashMap<String, String>,
    diskstats: HashSet<String>,
    btrfs: HashMap<String, (String, Vec<String>)>,
    swaps: Vec<SwapEntry>,
    fs_device_ids: HashMap<String, Option<(u32, u32)>>,
}

impl StorageInputs {
    fn live(filesystems: &[FsTick], volumes: &VolumeTick) -> Self {
        let _ = volumes;
        let mut inputs = Self {
            platform: Some(current_platform()),
            ..Self::default()
        };

        for fs in filesystems {
            inputs
                .fs_device_ids
                .insert(fs.mount.clone(), filesystem_device_id(&fs.mount));
        }

        #[cfg(target_os = "linux")]
        {
            inputs.read_linux_blocks();
            inputs.diskstats = read_diskstats_names();
            inputs.swaps = read_swaps();
            for fs in filesystems
                .iter()
                .filter(|fs| fs.fs_type.eq_ignore_ascii_case("btrfs"))
            {
                let source = linux_block_name(&fs.device, &inputs.aliases);
                if let Some((uuid, members)) = super::btrfs::filesystem(&source) {
                    inputs.btrfs.insert(source, (uuid, members));
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let _ = volumes;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = volumes;
        }
        inputs
    }

    #[cfg(target_os = "linux")]
    fn read_linux_blocks(&mut self) {
        let Ok(entries) = std::fs::read_dir("/sys/class/block") else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let canonical = std::fs::canonicalize(entry.path()).unwrap_or_else(|_| entry.path());
            let parent = if canonical.join("partition").is_file() {
                canonical
                    .parent()
                    .and_then(|path| path.file_name())
                    .map(|name| name.to_string_lossy().into_owned())
            } else {
                None
            };
            let slaves_path = format!("/sys/block/{name}/slaves");
            let slaves = std::fs::read_dir(slaves_path)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            let dm_root = format!("/sys/block/{name}/dm");
            let dm_uuid = std::fs::read_to_string(format!("{dm_root}/uuid"))
                .ok()
                .map(|value| value.trim().to_string());
            let dm_name = std::fs::read_to_string(format!("{dm_root}/name"))
                .ok()
                .map(|value| value.trim().to_string());
            self.blocks.insert(
                name,
                BlockInfo {
                    parent,
                    slaves,
                    dm_uuid,
                    dm_name,
                },
            );
        }
        if let Ok(entries) = std::fs::read_dir("/dev/mapper") {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::canonicalize(entry.path()) {
                    if let Some(kernel_name) = target.file_name() {
                        self.aliases.insert(
                            entry.file_name().to_string_lossy().into_owned(),
                            kernel_name.to_string_lossy().into_owned(),
                        );
                    }
                }
            }
        }
    }
}

fn resolve_with_inputs(
    filesystems: &[FsTick],
    volumes: &VolumeTick,
    inputs: &StorageInputs,
) -> StorageResolution {
    let platform = inputs.platform.unwrap_or_else(current_platform);
    let mut rows = Vec::new();
    let mut notes = Vec::new();
    let mut consumed = HashSet::<usize>::new();

    if platform == Platform::MacOs {
        for container in &volumes.containers {
            let mut mounts = Vec::new();
            let mut fs_ids = Vec::new();
            let volume_names: HashSet<_> = container
                .volumes
                .iter()
                .map(|volume| volume.bsd.as_str())
                .collect();
            for (index, fs) in filesystems.iter().enumerate() {
                let source = device_name(&fs.device);
                let is_container_volume = volume_names.contains(source)
                    || container
                        .volumes
                        .iter()
                        .any(|volume| volume.mount_point.as_deref() == Some(fs.mount.as_str()));
                if is_container_volume {
                    consumed.insert(index);
                    mounts.push(fs.mount.clone());
                    push_unique(
                        &mut fs_ids,
                        inputs.fs_device_ids.get(&fs.mount).copied().flatten(),
                    );
                }
            }
            let physical = container
                .physical_store
                .as_deref()
                .map(device_name)
                .map(mac_media_name);
            let member_disks = physical.iter().cloned().collect::<Vec<_>>();
            let mut row = VolumeRow {
                id: format!("apfs:{}", container.bsd),
                label: mounts
                    .first()
                    .cloned()
                    .unwrap_or_else(|| container.bsd.clone()),
                kind: VolumeKind::ApfsContainer,
                fs_type: "apfs".into(),
                mounts,
                size_bytes: container.size_bytes,
                free_bytes: container.size_bytes.saturating_sub(container.used_bytes),
                backing: format!("apfs {}", physical.as_deref().unwrap_or("unknown")),
                member_disks,
                counter_sources: physical.into_iter().collect(),
                latency_sources: Vec::new(),
                latency_note: None,
                fs_device_ids: fs_ids,
                warnings: Vec::new(),
            };
            row.mounts = unique_mounts(row.mounts);
            rows.push(row);
        }
    }

    if platform == Platform::Linux {
        let mut zfs_mounts: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, fs) in filesystems.iter().enumerate() {
            if fs.fs_type.eq_ignore_ascii_case("zfs") {
                if let Some(pool) = super::volumes::pool_for_dataset(&fs.device, &volumes.zfs) {
                    zfs_mounts.entry(pool.name.clone()).or_default().push(index);
                    consumed.insert(index);
                }
            }
        }
        for pool in &volumes.zfs {
            let indices = zfs_mounts.remove(&pool.name).unwrap_or_default();
            let mounts = unique_mounts(
                indices
                    .iter()
                    .map(|index| filesystems[*index].mount.clone())
                    .collect(),
            );
            let mut fs_device_ids = Vec::new();
            for index in &indices {
                push_unique(
                    &mut fs_device_ids,
                    inputs
                        .fs_device_ids
                        .get(&filesystems[*index].mount)
                        .copied()
                        .flatten(),
                );
            }
            let leaf_names: Vec<String> = pool
                .leaf_vdevs()
                .into_iter()
                .filter(|(leaf, _)| {
                    !matches!(
                        leaf.section,
                        super::volumes::ZfsVdevSection::Cache
                            | super::volumes::ZfsVdevSection::Spare
                    )
                })
                .map(|(leaf, _)| device_name(&leaf.name).to_string())
                .collect();
            let counter_sources = expand_counter_sources(&leaf_names, inputs);
            let member_disks = member_disks_for(&leaf_names, inputs);
            let backing_members = sorted_braced(&leaf_names);
            rows.push(VolumeRow {
                id: format!("zfs:{}", pool.name),
                label: zfs_label(&pool.name, filesystems, &indices),
                kind: VolumeKind::ZfsPool,
                fs_type: "zfs".into(),
                mounts,
                size_bytes: pool.size_bytes,
                free_bytes: pool.free_bytes,
                backing: format!("zfs {} {}", pool.name, backing_members),
                member_disks,
                counter_sources,
                latency_sources: Vec::new(),
                latency_note: None,
                fs_device_ids,
                warnings: if pool.health.eq_ignore_ascii_case("ONLINE") {
                    Vec::new()
                } else {
                    vec![format!("pool health {}", pool.health)]
                },
            });
        }

        // Keep mounted datasets visible when pool inspection is unavailable,
        // such as inside a restricted container without /dev/zfs.
        let mut fallback_mounts: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, fs) in filesystems.iter().enumerate() {
            if consumed.contains(&index) || !fs.fs_type.eq_ignore_ascii_case("zfs") {
                continue;
            }
            let Some(pool) = fs.device.split('/').next().filter(|name| !name.is_empty()) else {
                continue;
            };
            fallback_mounts
                .entry(pool.to_string())
                .or_default()
                .push(index);
            consumed.insert(index);
        }
        for (pool, indices) in fallback_mounts {
            let (size_bytes, free_bytes) = fs_capacity(filesystems, &indices);
            let mounts = unique_mounts(
                indices
                    .iter()
                    .map(|index| filesystems[*index].mount.clone())
                    .collect(),
            );
            let mut fs_device_ids = Vec::new();
            for index in &indices {
                push_unique(
                    &mut fs_device_ids,
                    inputs
                        .fs_device_ids
                        .get(&filesystems[*index].mount)
                        .copied()
                        .flatten(),
                );
            }
            rows.push(VolumeRow {
                id: format!("zfs:{pool}"),
                label: zfs_label(&pool, filesystems, &indices),
                kind: VolumeKind::ZfsPool,
                fs_type: "zfs".into(),
                mounts,
                size_bytes,
                free_bytes,
                backing: format!("zfs {pool}"),
                member_disks: Vec::new(),
                counter_sources: Vec::new(),
                latency_sources: Vec::new(),
                latency_note: Some("pool metadata unavailable".into()),
                fs_device_ids,
                warnings: vec!["pool metadata unavailable".into()],
            });
        }
    }

    if platform == Platform::Linux {
        let mut btrfs_groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, fs) in filesystems.iter().enumerate() {
            if !fs.fs_type.eq_ignore_ascii_case("btrfs") {
                continue;
            }
            let source = linux_block_name(&fs.device, &inputs.aliases);
            if let Some((uuid, members)) = inputs.btrfs.get(&source) {
                if members.len() > 1 {
                    btrfs_groups.entry(uuid.clone()).or_default().push(index);
                    consumed.insert(index);
                }
            }
        }
        for (uuid, indices) in btrfs_groups {
            let members = indices
                .iter()
                .filter_map(|index| {
                    let source = linux_block_name(&filesystems[*index].device, &inputs.aliases);
                    inputs
                        .btrfs
                        .get(&source)
                        .map(|(_, members)| members.clone())
                })
                .flatten()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mounts = unique_mounts(
                indices
                    .iter()
                    .map(|index| filesystems[*index].mount.clone())
                    .collect(),
            );
            let mut fs_device_ids = Vec::new();
            for index in &indices {
                push_unique(
                    &mut fs_device_ids,
                    inputs
                        .fs_device_ids
                        .get(&filesystems[*index].mount)
                        .copied()
                        .flatten(),
                );
            }
            let (size_bytes, free_bytes) = fs_capacity(filesystems, &indices);
            rows.push(VolumeRow {
                id: format!("btrfs:{uuid}"),
                label: indices
                    .first()
                    .map(|index| filesystems[*index].mount.clone())
                    .unwrap_or_else(|| format!("btrfs:{uuid}")),
                kind: VolumeKind::Btrfs,
                fs_type: "btrfs".into(),
                mounts,
                size_bytes,
                free_bytes,
                backing: format!("btrfs {}", sorted_braced(&members)),
                member_disks: member_disks_for(&members, inputs),
                counter_sources: expand_counter_sources(&members, inputs),
                latency_sources: Vec::new(),
                latency_note: None,
                fs_device_ids,
                warnings: Vec::new(),
            });
        }
    }

    let mut ordinary: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, fs) in filesystems.iter().enumerate() {
        if consumed.contains(&index) || is_pseudo_filesystem(fs) {
            continue;
        }
        let source = match platform {
            Platform::Linux => linux_block_name(&fs.device, &inputs.aliases),
            Platform::MacOs => device_name(&fs.device).to_string(),
            Platform::Other => device_name(&fs.device).to_string(),
        };
        if !is_block_source(&source, platform, inputs) {
            continue;
        }
        let fs_id = inputs.fs_device_ids.get(&fs.mount).copied().flatten();
        let key = fs_id
            .map(|(major, minor)| format!("dev:{major}:{minor}"))
            .unwrap_or_else(|| format!("src:{source}"));
        ordinary.entry(key).or_default().push(index);
    }

    for (key, indices) in ordinary {
        let first = &filesystems[indices[0]];
        let source = match platform {
            Platform::Linux => linux_block_name(&first.device, &inputs.aliases),
            _ => device_name(&first.device).to_string(),
        };
        let (size_bytes, mut free_bytes) = fs_capacity(filesystems, &indices);
        let info = inputs.blocks.get(&source);
        if let Some(info) = info {
            if info
                .dm_uuid
                .as_deref()
                .is_some_and(|uuid| uuid.starts_with("LVM-"))
                && is_internal_lvm_device(info)
            {
                continue;
            }
        }
        let lvm_identity = info.and_then(lvm_identity_from_block);
        let lvm = info.and_then(|info| lvm_for_block(info, &volumes.lvm));
        let mut warnings = Vec::new();
        if let Some(lvm) = lvm.filter(|lv| lv.pool_lv.is_some()) {
            if let Some(pool) = lvm_thin_pool(lvm, &volumes.lvm) {
                let pool_free = pool
                    .data_percent
                    .map(|used| {
                        ((pool.size_bytes as f64) * (1.0 - used.clamp(0.0, 100.0) / 100.0)) as u64
                    })
                    .unwrap_or(pool.size_bytes);
                free_bytes = free_bytes.min(pool_free);
                if pool.data_percent.is_some_and(|used| used >= 80.0) {
                    warnings.push(format!(
                        "thin pool data {:.0}%",
                        pool.data_percent.unwrap_or(0.0)
                    ));
                }
                if pool.metadata_percent.is_some_and(|used| used >= 80.0) {
                    warnings.push(format!(
                        "thin pool metadata {:.0}%",
                        pool.metadata_percent.unwrap_or(0.0)
                    ));
                }
            }
        }
        let md = volumes
            .mdraid
            .iter()
            .find(|array| device_name(&array.name) == source);
        let member_names = if let Some(array) = md {
            array
                .members
                .iter()
                .map(|member| device_name(&member.device).to_string())
                .collect::<Vec<_>>()
        } else {
            vec![source.clone()]
        };
        let member_disks = member_disks_for(&member_names, inputs);
        let counter_sources = if platform == Platform::MacOs {
            vec![mac_media_name(&source)]
        } else {
            expand_counter_sources(std::slice::from_ref(&source), inputs)
        };
        let mut backing = if let Some((vg, lv)) = &lvm_identity {
            format!(
                "{}/{} → {} → {}",
                vg,
                lv,
                source,
                format_device_set(&block_leaves(&source, inputs))
            )
        } else if let Some(array) = md {
            format!(
                "{} {} {}",
                array.name,
                array.level,
                sorted_braced(&member_names)
            )
        } else if info.is_some_and(|info| {
            info.dm_uuid
                .as_deref()
                .is_some_and(|uuid| uuid.starts_with("CRYPT-LUKS"))
        }) {
            format!(
                "LUKS {} → {}",
                source,
                format_device_set(&block_leaves(&source, inputs))
            )
        } else if info.is_some_and(|info| info.parent.is_some()) {
            source.clone()
        } else if info.is_some_and(|info| !info.slaves.is_empty()) {
            format!(
                "{} → {}",
                source,
                format_device_set(&block_leaves(&source, inputs))
            )
        } else {
            source.clone()
        };
        if platform == Platform::MacOs {
            backing = source.clone();
        }
        let mut fs_ids = Vec::new();
        let mut mounts = Vec::new();
        for index in &indices {
            let fs = &filesystems[*index];
            mounts.push(fs.mount.clone());
            push_unique(
                &mut fs_ids,
                inputs.fs_device_ids.get(&fs.mount).copied().flatten(),
            );
        }
        mounts = unique_mounts(mounts);
        let id = key
            .strip_prefix("dev:")
            .map(|id| format!("fs:{id}"))
            .unwrap_or_else(|| format!("fs:{}", source));
        rows.push(VolumeRow {
            id,
            label: mounts
                .first()
                .cloned()
                .unwrap_or_else(|| first.mount.clone()),
            kind: VolumeKind::Filesystem,
            fs_type: first.fs_type.clone(),
            mounts,
            size_bytes,
            free_bytes,
            backing,
            member_disks,
            counter_sources,
            latency_sources: Vec::new(),
            latency_note: None,
            fs_device_ids: fs_ids,
            warnings: {
                if let Some(array) = md {
                    if array.state != "active"
                        || array.members_present < array.members_total
                        || array.member_state.contains('_')
                    {
                        warnings.push(format!("md health {} {}", array.state, array.member_state));
                    }
                }
                warnings
            },
        });
    }

    if platform == Platform::Linux {
        for swap in &inputs.swaps {
            if swap.kind.eq_ignore_ascii_case("file") || !swap.path.starts_with('/') {
                notes.push(format!(
                    "file swap {} skipped; its IO belongs to the backing filesystem",
                    swap.path
                ));
                continue;
            }
            let source = linux_block_name(&swap.path, &inputs.aliases);
            if !is_block_source(&source, platform, inputs) {
                notes.push(format!(
                    "swap {} skipped; block device could not be resolved",
                    swap.path
                ));
                continue;
            }
            let member_disks = member_disks_for(std::slice::from_ref(&source), inputs);
            rows.push(VolumeRow {
                id: format!("swap:{source}"),
                label: format!("swap {source}"),
                kind: VolumeKind::Swap,
                fs_type: "swap".into(),
                mounts: Vec::new(),
                size_bytes: swap.size_kib.saturating_mul(1024),
                free_bytes: swap
                    .size_kib
                    .saturating_sub(swap.used_kib)
                    .saturating_mul(1024),
                backing: source.clone(),
                member_disks,
                counter_sources: vec![source],
                latency_sources: Vec::new(),
                latency_note: None,
                fs_device_ids: Vec::new(),
                warnings: Vec::new(),
            });
        }
    }

    assign_latency_sources(&mut rows);
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    StorageResolution { rows, notes }
}

fn assign_latency_sources(rows: &mut [VolumeRow]) {
    for index in 0..rows.len() {
        let shared = rows[index].member_disks.iter().find_map(|disk| {
            rows.iter().enumerate().find_map(|(other_index, other)| {
                (other_index != index && other.member_disks.contains(disk))
                    .then(|| (disk.clone(), other.label.clone()))
            })
        });
        if let Some((disk, other)) = shared {
            rows[index].latency_sources.clear();
            rows[index].latency_note = Some(format!("{disk} shared with {other}"));
        } else if rows[index].member_disks.is_empty() {
            rows[index].latency_sources.clear();
            if rows[index].latency_note.is_none() {
                rows[index].latency_note = Some("no whole-disk backing resolved".into());
            }
        } else {
            rows[index].latency_sources = rows[index].member_disks.clone();
            rows[index].latency_note = None;
        }
    }
}

fn unique_mounts(mounts: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    mounts
        .into_iter()
        .filter(|mount| seen.insert(mount.clone()))
        .collect()
}

fn fs_capacity(filesystems: &[FsTick], indices: &[usize]) -> (u64, u64) {
    indices
        .iter()
        .map(|index| {
            (
                filesystems[*index].size_bytes,
                filesystems[*index].avail_bytes,
            )
        })
        .max_by_key(|(size, free)| (*size, *free))
        .unwrap_or_default()
}

fn is_pseudo_filesystem(fs: &FsTick) -> bool {
    let fs_type = fs.fs_type.to_ascii_lowercase();
    let source = fs.device.to_ascii_lowercase();
    matches!(
        fs_type.as_str(),
        "tmpfs"
            | "devtmpfs"
            | "proc"
            | "procfs"
            | "sysfs"
            | "cgroup"
            | "cgroup2"
            | "debugfs"
            | "tracefs"
            | "securityfs"
            | "pstore"
            | "configfs"
            | "fusectl"
            | "mqueue"
            | "hugetlbfs"
            | "rpc_pipefs"
            | "autofs"
            | "overlay"
            | "9p"
    ) || matches!(source.as_str(), "overlay" | "none" | "-" | "udev")
        || source.starts_with("overlay:")
        || source.starts_with("//")
}

fn is_block_source(name: &str, platform: Platform, inputs: &StorageInputs) -> bool {
    match platform {
        Platform::Linux => inputs.blocks.contains_key(name),
        Platform::MacOs => name.starts_with("disk"),
        Platform::Other => false,
    }
}

fn linux_block_name(source: &str, aliases: &HashMap<String, String>) -> String {
    let source = device_name(source);
    if let Some(mapper) = source.strip_prefix("mapper/") {
        return aliases
            .get(mapper)
            .cloned()
            .unwrap_or_else(|| mapper.to_string());
    }
    source.to_string()
}

fn device_name(value: &str) -> &str {
    value.strip_prefix("/dev/").unwrap_or(value)
}

fn mac_media_name(name: &str) -> String {
    let Some(rest) = name.strip_prefix("disk") else {
        return name.to_string();
    };
    let digits = rest.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits == 0 {
        return name.to_string();
    }
    format!("disk{}", &rest[..digits])
}

fn member_disks_for(names: &[String], inputs: &StorageInputs) -> Vec<String> {
    let mut disks = BTreeSet::new();
    for name in names {
        for leaf in block_leaves(name, inputs) {
            let disk = inputs
                .blocks
                .get(&leaf)
                .and_then(|info| info.parent.as_ref())
                .cloned()
                .unwrap_or_else(|| match inputs.platform.unwrap_or(Platform::Other) {
                    Platform::MacOs => mac_media_name(&leaf),
                    _ => leaf.clone(),
                });
            if !matches!(inputs.platform, Some(Platform::Linux))
                || (!disk.starts_with("loop") && !disk.starts_with("ram"))
            {
                disks.insert(disk);
            }
        }
    }
    disks.into_iter().collect()
}

fn block_leaves(name: &str, inputs: &StorageInputs) -> Vec<String> {
    fn visit(
        name: &str,
        inputs: &StorageInputs,
        seen: &mut HashSet<String>,
        out: &mut BTreeSet<String>,
    ) {
        if !seen.insert(name.to_string()) {
            return;
        }
        let Some(info) = inputs.blocks.get(name) else {
            out.insert(name.to_string());
            return;
        };
        if !info.slaves.is_empty() {
            for slave in &info.slaves {
                visit(slave, inputs, seen, out);
            }
        } else {
            out.insert(name.to_string());
        }
    }
    let mut out = BTreeSet::new();
    visit(name, inputs, &mut HashSet::new(), &mut out);
    out.into_iter().collect()
}

fn expand_counter_sources(names: &[String], inputs: &StorageInputs) -> Vec<String> {
    let mut sources = BTreeSet::new();
    for name in names {
        if inputs.diskstats.contains(name) {
            sources.insert(name.clone());
            continue;
        }
        for leaf in block_leaves(name, inputs) {
            if inputs.diskstats.contains(&leaf) {
                sources.insert(leaf);
            }
        }
    }
    sources.into_iter().collect()
}

fn sorted_braced(names: &[String]) -> String {
    let names: BTreeSet<_> = names.iter().map(String::as_str).collect();
    format!("{{{}}}", names.into_iter().collect::<Vec<_>>().join(","))
}

fn format_device_set(names: &[String]) -> String {
    let names: BTreeSet<_> = names.iter().map(String::as_str).collect();
    match names.len() {
        0 => "unknown".into(),
        1 => names.into_iter().next().unwrap_or("unknown").to_string(),
        _ => format!("{{{}}}", names.into_iter().collect::<Vec<_>>().join(",")),
    }
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: Option<T>) {
    if let Some(value) = value {
        if !values.contains(&value) {
            values.push(value);
        }
    }
}

fn lvm_for_block<'a>(
    info: &BlockInfo,
    lvs: &'a [super::volumes::LvmLogicalVolume],
) -> Option<&'a super::volumes::LvmLogicalVolume> {
    let name = info.dm_name.as_deref()?;
    let (vg, lv) = unescape_lvm_dm_name(name)?;
    lvs.iter()
        .find(|entry| entry.vg_name == vg && entry.lv_name == lv)
}

fn lvm_identity_from_block(info: &BlockInfo) -> Option<(String, String)> {
    if !info
        .dm_uuid
        .as_deref()
        .is_some_and(|uuid| uuid.starts_with("LVM-"))
    {
        return None;
    }
    unescape_lvm_dm_name(info.dm_name.as_deref()?)
}

fn lvm_thin_pool<'a>(
    thin_lv: &super::volumes::LvmLogicalVolume,
    lvs: &'a [super::volumes::LvmLogicalVolume],
) -> Option<&'a super::volumes::LvmLogicalVolume> {
    let pool = thin_lv.pool_lv.as_deref()?;
    lvs.iter()
        .find(|entry| entry.vg_name == thin_lv.vg_name && entry.lv_name == pool)
}

fn is_internal_lvm_device(info: &BlockInfo) -> bool {
    let name_internal = info
        .dm_name
        .as_deref()
        .and_then(unescape_lvm_dm_name)
        .is_some_and(|(_, lv)| is_internal_lvm_name(&lv));
    let uuid_internal = info.dm_uuid.as_deref().is_some_and(|uuid| {
        [
            "-tpool", "-tdata", "-tmeta", "-real", "-cow", "-cdata", "-cmeta", "-vdata", "-vmeta",
            "-pmspare",
        ]
        .iter()
        .any(|suffix| uuid.ends_with(suffix))
            || ["-rimage_", "-rmeta_"]
                .iter()
                .any(|prefix| uuid.contains(prefix))
    });
    name_internal || uuid_internal
}

fn is_internal_lvm_name(name: &str) -> bool {
    [
        "_tpool", "_tdata", "_tmeta", "_real", "_cow", "_cdata", "_cmeta", "_vdata", "_vmeta",
        "_pmspare",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
        || ["_rimage_", "_rmeta_"]
            .iter()
            .any(|prefix| name.contains(prefix))
}

/// Decode LVM's `vg-lv` device-mapper name. Hyphens inside either name are
/// doubled; the one undoubled hyphen separates VG and LV.
fn unescape_lvm_dm_name(name: &str) -> Option<(String, String)> {
    let bytes = name.as_bytes();
    let mut split = None;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'-' {
            if bytes.get(index + 1) == Some(&b'-') {
                index += 2;
                continue;
            }
            split = Some(index);
            break;
        }
        index += 1;
    }
    let split = split?;
    let unescape = |raw: &str| raw.replace("--", "-");
    let vg = unescape(&name[..split]);
    let lv = unescape(&name[split + 1..]);
    (!vg.is_empty() && !lv.is_empty()).then_some((vg, lv))
}

#[cfg(target_os = "linux")]
fn read_diskstats_names() -> HashSet<String> {
    std::fs::read_to_string("/proc/diskstats")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2).map(str::to_string))
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn read_diskstats_names() -> HashSet<String> {
    HashSet::new()
}

#[cfg(target_os = "linux")]
fn read_swaps() -> Vec<SwapEntry> {
    std::fs::read_to_string("/proc/swaps")
        .map(|text| parse_swaps(&text))
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn read_swaps() -> Vec<SwapEntry> {
    Vec::new()
}

fn parse_swaps(text: &str) -> Vec<SwapEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            Some(SwapEntry {
                path: fields.first()?.replace("\\040", " "),
                kind: (*fields.get(1)?).to_string(),
                size_kib: fields.get(2)?.parse().ok()?,
                used_kib: fields.get(3)?.parse().ok()?,
            })
        })
        .collect()
}

fn current_platform() -> Platform {
    #[cfg(target_os = "linux")]
    return Platform::Linux;
    #[cfg(target_os = "macos")]
    return Platform::MacOs;
    #[allow(unreachable_code)]
    Platform::Other
}

#[cfg(unix)]
fn filesystem_device_id(path: &str) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let device = std::fs::metadata(path).ok()?.dev() as u64;
    #[cfg(target_os = "linux")]
    {
        let major = (((device >> 8) & 0xfff) | ((device >> 32) & 0xfffff000)) as u32;
        let minor = ((device & 0xff) | ((device >> 12) & 0xffffff00)) as u32;
        Some((major, minor))
    }
    #[cfg(target_os = "macos")]
    {
        Some(((device >> 24) as u32, (device & 0x00ff_ffff) as u32))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = device;
        None
    }
}

#[cfg(not(unix))]
fn filesystem_device_id(_path: &str) -> Option<(u32, u32)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::volumes::{
        ApfsContainer, ApfsVolume, MdRaidArray, MdRaidMember, ZfsPool, ZfsVdev, ZfsVdevSection,
    };

    fn fs(mount: &str, device: &str, fs_type: &str, size: u64, free: u64) -> FsTick {
        FsTick {
            mount: mount.into(),
            device: device.into(),
            fs_type: fs_type.into(),
            size_bytes: size,
            used_bytes: size.saturating_sub(free),
            avail_bytes: free,
            inode_pct: None,
            is_removable: false,
            is_system: false,
        }
    }

    fn base_inputs(platform: Platform) -> StorageInputs {
        StorageInputs {
            platform: Some(platform),
            ..StorageInputs::default()
        }
    }

    #[test]
    fn unescapes_lvm_names_and_filters_internal_devices() {
        assert_eq!(
            unescape_lvm_dm_name("vg--west-root--home"),
            Some(("vg-west".into(), "root-home".into()))
        );
        assert_eq!(
            unescape_lvm_dm_name("vg-root"),
            Some(("vg".into(), "root".into()))
        );
        assert_eq!(
            unescape_lvm_dm_name("vg--west-pool_tdata"),
            Some(("vg-west".into(), "pool_tdata".into()))
        );
        assert!(is_internal_lvm_name("pool_tmeta"));
        assert!(is_internal_lvm_name("raid_rimage_2"));
        assert!(!is_internal_lvm_name("root"));
    }

    #[test]
    fn swap_parser_reads_partition_and_file_swap_sizes() {
        let entries = parse_swaps(
            "Filename Type Size Used Priority\n/dev/sde1 partition 8192 1024 -2\n/var/swap\\040file file 4096 256 -3\n",
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/dev/sde1");
        assert_eq!((entries[0].size_kib, entries[0].used_kib), (8192, 1024));
        assert_eq!(entries[1].path, "/var/swap file");
        assert_eq!(entries[1].kind, "file");
    }

    #[test]
    fn resolves_filesystem_bind_mounts_and_multidevice_btrfs() {
        let filesystems = [
            fs("/data", "/dev/sda1", "ext4", 1000, 400),
            fs("/data-bind", "/dev/sda1", "ext4", 1000, 400),
            fs("/btrfs", "/dev/sdb", "btrfs", 9000, 3000),
            fs("/btrfs/sub", "/dev/sdb", "btrfs", 9000, 3000),
        ];
        let mut inputs = base_inputs(Platform::Linux);
        inputs.fs_device_ids.insert("/data".into(), Some((8, 1)));
        inputs
            .fs_device_ids
            .insert("/data-bind".into(), Some((8, 1)));
        inputs.fs_device_ids.insert("/btrfs".into(), Some((8, 16)));
        inputs
            .fs_device_ids
            .insert("/btrfs/sub".into(), Some((8, 16)));
        inputs.blocks.insert(
            "sda1".into(),
            BlockInfo {
                parent: Some("sda".into()),
                ..Default::default()
            },
        );
        inputs.blocks.insert("sda".into(), BlockInfo::default());
        inputs.blocks.insert("sdb".into(), BlockInfo::default());
        inputs.blocks.insert("sdc".into(), BlockInfo::default());
        inputs.blocks.insert(
            "sdd".into(),
            BlockInfo {
                parent: Some("sdd".into()),
                ..Default::default()
            },
        );
        inputs
            .diskstats
            .extend(["sda1".into(), "sdb".into(), "sdc".into(), "sdd".into()]);
        inputs.btrfs.insert(
            "sdb".into(),
            (
                "uuid-b".into(),
                vec!["sdb".into(), "sdc".into(), "sdd".into()],
            ),
        );
        let resolution = resolve_with_inputs(&filesystems, &VolumeTick::default(), &inputs);
        let plain = resolution
            .rows
            .iter()
            .find(|row| row.kind == VolumeKind::Filesystem)
            .unwrap();
        assert_eq!(plain.mounts, vec!["/data", "/data-bind"]);
        assert_eq!(plain.counter_sources, vec!["sda1"]);
        let btrfs = resolution
            .rows
            .iter()
            .find(|row| row.kind == VolumeKind::Btrfs)
            .unwrap();
        assert_eq!(btrfs.mounts.len(), 2);
        assert_eq!(btrfs.counter_sources, vec!["sdb", "sdc", "sdd"]);
    }

    #[test]
    fn resolves_zfs_md_apfs_and_pseudo_filesystems() {
        let filesystems = [
            fs("/tank", "tank", "zfs", 500, 200),
            fs("/tank/home", "tank/home", "zfs", 500, 200),
            fs("/raid", "/dev/md0", "ext4", 200, 80),
            fs("/run", "tmpfs", "tmpfs", 100, 50),
            fs("/", "/dev/disk3s1", "apfs", 1000, 400),
        ];
        let volumes = VolumeTick {
            zfs: vec![ZfsPool {
                name: "tank".into(),
                health: "ONLINE".into(),
                size_bytes: 500,
                alloc_bytes: 300,
                free_bytes: 200,
                vdevs: vec![ZfsVdev {
                    name: "sdc1".into(),
                    section: ZfsVdevSection::Data,
                    ..Default::default()
                }],
            }],
            mdraid: vec![MdRaidArray {
                name: "md0".into(),
                level: "raid1".into(),
                state: "active".into(),
                members_total: 2,
                members_present: 1,
                member_state: "U_".into(),
                members: vec![MdRaidMember {
                    device: "sda1".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            containers: vec![ApfsContainer {
                bsd: "disk3".into(),
                size_bytes: 1000,
                used_bytes: 600,
                physical_store: Some("disk0s2".into()),
                volumes: vec![ApfsVolume {
                    bsd: "disk3s1".into(),
                    mount_point: Some("/".into()),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        };
        let mut inputs = base_inputs(Platform::Linux);
        inputs.fs_device_ids.insert("/tank".into(), Some((0, 55)));
        inputs
            .fs_device_ids
            .insert("/tank/home".into(), Some((0, 55)));
        inputs.fs_device_ids.insert("/raid".into(), Some((9, 0)));
        inputs.fs_device_ids.insert("/run".into(), Some((0, 1)));
        inputs.blocks.insert("md0".into(), BlockInfo::default());
        inputs.blocks.insert(
            "sda1".into(),
            BlockInfo {
                parent: Some("sda".into()),
                ..Default::default()
            },
        );
        inputs.blocks.insert("sda".into(), BlockInfo::default());
        inputs.blocks.insert(
            "sdc1".into(),
            BlockInfo {
                parent: Some("sdc".into()),
                ..Default::default()
            },
        );
        inputs.blocks.insert("sdc".into(), BlockInfo::default());
        inputs
            .diskstats
            .extend(["md0".into(), "sda1".into(), "sdc1".into()]);
        let linux_rows = resolve_with_inputs(&filesystems[..4], &volumes, &inputs).rows;
        assert_eq!(
            linux_rows
                .iter()
                .filter(|row| row.kind == VolumeKind::ZfsPool)
                .count(),
            1
        );
        let zfs = linux_rows
            .iter()
            .find(|row| row.kind == VolumeKind::ZfsPool)
            .unwrap();
        assert_eq!(zfs.mounts, vec!["/tank", "/tank/home"]);
        assert!(linux_rows.iter().all(|row| row.fs_type != "tmpfs"));
        let md = linux_rows
            .iter()
            .find(|row| row.backing.starts_with("md0"))
            .unwrap();
        assert!(md
            .warnings
            .iter()
            .any(|warning| warning.contains("md health")));

        let mut mac_inputs = base_inputs(Platform::MacOs);
        mac_inputs.fs_device_ids.insert("/".into(), Some((1, 2)));
        let apfs = resolve_with_inputs(&filesystems[4..], &volumes, &mac_inputs).rows;
        assert_eq!(apfs[0].kind, VolumeKind::ApfsContainer);
        assert_eq!(apfs[0].counter_sources, vec!["disk0"]);
    }

    #[test]
    fn mounted_zfs_without_pool_metadata_still_has_one_fallback_row() {
        let filesystems = [
            fs("/tank", "tank", "zfs", 500, 200),
            fs("/tank", "tank", "zfs", 500, 200),
        ];
        let inputs = base_inputs(Platform::Linux);
        let resolution = resolve_with_inputs(&filesystems, &VolumeTick::default(), &inputs);
        assert_eq!(resolution.rows.len(), 1);
        assert_eq!(resolution.rows[0].id, "zfs:tank");
        assert_eq!(resolution.rows[0].label, "/tank");
        assert_eq!(resolution.rows[0].mounts, vec!["/tank"]);
        assert_eq!(resolution.rows[0].kind, VolumeKind::ZfsPool);
        assert!(resolution.rows[0]
            .warnings
            .contains(&"pool metadata unavailable".into()));
    }

    #[test]
    fn swap_shares_latency_with_filesystem_on_same_disk_and_skips_file_row() {
        let filesystems = vec![fs("/data", "/dev/sde2", "ext4", 100, 50)];
        let mut inputs = base_inputs(Platform::Linux);
        inputs.fs_device_ids.insert("/data".into(), Some((8, 66)));
        inputs.blocks.insert("sde".into(), BlockInfo::default());
        inputs.blocks.insert(
            "sde1".into(),
            BlockInfo {
                parent: Some("sde".into()),
                ..Default::default()
            },
        );
        inputs.blocks.insert(
            "sde2".into(),
            BlockInfo {
                parent: Some("sde".into()),
                ..Default::default()
            },
        );
        inputs.diskstats.extend(["sde1".into(), "sde2".into()]);
        inputs.swaps = vec![
            SwapEntry {
                path: "/dev/sde1".into(),
                kind: "partition".into(),
                size_kib: 2048,
                used_kib: 512,
            },
            SwapEntry {
                path: "/swapfile".into(),
                kind: "file".into(),
                size_kib: 1024,
                used_kib: 0,
            },
        ];
        let resolution = resolve_with_inputs(&filesystems, &VolumeTick::default(), &inputs);
        assert_eq!(resolution.rows.len(), 2);
        let swap = resolution
            .rows
            .iter()
            .find(|row| row.kind == VolumeKind::Swap)
            .unwrap();
        assert_eq!(swap.free_bytes, 1536 * 1024);
        assert_eq!(swap.counter_sources, vec!["sde1"]);
        let fs_row = resolution
            .rows
            .iter()
            .find(|row| row.kind == VolumeKind::Filesystem)
            .unwrap();
        assert!(fs_row.latency_sources.is_empty());
        assert_eq!(
            fs_row.latency_note.as_deref(),
            Some("sde shared with swap sde1")
        );
        assert!(resolution.notes[0].contains("/swapfile skipped"));
    }

    #[test]
    fn thin_lvm_caps_free_and_reports_eighty_percent_fill() {
        let filesystems = vec![fs("/thin", "/dev/dm-2", "ext4", 1000, 700)];
        let volumes = VolumeTick {
            lvm: vec![
                super::super::volumes::LvmLogicalVolume {
                    vg_name: "vg".into(),
                    lv_name: "pool".into(),
                    size_bytes: 1000,
                    data_percent: Some(85.0),
                    metadata_percent: Some(82.0),
                    ..Default::default()
                },
                super::super::volumes::LvmLogicalVolume {
                    vg_name: "vg".into(),
                    lv_name: "thin".into(),
                    pool_lv: Some("pool".into()),
                    size_bytes: 2000,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut inputs = base_inputs(Platform::Linux);
        inputs.fs_device_ids.insert("/thin".into(), Some((253, 2)));
        inputs.blocks.insert(
            "dm-2".into(),
            BlockInfo {
                dm_uuid: Some("LVM-vg-thin".into()),
                dm_name: Some("vg-thin".into()),
                ..Default::default()
            },
        );
        inputs.diskstats.insert("dm-2".into());
        let rows = resolve_with_inputs(&filesystems, &volumes, &inputs).rows;
        assert_eq!(rows[0].free_bytes, 150);
        assert_eq!(rows[0].warnings.len(), 2);
    }

    #[test]
    fn lvm_internal_mappings_do_not_become_filesystem_rows() {
        let filesystems = [fs("/internal", "/dev/dm-9", "ext4", 100, 50)];
        let mut inputs = base_inputs(Platform::Linux);
        inputs.blocks.insert(
            "dm-9".into(),
            BlockInfo {
                dm_uuid: Some("LVM-vg-uuid-lv-uuid-tdata".into()),
                dm_name: Some("vg-pool_tdata".into()),
                ..Default::default()
            },
        );
        inputs.diskstats.insert("dm-9".into());
        let rows = resolve_with_inputs(&filesystems, &VolumeTick::default(), &inputs).rows;
        assert!(rows.is_empty());
    }

    #[test]
    fn unprivileged_lvm_rows_still_show_identity_and_backing_chain() {
        let filesystems = [fs("/root", "/dev/dm-3", "ext4", 100, 50)];
        let mut inputs = base_inputs(Platform::Linux);
        inputs.blocks.insert(
            "dm-3".into(),
            BlockInfo {
                dm_uuid: Some("LVM-vg-uuid-lv-uuid".into()),
                dm_name: Some("vg-root".into()),
                slaves: vec!["sda2".into()],
                ..Default::default()
            },
        );
        inputs.blocks.insert(
            "sda2".into(),
            BlockInfo {
                parent: Some("sda".into()),
                ..Default::default()
            },
        );
        inputs.blocks.insert("sda".into(), BlockInfo::default());
        inputs.diskstats.insert("dm-3".into());
        let rows = resolve_with_inputs(&filesystems, &VolumeTick::default(), &inputs).rows;
        assert_eq!(rows[0].backing, "vg/root → dm-3 → sda2");

        let loop_fs = [fs("/loop", "/dev/dm-0", "ext4", 100, 50)];
        let mut loop_inputs = base_inputs(Platform::Linux);
        loop_inputs.blocks.insert(
            "dm-0".into(),
            BlockInfo {
                dm_uuid: Some("LVM-vg-uuid-lv-uuid".into()),
                dm_name: Some("vg-looplv".into()),
                slaves: vec!["loop0".into()],
                ..Default::default()
            },
        );
        loop_inputs
            .blocks
            .insert("loop0".into(), BlockInfo::default());
        loop_inputs.diskstats.insert("dm-0".into());
        let row = resolve_with_inputs(&loop_fs, &VolumeTick::default(), &loop_inputs)
            .rows
            .remove(0);
        assert!(row.member_disks.is_empty());
    }
}
