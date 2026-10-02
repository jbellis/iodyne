//! Volumes collector — APFS containers (macOS), mdraid and ZFS on Linux.

#[derive(Debug, Clone, Default)]
pub struct VolumeTick {
    pub containers: Vec<ApfsContainer>,
    pub mdraid: Vec<MdRaidArray>,
    pub zfs: Vec<ZfsPool>,
}

#[derive(Debug, Clone, Default)]
pub struct ZfsPool {
    pub name: String,
    pub health: String,
    pub size_bytes: u64,
    pub alloc_bytes: u64,
    pub free_bytes: u64,
    pub vdevs: Vec<ZfsVdev>,
}

#[derive(Debug, Clone, Default)]
pub struct ZfsVdev {
    /// Vdev group name, or a leaf's kernel device name (for example `sdc1`).
    pub name: String,
    pub vdev_type: String,
    #[allow(dead_code)]
    pub size_bytes: u64,
    /// Missing when OpenZFS prints `-` for a child vdev allocation.
    pub alloc_bytes: Option<u64>,
    #[allow(dead_code)]
    pub free_bytes: u64,
    #[allow(dead_code)]
    pub health: String,
    pub section: ZfsVdevSection,
    pub children: Vec<ZfsVdev>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ZfsVdevSection {
    #[default]
    Data,
    Log,
    Cache,
    Spare,
    Special,
    Dedup,
}

impl ZfsPool {
    /// Return each leaf and its containing vdev groups, from outermost in.
    pub fn leaf_vdevs(&self) -> Vec<(&ZfsVdev, Vec<&ZfsVdev>)> {
        fn visit<'a>(
            nodes: &'a [ZfsVdev],
            groups: &mut Vec<&'a ZfsVdev>,
            out: &mut Vec<(&'a ZfsVdev, Vec<&'a ZfsVdev>)>,
        ) {
            for node in nodes {
                if node.children.is_empty() {
                    out.push((node, groups.clone()));
                } else {
                    groups.push(node);
                    visit(&node.children, groups, out);
                    groups.pop();
                }
            }
        }

        let mut out = Vec::new();
        visit(&self.vdevs, &mut Vec::new(), &mut out);
        out
    }

    /// Return each leaf with its effective allocation. OpenZFS reports the
    /// allocation on a mirror/RAIDZ group rather than on its children.
    pub fn leaf_allocations(&self) -> Vec<(&ZfsVdev, u64)> {
        struct AllocationGroup<'a> {
            vdev: &'a ZfsVdev,
            allocated: u64,
            leaf_count: usize,
            leaves_seen: usize,
        }

        fn leaf_count(vdev: &ZfsVdev) -> usize {
            if vdev.children.is_empty() {
                1
            } else {
                vdev.children.iter().map(leaf_count).sum()
            }
        }

        fn visit<'a>(
            nodes: &'a [ZfsVdev],
            groups: &mut Vec<AllocationGroup<'a>>,
            out: &mut Vec<(&'a ZfsVdev, u64)>,
        ) {
            for vdev in nodes {
                if vdev.children.is_empty() {
                    let inherited = groups.last().map(|group| {
                        let type_name = group.vdev.vdev_type.to_ascii_lowercase();
                        let mirror = matches!(type_name.as_str(), "mirror" | "replacing" | "spare");
                        if mirror {
                            group.allocated
                        } else {
                            let count = group.leaf_count.max(1) as u64;
                            let quotient = group.allocated / count;
                            let remainder = group.allocated % count;
                            quotient + u64::from((group.leaves_seen as u64) < remainder)
                        }
                    });
                    let allocated = vdev.alloc_bytes.or(inherited).unwrap_or(0);
                    out.push((vdev, allocated));
                    for group in groups.iter_mut() {
                        group.leaves_seen += 1;
                    }
                } else {
                    if let Some(allocated) = vdev.alloc_bytes {
                        groups.push(AllocationGroup {
                            vdev,
                            allocated,
                            leaf_count: leaf_count(vdev),
                            leaves_seen: 0,
                        });
                    }
                    visit(&vdev.children, groups, out);
                    if vdev.alloc_bytes.is_some() {
                        groups.pop();
                    }
                }
            }
        }

        let mut out = Vec::new();
        visit(&self.vdevs, &mut Vec::new(), &mut out);
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct MdRaidArray {
    pub name: String,  // "md0"
    pub level: String, // "raid10", "raid1", ...
    pub state: String, // "active", "inactive", ...
    pub size_bytes: u64,
    /// "[4/4]" — total / present.
    pub members_total: u32,
    pub members_present: u32,
    /// "[UUUU]" — one char per slot. 'U' = up.
    pub member_state: String,
    /// "sda1[0]", "sdb1[1]", …
    pub members: Vec<MdRaidMember>,
    /// In-progress resync/recovery: (operation, percent, eta).
    pub progress: Option<MdRaidProgress>,
}

#[derive(Debug, Clone, Default)]
pub struct MdRaidMember {
    pub device: String,
    /// Kernel RAID slot retained for diagnostics and degraded-array evidence.
    #[allow(dead_code)]
    pub index: u32,
    pub flag: Option<String>, // "(F)" failed, "(S)" spare, "(W)" write-mostly
}

#[derive(Debug, Clone, Default)]
pub struct MdRaidProgress {
    pub op: String,
    pub percent: f32,
    pub eta: String,
    pub speed: String,
}

#[derive(Debug, Clone, Default)]
pub struct ApfsContainer {
    pub bsd: String,
    /// Parsed APFS capacity evidence reserved for a richer volume view.
    #[allow(dead_code)]
    pub size_bytes: u64,
    /// Parsed APFS usage evidence reserved for a richer volume view.
    #[allow(dead_code)]
    pub used_bytes: u64,
    pub physical_store: Option<String>,
    pub volumes: Vec<ApfsVolume>,
}

#[derive(Debug, Clone, Default)]
pub struct ApfsVolume {
    pub bsd: String,
    /// Parsed APFS metadata retained even though topology only needs the BSD ID.
    #[allow(dead_code)]
    pub name: String,
    #[allow(dead_code)]
    pub role: String,
    #[allow(dead_code)]
    pub mount_point: Option<String>,
    #[allow(dead_code)]
    pub consumed_bytes: u64,
    #[allow(dead_code)]
    pub filevault: bool,
}

pub fn collect() -> VolumeTick {
    #[cfg(target_os = "macos")]
    {
        macos_collect()
    }
    #[cfg(target_os = "linux")]
    {
        VolumeTick {
            mdraid: linux_mdraid(),
            zfs: linux_zfs(),
            ..VolumeTick::default()
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        VolumeTick::default()
    }
}

#[cfg(target_os = "macos")]
fn macos_collect() -> VolumeTick {
    use std::process::Command;
    let Ok(out) = Command::new("diskutil").args(["apfs", "list"]).output() else {
        return VolumeTick::default();
    };
    if !out.status.success() {
        return VolumeTick::default();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = VolumeTick::default();
    let mut cur_container: Option<ApfsContainer> = None;
    let mut cur_volume: Option<ApfsVolume> = None;

    for line in text.lines() {
        let trimmed = line.trim_start();

        // Container header: "+-- Container disk3 <uuid>"
        if let Some(rest) = trimmed.strip_prefix("+-- Container ") {
            // Push any in-flight volume / container.
            if let Some(v) = cur_volume.take() {
                if let Some(c) = cur_container.as_mut() {
                    c.volumes.push(v);
                }
            }
            if let Some(c) = cur_container.take() {
                result.containers.push(c);
            }
            let bsd: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
            cur_container = Some(ApfsContainer {
                bsd,
                ..Default::default()
            });
            continue;
        }

        // Volume header: "+-> Volume disk3s1 <uuid>"
        if let Some(rest) = trimmed.strip_prefix("+-> Volume ") {
            if let Some(v) = cur_volume.take() {
                if let Some(c) = cur_container.as_mut() {
                    c.volumes.push(v);
                }
            }
            let bsd: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
            cur_volume = Some(ApfsVolume {
                bsd,
                ..Default::default()
            });
            continue;
        }

        // Physical store: "+-< Physical Store disk0s2 <uuid>"
        if let Some(rest) = trimmed.strip_prefix("+-< Physical Store ") {
            let store: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
            if let Some(c) = cur_container.as_mut() {
                c.physical_store = Some(store);
            }
            continue;
        }

        // Container "Size (Capacity Ceiling):  994662584320 B (994.7 GB)"
        if let Some(rest) = trimmed.strip_prefix("Size (Capacity Ceiling):") {
            if let Some(c) = cur_container.as_mut() {
                if cur_volume.is_none() {
                    c.size_bytes = first_byte_count(rest);
                }
            }
            continue;
        }
        // "Capacity In Use By Volumes:   319709114368 B (319.7 GB) (32.1% used)"
        if let Some(rest) = trimmed.strip_prefix("Capacity In Use By Volumes:") {
            if let Some(c) = cur_container.as_mut() {
                c.used_bytes = first_byte_count(rest);
            }
            continue;
        }

        // Volume role: "APFS Volume Disk (Role):   disk3s1 (System)"
        if let Some(rest) = trimmed.strip_prefix("APFS Volume Disk (Role):") {
            if let Some(v) = cur_volume.as_mut() {
                if let Some(open) = rest.find('(') {
                    if let Some(close) = rest[open..].find(')') {
                        v.role = rest[open + 1..open + close].to_string();
                    }
                }
            }
            continue;
        }
        // Volume name: "Name:                      Macintosh HD (Case-insensitive)"
        if let Some(rest) = trimmed.strip_prefix("Name:") {
            if let Some(v) = cur_volume.as_mut() {
                let name = rest.trim();
                let name = name.split_once(" (").map(|(a, _)| a).unwrap_or(name);
                v.name = name.trim().to_string();
            }
            continue;
        }
        // Mount point: "Mount Point:               /System/Volumes/Data"
        if let Some(rest) = trimmed.strip_prefix("Mount Point:") {
            if let Some(v) = cur_volume.as_mut() {
                let mp = rest.trim();
                if !mp.is_empty() && mp != "Not Mounted" {
                    v.mount_point = Some(mp.to_string());
                }
            }
            continue;
        }
        // "Capacity Consumed:         17797750784 B (17.8 GB)"
        if let Some(rest) = trimmed.strip_prefix("Capacity Consumed:") {
            if let Some(v) = cur_volume.as_mut() {
                v.consumed_bytes = first_byte_count(rest);
            }
            continue;
        }
        // "FileVault:                 Yes (Unlocked)"
        if let Some(rest) = trimmed.strip_prefix("FileVault:") {
            if let Some(v) = cur_volume.as_mut() {
                v.filevault = rest.trim_start().starts_with("Yes");
            }
            continue;
        }
    }

    // Flush trailing.
    if let Some(v) = cur_volume.take() {
        if let Some(c) = cur_container.as_mut() {
            c.volumes.push(v);
        }
    }
    if let Some(c) = cur_container.take() {
        result.containers.push(c);
    }
    result
}

#[cfg(target_os = "linux")]
fn linux_mdraid() -> Vec<MdRaidArray> {
    let Ok(text) = std::fs::read_to_string("/proc/mdstat") else {
        return Vec::new();
    };
    parse_mdstat(&text)
}

#[cfg(target_os = "linux")]
fn linux_zfs() -> Vec<ZfsPool> {
    if let Ok(output) = zpool_command(&["list", "-j", "-v", "-p", "-P", "-L"]) {
        if output.status.success() {
            if let Some(pools) = parse_zpool_json(&String::from_utf8_lossy(&output.stdout)) {
                return pools;
            }
        }
    }

    let Ok(output) = zpool_command(&["list", "-v", "-P", "-L", "-p"]) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    parse_zpool_text(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "linux")]
fn zpool_command(args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::io::ErrorKind;
    use std::process::Command;

    match Command::new("zpool").args(args).env("LC_ALL", "C").output() {
        Err(error) if error.kind() == ErrorKind::NotFound => Command::new("/usr/sbin/zpool")
            .args(args)
            .env("LC_ALL", "C")
            .output(),
        result => result,
    }
}

/// Parse the JSON emitted by `zpool list -j -v -p -P -L`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_zpool_json(text: &str) -> Option<Vec<ZfsPool>> {
    use serde_json::{Map, Value};

    fn parse_vdev_map(
        entries: &Map<String, Value>,
        inherited_section: ZfsVdevSection,
        out: &mut Vec<ZfsVdev>,
    ) {
        for (name, value) in entries {
            let section = parse_zfs_section(name);
            if let (Some(section), Some(children)) = (section, value.as_object()) {
                if value.get("vdev_type").is_none() {
                    parse_vdev_map(children, section, out);
                    continue;
                }
            }
            out.push(parse_json_vdev(name, value, inherited_section));
        }
    }

    fn parse_json_vdev(name: &str, value: &Value, inherited: ZfsVdevSection) -> ZfsVdev {
        let explicit_name = value.get("name").and_then(Value::as_str).unwrap_or(name);
        let base_name = std::path::Path::new(explicit_name)
            .file_name()
            .map(|part| part.to_string_lossy().into_owned())
            .unwrap_or_else(|| explicit_name.to_string());
        let class_section = value
            .get("class")
            .and_then(Value::as_str)
            .and_then(parse_zfs_section)
            .filter(|section| *section != ZfsVdevSection::Data);
        let section = class_section.unwrap_or(inherited);
        let mut vdev = ZfsVdev {
            name: base_name,
            vdev_type: value
                .get("vdev_type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            size_bytes: json_property_u64(value, "size").unwrap_or(0),
            alloc_bytes: json_property_u64(value, "allocated"),
            free_bytes: json_property_u64(value, "free").unwrap_or(0),
            health: json_property_string(value, "health")
                .or_else(|| {
                    value
                        .get("state")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_default(),
            section,
            ..Default::default()
        };
        if let Some(children) = value.get("vdevs").and_then(Value::as_object) {
            parse_vdev_map(children, section, &mut vdev.children);
        }
        vdev
    }

    let root: Value = serde_json::from_str(text).ok()?;
    let entries = root.get("pools")?.as_object()?;
    let mut pools = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        if value
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind != "POOL")
        {
            continue;
        }
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(key)
            .to_string();
        let mut pool = ZfsPool {
            health: json_property_string(value, "health")
                .or_else(|| {
                    value
                        .get("state")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_default(),
            size_bytes: json_property_u64(value, "size").unwrap_or(0),
            alloc_bytes: json_property_u64(value, "allocated").unwrap_or(0),
            free_bytes: json_property_u64(value, "free").unwrap_or(0),
            name,
            ..Default::default()
        };
        if let Some(vdevs) = value.get("vdevs").and_then(Value::as_object) {
            parse_vdev_map(vdevs, ZfsVdevSection::Data, &mut pool.vdevs);
        }
        pools.push(pool);
    }
    Some(pools)
}

fn json_property_string(value: &serde_json::Value, property: &str) -> Option<String> {
    value
        .get("properties")?
        .get(property)?
        .get("value")?
        .as_str()
        .map(str::to_string)
}

fn json_property_u64(value: &serde_json::Value, property: &str) -> Option<u64> {
    let value = value.get("properties")?.get(property)?.get("value")?;
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse::<u64>().ok())
}

/// Parse `zpool list -vPLp` for OpenZFS releases without JSON output. In this
/// format indentation is two spaces per vdev depth and class headers occupy a
/// padded, column-zero row whose value columns are all `-`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_zpool_text(text: &str) -> Vec<ZfsPool> {
    let mut pools = Vec::new();
    let mut current: Option<ZfsPool> = None;
    let mut section = ZfsVdevSection::Data;
    let mut path = Vec::new();

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let indentation = line.chars().take_while(|ch| *ch == ' ').count();
        if indentation % 2 != 0 {
            continue;
        }
        let row = &line[indentation..];
        let fields: Vec<_> = row.split_whitespace().collect();
        let Some(name) = fields.first().filter(|name| !name.is_empty()).copied() else {
            continue;
        };

        if name.eq_ignore_ascii_case("NAME") && fields.get(1) == Some(&"SIZE") {
            continue;
        }

        if indentation == 0 && fields.len() > 1 && fields[1..].iter().all(|field| *field == "-") {
            if let Some(next_section) = parse_zfs_section(name) {
                section = next_section;
                path.clear();
                continue;
            }
        }

        if indentation == 0 {
            if let Some(pool) = current.take() {
                pools.push(pool);
            }
            section = ZfsVdevSection::Data;
            path.clear();
            current = Some(ZfsPool {
                name: name.to_string(),
                health: field(&fields, 9).to_string(),
                size_bytes: number_field(&fields, 1),
                alloc_bytes: number_field(&fields, 2),
                free_bytes: number_field(&fields, 3),
                ..Default::default()
            });
            continue;
        }

        let Some(pool) = current.as_mut() else {
            continue;
        };
        let vdev_depth = indentation / 2 - 1;
        let vdev = ZfsVdev {
            name: std::path::Path::new(name)
                .file_name()
                .map(|part| part.to_string_lossy().into_owned())
                .unwrap_or_else(|| name.to_string()),
            vdev_type: infer_text_vdev_type(name).to_string(),
            health: field(&fields, 9).to_string(),
            size_bytes: number_field(&fields, 1),
            alloc_bytes: field(&fields, 2).parse().ok(),
            free_bytes: number_field(&fields, 3),
            section,
            ..Default::default()
        };
        insert_zfs_vdev(&mut pool.vdevs, &mut path, vdev_depth, vdev);
    }

    if let Some(pool) = current {
        pools.push(pool);
    }
    pools
}

fn infer_text_vdev_type(name: &str) -> &'static str {
    let name = name.to_ascii_lowercase();
    if name == "mirror" || name.starts_with("mirror-") {
        "mirror"
    } else if name.starts_with("raidz") {
        "raidz"
    } else if name.starts_with("draid") {
        "draid"
    } else if name == "replacing" || name.starts_with("replacing-") {
        "replacing"
    } else if name == "spare" || name.starts_with("spare-") {
        "spare"
    } else {
        ""
    }
}

fn insert_zfs_vdev(roots: &mut Vec<ZfsVdev>, path: &mut Vec<usize>, depth: usize, vdev: ZfsVdev) {
    if depth > path.len() {
        return;
    }
    path.truncate(depth);
    if depth == 0 {
        roots.push(vdev);
        path.push(roots.len() - 1);
        return;
    }

    let Some(parent) = zfs_vdev_at_mut(roots, &path[..depth]) else {
        return;
    };
    parent.children.push(vdev);
    path.push(parent.children.len() - 1);
}

fn zfs_vdev_at_mut<'a>(nodes: &'a mut [ZfsVdev], path: &[usize]) -> Option<&'a mut ZfsVdev> {
    let (index, rest) = path.split_first()?;
    let node = nodes.get_mut(*index)?;
    if rest.is_empty() {
        Some(node)
    } else {
        zfs_vdev_at_mut(&mut node.children, rest)
    }
}

fn parse_zfs_section(value: &str) -> Option<ZfsVdevSection> {
    match value.to_ascii_lowercase().as_str() {
        "logs" | "log" => Some(ZfsVdevSection::Log),
        "cache" | "l2cache" => Some(ZfsVdevSection::Cache),
        "spares" | "spare" => Some(ZfsVdevSection::Spare),
        "special" => Some(ZfsVdevSection::Special),
        "dedup" => Some(ZfsVdevSection::Dedup),
        _ => None,
    }
}

fn field<'a>(fields: &[&'a str], index: usize) -> &'a str {
    fields.get(index).copied().unwrap_or("")
}

fn number_field(fields: &[&str], index: usize) -> u64 {
    field(fields, index).parse().unwrap_or(0)
}

/// Match a ZFS dataset source to its imported pool using the first path part.
pub fn pool_for_dataset<'a>(source: &str, pools: &'a [ZfsPool]) -> Option<&'a ZfsPool> {
    let pool_name = source.split('/').next()?;
    pools.iter().find(|pool| pool.name == pool_name)
}

/// Pure parser for `/proc/mdstat` content. Kept cfg-free so it can be
/// exercised in tests from any platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_mdstat(text: &str) -> Vec<MdRaidArray> {
    let mut out = Vec::new();
    let mut cur: Option<MdRaidArray> = None;

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.starts_with("Personalities") || line.starts_with("unused devices") {
            continue;
        }
        // New array header: "md0 : active raid10 sda1[0] sdb1[1] …"
        if let Some(colon) = line.find(" : ") {
            // Flush any prior array.
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            let name = line[..colon].trim().to_string();
            let rest = &line[colon + 3..];
            let mut tokens = rest.split_whitespace();
            let state = tokens.next().unwrap_or("").to_string();
            let level = tokens.next().unwrap_or("").to_string();
            let mut members = Vec::new();
            for tok in tokens {
                if let Some(member) = parse_member(tok) {
                    members.push(member);
                }
            }
            cur = Some(MdRaidArray {
                name,
                level,
                state,
                members,
                ..Default::default()
            });
            continue;
        }

        let Some(arr) = cur.as_mut() else { continue };

        // Status line: "      7813767168 blocks super 1.2 256K chunks 2 near-copies [4/4] [UUUU]"
        if line.trim_start().starts_with(|c: char| c.is_ascii_digit()) && line.contains("blocks") {
            let mut tokens = line.split_whitespace();
            if let Some(blocks) = tokens.next().and_then(|s| s.parse::<u64>().ok()) {
                arr.size_bytes = blocks.saturating_mul(1024);
            }
            if let Some(slash) = find_slot_pair(line) {
                arr.members_total = slash.0;
                arr.members_present = slash.1;
            }
            if let Some(state) = find_member_state(line) {
                arr.member_state = state;
            }
            continue;
        }

        // Progress line: "      [=====>...........]  resync = 15.0% (…) finish=89.3min speed=123776K/sec"
        let trimmed = line.trim_start();
        if trimmed.starts_with('[')
            && (trimmed.contains("resync")
                || trimmed.contains("recovery")
                || trimmed.contains("reshape")
                || trimmed.contains("check"))
        {
            arr.progress = parse_progress(line);
            continue;
        }
    }

    if let Some(last) = cur.take() {
        out.push(last);
    }
    out
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_member(tok: &str) -> Option<MdRaidMember> {
    // Forms: "sda1[0]", "sdb1[1](F)", "sdc1[2](S)", "sdd1[3](W)"
    let lb = tok.find('[')?;
    let rb = tok.find(']')?;
    let device = tok[..lb].to_string();
    let idx_str = &tok[lb + 1..rb];
    let index = idx_str.parse().ok()?;
    let flag = if tok.len() > rb + 1 {
        Some(tok[rb + 1..].to_string())
    } else {
        None
    };
    Some(MdRaidMember {
        device,
        index,
        flag,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn find_slot_pair(line: &str) -> Option<(u32, u32)> {
    // Look for "[N/M]" near the end of the line.
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let close = line[i..].find(']').map(|j| i + j)?;
            let inside = &line[i + 1..close];
            if let Some(slash) = inside.find('/') {
                if let (Ok(a), Ok(b)) = (inside[..slash].parse(), inside[slash + 1..].parse()) {
                    return Some((a, b));
                }
            }
            i = close + 1;
        } else {
            i += 1;
        }
    }
    None
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn find_member_state(line: &str) -> Option<String> {
    // "[UUUU]" — the second bracketed block on a status line (the first
    // is the [present/total] pair). We look for one whose content is
    // all 'U' / '_' characters.
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let close = line[i..].find(']').map(|j| i + j)?;
            let inside = &line[i + 1..close];
            if !inside.is_empty() && inside.chars().all(|c| matches!(c, 'U' | '_' | 'B')) {
                return Some(inside.to_string());
            }
            i = close + 1;
        } else {
            i += 1;
        }
    }
    None
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_progress(line: &str) -> Option<MdRaidProgress> {
    let op = if line.contains("resync") {
        "resync"
    } else if line.contains("recovery") {
        "recovery"
    } else if line.contains("reshape") {
        "reshape"
    } else if line.contains("check") {
        "check"
    } else {
        return None;
    };
    // The "=" inside the progress bar (`[===>....]`) confounds a naive
    // split-on-equals. Anchor the percent parse to the op keyword.
    let needle = format!("{} = ", op);
    let percent = line
        .find(&needle)
        .and_then(|i| line[i + needle.len()..].split('%').next())
        .and_then(|s| s.trim().parse::<f32>().ok())
        .unwrap_or(0.0);
    let eta = line
        .split("finish=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or("")
        .to_string();
    let speed = line
        .split("speed=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or("")
        .to_string();
    Some(MdRaidProgress {
        op: op.to_string(),
        percent,
        eta,
        speed,
    })
}

/// Extracts the first byte count from a line like
/// "   319709114368 B (319.7 GB) (32.1% used)" → 319_709_114_368.
#[cfg(target_os = "macos")]
fn first_byte_count(s: &str) -> u64 {
    let mut digits = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else if !digits.is_empty() {
            break;
        }
    }
    digits.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_active_arrays() {
        // Real `/proc/mdstat` shape from a healthy host.
        let text = "\
Personalities : [raid1] [raid10] [raid0]
md0 : active raid10 sda1[0] sdb1[1] sdc1[2] sdd1[3]
      7813767168 blocks super 1.2 256K chunks 2 near-copies [4/4] [UUUU]
      bitmap: 0/59 pages [0KB], 65536KB chunk

md1 : active raid1 sde1[0] sdf1[1]
      1953382464 blocks super 1.2 [2/2] [UU]
      bitmap: 0/15 pages [0KB], 65536KB chunk

unused devices: <none>
";
        let arrays = parse_mdstat(text);
        assert_eq!(arrays.len(), 2);

        let md0 = &arrays[0];
        assert_eq!(md0.name, "md0");
        assert_eq!(md0.level, "raid10");
        assert_eq!(md0.state, "active");
        assert_eq!(md0.members.len(), 4);
        assert_eq!(md0.members[0].device, "sda1");
        assert_eq!(md0.members[0].index, 0);
        assert!(md0.members[0].flag.is_none());
        assert_eq!(md0.size_bytes, 7_813_767_168u64 * 1024);
        assert_eq!(md0.members_total, 4);
        assert_eq!(md0.members_present, 4);
        assert_eq!(md0.member_state, "UUUU");
        assert!(md0.progress.is_none());

        let md1 = &arrays[1];
        assert_eq!(md1.members.len(), 2);
        assert_eq!(md1.member_state, "UU");
    }

    #[test]
    fn parses_degraded_with_resync() {
        let text = "\
Personalities : [raid10]
md0 : active raid10 sda1[0] sdb1[1] sdc1[2] sdd1[3](F)
      7813767168 blocks super 1.2 256K chunks 2 near-copies [4/3] [UUU_]
      [===>.................]  resync = 15.0% (1176224256/7813767168) finish=89.3min speed=123776K/sec
      bitmap: 0/59 pages [0KB], 65536KB chunk

unused devices: <none>
";
        let arrays = parse_mdstat(text);
        assert_eq!(arrays.len(), 1);
        let a = &arrays[0];
        assert_eq!(a.members_total, 4);
        assert_eq!(a.members_present, 3);
        assert_eq!(a.member_state, "UUU_");
        let failed = a.members.iter().find(|m| m.device == "sdd1").unwrap();
        assert_eq!(failed.flag.as_deref(), Some("(F)"));
        let prog = a.progress.as_ref().expect("resync progress");
        assert_eq!(prog.op, "resync");
        assert!((prog.percent - 15.0).abs() < 0.001);
        assert_eq!(prog.eta, "89.3min");
        assert_eq!(prog.speed, "123776K/sec");
    }

    #[test]
    fn parses_empty_when_no_arrays() {
        let text = "Personalities : [raid1]\n\nunused devices: <none>\n";
        let arrays = parse_mdstat(text);
        assert!(arrays.is_empty());
    }

    const REAL_ZPOOL_TEXT_FIXTURE: &str = "\
NAME                            SIZE   ALLOC       FREE  CKPOINT  EXPANDSZ   FRAG    CAP  DEDUP    HEALTH  ALTROOT
iodynetestm                251658240  267264  251390976        -         -     13      0   1.00    ONLINE  -
  mirror-0                 251658240  267264  251390976        -         -     13      0      -    ONLINE        -
    /tmp/iodyne-zt.8N9B/a  268435456      -      -        -         -      -      -      -    ONLINE        -
    /tmp/iodyne-zt.8N9B/b  268435456      -      -        -         -      -      -      -    ONLINE        -
    /tmp/iodyne-zt.8N9B/i  268435456      -      -        -         -      -      -      -    ONLINE        -
cache                              -       -          -        -         -      -      -      -         -        -
  /tmp/iodyne-zt.8N9B/g    268435456      0  263716352        -         -      0      0      -    ONLINE        -
spare                              -       -          -        -         -      -      -      -         -        -
  /tmp/iodyne-zt.8N9B/h    268435456      -      -        -         -      -      -      -     AVAIL        -
iodynetestr                738197504  334848  737862656        -         -      9      0   1.00    ONLINE  -
  raidz1-0                 738197504  334848  737862656        -         -      9      0      -    ONLINE        -
    /tmp/iodyne-zt.8N9B/c  268435456      -      -        -         -      -      -      -    ONLINE        -
    /tmp/iodyne-zt.8N9B/d  268435456      -      -        -         -      -      -      -    ONLINE        -
    /tmp/iodyne-zt.8N9B/e  268435456      -      -        -         -      -      -      -    ONLINE        -
logs                               -       -          -        -         -      -      -      -         -        -
  /tmp/iodyne-zt.8N9B/f    268435456      0  251658240        -         -      0      0      -    ONLINE        -
";

    const REAL_ZPOOL_JSON_FIXTURE: &str = r#"{
      "pools": {
        "iodynetestm": {
          "name":"iodynetestm", "type":"POOL", "state":"ONLINE",
          "properties":{"size":{"value":"251658240"},"allocated":{"value":"267264"},"free":{"value":"251390976"},"health":{"value":"ONLINE"}},
          "vdevs": {
            "mirror-0": {
              "name":"mirror-0", "vdev_type":"mirror", "class":"normal", "state":"ONLINE",
              "properties":{"allocated":{"value":"267264"}},
              "vdevs": {
                "/tmp/iodyne-zt.8N9B/a":{"name":"/tmp/iodyne-zt.8N9B/a","vdev_type":"file","class":"normal","state":"ONLINE","properties":{"size":{"value":"268435456"},"allocated":{"value":"-"}}},
                "/tmp/iodyne-zt.8N9B/b":{"name":"/tmp/iodyne-zt.8N9B/b","vdev_type":"file","class":"normal","state":"ONLINE","properties":{"size":{"value":"268435456"},"allocated":{"value":"-"}}},
                "/tmp/iodyne-zt.8N9B/i":{"name":"/tmp/iodyne-zt.8N9B/i","vdev_type":"file","class":"normal","state":"ONLINE","properties":{"size":{"value":"268435456"},"allocated":{"value":"-"}}}
              }
            },
            "l2cache": {"/tmp/iodyne-zt.8N9B/g":{"name":"/tmp/iodyne-zt.8N9B/g","vdev_type":"file","class":"l2cache","state":"ONLINE","properties":{"allocated":{"value":"0"}}}},
            "spares": {"/tmp/iodyne-zt.8N9B/h":{"name":"/tmp/iodyne-zt.8N9B/h","vdev_type":"file","class":"spare","state":"AVAIL","properties":{"allocated":{"value":"-"}}}}
          }
        },
        "iodynetestr": {
          "name":"iodynetestr", "type":"POOL", "state":"ONLINE",
          "properties":{"size":{"value":"738197504"},"allocated":{"value":"334848"},"free":{"value":"737862656"},"health":{"value":"ONLINE"}},
          "vdevs": {
            "raidz1-0": {
              "name":"raidz1-0", "vdev_type":"raidz", "class":"normal", "state":"ONLINE",
              "properties":{"allocated":{"value":"334848"}},
              "vdevs": {
                "/tmp/iodyne-zt.8N9B/c":{"name":"/tmp/iodyne-zt.8N9B/c","vdev_type":"file","class":"normal","state":"ONLINE","properties":{"allocated":{"value":"-"}}},
                "/tmp/iodyne-zt.8N9B/d":{"name":"/tmp/iodyne-zt.8N9B/d","vdev_type":"file","class":"normal","state":"ONLINE","properties":{"allocated":{"value":"-"}}},
                "/tmp/iodyne-zt.8N9B/e":{"name":"/tmp/iodyne-zt.8N9B/e","vdev_type":"file","class":"normal","state":"ONLINE","properties":{"allocated":{"value":"-"}}}
              }
            },
            "logs": {"/tmp/iodyne-zt.8N9B/f":{"name":"/tmp/iodyne-zt.8N9B/f","vdev_type":"file","class":"log","state":"ONLINE","properties":{"allocated":{"value":"0"}}}}
          }
        }
      }
    }"#;

    const OPTANE_TEXT_FIXTURE: &str = "\
NAME                  SIZE        ALLOC           FREE  CKPOINT  EXPANDSZ   FRAG    CAP  DEDUP    HEALTH  ALTROOT
optane       3367254360064  84713775104  3282540584960        -         -      0      2   1.00    ONLINE  -
  /dev/sdc1  960187334656  24127934464  929354805248        -         -      0      2      -    ONLINE        -
  /dev/sdd1  960187334656  24019652608  929463087104        -         -      0      2      -    ONLINE        -
  /dev/sde2  1462881222656  36566188032  1423722692608        -         -      0      2      -    ONLINE        -
";

    const OPTANE_JSON_FIXTURE: &str = r#"{
      "pools": {"optane": {
        "name":"optane", "type":"POOL", "state":"ONLINE",
        "properties":{"size":{"value":"3367254360064"},"allocated":{"value":"84715307008"},"free":{"value":"3282539053056"},"health":{"value":"ONLINE"}},
        "vdevs": {
          "/dev/sdc1":{"name":"/dev/sdc1","properties":{"size":{"value":"960187334656"},"allocated":{"value":"24128602112"},"free":{"value":"929354137600"},"health":{"value":"ONLINE"}}},
          "/dev/sdd1":{"name":"/dev/sdd1","properties":{"size":{"value":"960187334656"},"allocated":{"value":"24020709376"},"free":{"value":"929462030336"},"health":{"value":"ONLINE"}}},
          "/dev/sde2":{"name":"/dev/sde2","properties":{"size":{"value":"1462881222656"},"allocated":{"value":"36565995520"},"free":{"value":"1423722885120"},"health":{"value":"ONLINE"}}}
        }
      }}
    }"#;

    fn leaf_allocations_named(pool: &ZfsPool) -> std::collections::HashMap<&str, u64> {
        pool.leaf_allocations()
            .into_iter()
            .map(|(leaf, allocation)| (leaf.name.as_str(), allocation))
            .collect()
    }

    #[test]
    fn parses_real_json_mirror_raidz_and_auxiliary_sections() {
        let pools = parse_zpool_json(REAL_ZPOOL_JSON_FIXTURE).expect("valid zpool JSON");
        assert_eq!(pools.len(), 2);
        let mirror = pools
            .iter()
            .find(|pool| pool.name == "iodynetestm")
            .unwrap();
        assert_eq!(mirror.health, "ONLINE");
        assert_eq!(mirror.vdevs.len(), 3);
        let group = mirror
            .vdevs
            .iter()
            .find(|vdev| vdev.name == "mirror-0")
            .unwrap();
        assert_eq!(group.vdev_type, "mirror");
        assert_eq!(group.children.len(), 3);
        assert_eq!(
            leaf_allocations_named(mirror),
            [
                ("a", 267264),
                ("b", 267264),
                ("g", 0),
                ("h", 0),
                ("i", 267264)
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            mirror
                .leaf_vdevs()
                .into_iter()
                .map(|(leaf, _)| (leaf.name.as_str(), leaf.section))
                .collect::<std::collections::HashMap<_, _>>()["g"],
            ZfsVdevSection::Cache
        );
        assert_eq!(
            mirror
                .leaf_vdevs()
                .into_iter()
                .map(|(leaf, _)| (leaf.name.as_str(), leaf.section))
                .collect::<std::collections::HashMap<_, _>>()["h"],
            ZfsVdevSection::Spare
        );
        let raidz = pools
            .iter()
            .find(|pool| pool.name == "iodynetestr")
            .unwrap();
        let group = raidz
            .vdevs
            .iter()
            .find(|vdev| vdev.name == "raidz1-0")
            .unwrap();
        assert_eq!(group.vdev_type, "raidz");
        assert_eq!(
            leaf_allocations_named(raidz),
            [("c", 111616), ("d", 111616), ("e", 111616), ("f", 0)]
                .into_iter()
                .collect()
        );
        assert!(raidz
            .leaf_vdevs()
            .iter()
            .any(|(leaf, _)| leaf.name == "f" && leaf.section == ZfsVdevSection::Log));
        assert!(parse_zpool_json("not json").is_none());
    }

    #[test]
    fn parses_real_text_fallback_mirror_raidz_log_cache_and_spare() {
        let pools = parse_zpool_text(REAL_ZPOOL_TEXT_FIXTURE);
        assert_eq!(pools.len(), 2);
        let mirror = &pools[0];
        assert_eq!(mirror.name, "iodynetestm");
        assert_eq!(mirror.vdevs.len(), 3);
        assert_eq!(mirror.vdevs[0].name, "mirror-0");
        assert_eq!(mirror.vdevs[0].children.len(), 3);
        assert_eq!(mirror.vdevs[0].vdev_type, "mirror");
        assert_eq!(
            leaf_allocations_named(mirror),
            [
                ("a", 267264),
                ("b", 267264),
                ("g", 0),
                ("h", 0),
                ("i", 267264)
            ]
            .into_iter()
            .collect()
        );
        let sections: std::collections::HashMap<_, _> = mirror
            .leaf_vdevs()
            .into_iter()
            .map(|(leaf, _)| (leaf.name.as_str(), leaf.section))
            .collect();
        assert_eq!(sections["g"], ZfsVdevSection::Cache);
        assert_eq!(sections["h"], ZfsVdevSection::Spare);
        assert_eq!(
            mirror
                .leaf_vdevs()
                .iter()
                .find(|(leaf, _)| leaf.name == "h")
                .unwrap()
                .0
                .health,
            "AVAIL"
        );

        let raidz = &pools[1];
        assert_eq!(raidz.name, "iodynetestr");
        assert_eq!(raidz.vdevs[0].vdev_type, "raidz");
        assert_eq!(raidz.vdevs[0].children.len(), 3);
        assert_eq!(
            leaf_allocations_named(raidz),
            [("c", 111616), ("d", 111616), ("e", 111616), ("f", 0)]
                .into_iter()
                .collect()
        );
        assert_eq!(
            raidz
                .leaf_vdevs()
                .iter()
                .find(|(leaf, _)| leaf.name == "f")
                .unwrap()
                .0
                .section,
            ZfsVdevSection::Log
        );
    }

    #[test]
    fn parses_real_optane_stripe_from_json_and_text() {
        let json_pools = parse_zpool_json(OPTANE_JSON_FIXTURE).unwrap();
        let text_pools = parse_zpool_text(OPTANE_TEXT_FIXTURE);
        for pool in [&json_pools[0], &text_pools[0]] {
            assert_eq!(pool.name, "optane");
            assert_eq!(pool.health, "ONLINE");
            assert_eq!(
                pool.leaf_vdevs()
                    .iter()
                    .map(|(leaf, _)| leaf.name.as_str())
                    .collect::<std::collections::HashSet<_>>(),
                ["sdc1", "sdd1", "sde2"].into_iter().collect()
            );
        }
        assert_eq!(
            leaf_allocations_named(&json_pools[0]),
            [
                ("sdc1", 24_128_602_112),
                ("sdd1", 24_020_709_376),
                ("sde2", 36_565_995_520)
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            leaf_allocations_named(&text_pools[0]),
            [
                ("sdc1", 24_127_934_464),
                ("sdd1", 24_019_652_608),
                ("sde2", 36_566_188_032)
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn matches_zfs_pool_by_root_or_nested_dataset_source() {
        let pools = parse_zpool_text(OPTANE_TEXT_FIXTURE);
        assert_eq!(pool_for_dataset("optane", &pools).unwrap().name, "optane");
        assert_eq!(
            pool_for_dataset("optane/Projects/foo", &pools)
                .unwrap()
                .name,
            "optane"
        );
        assert!(pool_for_dataset("optane-old/Projects", &pools).is_none());
    }
}
