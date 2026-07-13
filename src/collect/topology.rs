use std::collections::BTreeSet;

use serde::Serialize;

use super::{FsTick, VolumeTick};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopologyEdge {
    pub kind: &'static str,
    pub from: String,
    pub to: String,
}

/// Return machine-readable storage relationships. Display strings are built
/// elsewhere so JSON consumers never have to parse arrows or labels.
pub fn relationships(filesystems: &[FsTick], volumes: &VolumeTick) -> Vec<TopologyEdge> {
    let mut edges = BTreeSet::new();
    for fs in filesystems {
        let source = device_name(&fs.device).to_string();
        edges.insert(("mount_backed_by", fs.mount.clone(), source.clone()));
        if let Some(parent) = partition_parent(&source) {
            edges.insert(("partition_of", source.clone(), parent));
        }
        #[cfg(target_os = "linux")]
        for slave in stacked_members(&source) {
            edges.insert(("block_device_backed_by", source.clone(), slave));
        }
    }
    for array in &volumes.mdraid {
        for member in &array.members {
            edges.insert((
                "raid_member_of",
                device_name(&member.device).to_string(),
                device_name(&array.name).to_string(),
            ));
        }
    }
    for container in &volumes.containers {
        for volume in &container.volumes {
            edges.insert(("apfs_volume_of", volume.bsd.clone(), container.bsd.clone()));
        }
        if let Some(store) = &container.physical_store {
            edges.insert((
                "apfs_container_backed_by",
                container.bsd.clone(),
                device_name(store).to_string(),
            ));
        }
    }
    edges
        .into_iter()
        .map(|(kind, from, to)| TopologyEdge { kind, from, to })
        .collect()
}

pub fn device_name(value: &str) -> &str {
    value.strip_prefix("/dev/").unwrap_or(value)
}

fn partition_parent(name: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let path = std::fs::canonicalize(format!("/sys/class/block/{name}")).ok()?;
        if !path.join("partition").is_file() {
            return None;
        }
        return path
            .parent()?
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
    }
    #[cfg(target_os = "macos")]
    {
        let suffix = name.strip_prefix("disk")?;
        let digits = suffix.chars().take_while(|c| c.is_ascii_digit()).count();
        (digits > 0 && suffix[digits..].starts_with('s'))
            .then(|| format!("disk{}", &suffix[..digits]))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = name;
        None
    }
}

#[cfg(target_os = "linux")]
fn stacked_members(name: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(format!("/sys/class/block/{name}/slaves")) else {
        return Vec::new();
    };
    let mut members: Vec<_> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    members.sort();
    members.dedup();
    members
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::volumes::{MdRaidArray, MdRaidMember};

    #[test]
    fn emits_mount_and_raid_edges_in_stable_order() {
        let fs = FsTick {
            mount: "/data".into(),
            device: "/dev/md0".into(),
            fs_type: "ext4".into(),
            size_bytes: 0,
            used_bytes: 0,
            avail_bytes: 0,
            inode_pct: None,
            is_removable: false,
            is_system: false,
        };
        let volumes = VolumeTick {
            mdraid: vec![MdRaidArray {
                name: "md0".into(),
                members: vec![MdRaidMember {
                    device: "sda1".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let edges = relationships(&[fs], &volumes);
        assert!(edges.iter().any(|edge| edge.kind == "mount_backed_by"));
        assert!(edges.iter().any(|edge| edge.kind == "raid_member_of"));
    }
}
