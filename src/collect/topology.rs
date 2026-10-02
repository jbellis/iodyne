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
    let btrfs_members = |source: &str| {
        #[cfg(target_os = "linux")]
        {
            let kernel_name = super::btrfs::kernel_name(source);
            super::btrfs::members(&kernel_name)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = source;
            None
        }
    };
    relationships_with(
        filesystems,
        volumes,
        &btrfs_members,
        &partition_parent,
        &stacked_members,
    )
}

fn relationships_with(
    filesystems: &[FsTick],
    volumes: &VolumeTick,
    btrfs_members: &dyn Fn(&str) -> Option<Vec<String>>,
    partition_parent: &dyn Fn(&str) -> Option<String>,
    stacked_members: &dyn Fn(&str) -> Vec<String>,
) -> Vec<TopologyEdge> {
    let mut edges = BTreeSet::new();
    for fs in filesystems {
        let source = device_name(&fs.device).to_string();
        edges.insert(("mount_backed_by", fs.mount.clone(), source.clone()));
        if fs.fs_type.eq_ignore_ascii_case("zfs") {
            if let Some(pool) = super::volumes::pool_for_dataset(&fs.device, &volumes.zfs) {
                if source != pool.name {
                    edges.insert(("zfs_dataset_of", source.clone(), pool.name.clone()));
                }
            }
        }
        if let Some(parent) = partition_parent(&source) {
            edges.insert(("partition_of", source.clone(), parent));
        }
        for slave in stacked_members(&source) {
            edges.insert(("block_device_backed_by", source.clone(), slave));
        }
        if let Some(members) = btrfs_members(&source) {
            for member in members {
                edges.insert(("mount_backed_by", fs.mount.clone(), member.clone()));
                if let Some(parent) = partition_parent(&member) {
                    edges.insert(("partition_of", member.clone(), parent));
                }
                for slave in stacked_members(&member) {
                    edges.insert(("block_device_backed_by", member.clone(), slave));
                }
            }
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
    for pool in &volumes.zfs {
        for (leaf, groups) in pool.leaf_vdevs() {
            let mut parent = pool.name.clone();
            let mut group_path = Vec::new();
            for group in groups {
                group_path.push(group.name.as_str());
                let group_id = format!("{}/{}", pool.name, group_path.join("/"));
                edges.insert(("zfs_vdev_member_of", group_id.clone(), parent.clone()));
                parent = group_id;
            }
            edges.insert(("zfs_vdev_member_of", leaf.name.clone(), parent));
            // Preserve the public leaf-to-pool relationship alongside the
            // richer vdev-group hierarchy.
            edges.insert(("zfs_member_of", leaf.name.clone(), pool.name.clone()));
            if let Some(parent) = partition_parent(&leaf.name) {
                edges.insert(("partition_of", leaf.name.clone(), parent));
            }
            for slave in stacked_members(&leaf.name) {
                edges.insert(("block_device_backed_by", leaf.name.clone(), slave));
            }
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
        path.parent()?
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
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
    super::devices::stacked_device_members(name).unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn stacked_members(name: &str) -> Vec<String> {
    let _ = name;
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::volumes::{MdRaidArray, MdRaidMember, ZfsPool, ZfsVdev, ZfsVdevSection};

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

    #[test]
    fn emits_btrfs_member_partition_and_stacked_edges() {
        let fs = FsTick {
            mount: "/mnt/optane".into(),
            device: "/dev/sdc".into(),
            fs_type: "btrfs".into(),
            size_bytes: 0,
            used_bytes: 0,
            avail_bytes: 0,
            inode_pct: None,
            is_removable: false,
            is_system: false,
        };
        let volumes = VolumeTick::default();
        let members = |source: &str| {
            (source == "sdc")
                .then(|| vec!["sdc".into(), "sdd".into(), "sde2".into(), "dm-0".into()])
        };
        let parent = |name: &str| (name == "sde2").then(|| "sde".into());
        let slaves = |name: &str| match name {
            "sdc" => vec!["source-slave".into()],
            "dm-0" => vec!["dm-slave".into()],
            _ => Vec::new(),
        };

        let edges = relationships_with(&[fs], &volumes, &members, &parent, &slaves);
        let pairs: BTreeSet<_> = edges
            .iter()
            .map(|edge| (edge.kind, edge.from.as_str(), edge.to.as_str()))
            .collect();
        assert!(pairs.contains(&("mount_backed_by", "/mnt/optane", "sdc")));
        assert!(pairs.contains(&("mount_backed_by", "/mnt/optane", "sdd")));
        assert!(pairs.contains(&("mount_backed_by", "/mnt/optane", "sde2")));
        assert!(pairs.contains(&("partition_of", "sde2", "sde")));
        assert!(pairs.contains(&("block_device_backed_by", "sdc", "source-slave")));
        assert!(pairs.contains(&("block_device_backed_by", "dm-0", "dm-slave")));
    }

    #[test]
    fn emits_zfs_dataset_vdev_partition_and_stacked_edges() {
        let fs = FsTick {
            mount: "/mnt/tank".into(),
            device: "tank/Projects".into(),
            fs_type: "zfs".into(),
            size_bytes: 0,
            used_bytes: 0,
            avail_bytes: 0,
            inode_pct: None,
            is_removable: false,
            is_system: false,
        };
        let volumes = VolumeTick {
            zfs: vec![ZfsPool {
                name: "tank".into(),
                vdevs: vec![ZfsVdev {
                    name: "mirror-0".into(),
                    section: ZfsVdevSection::Data,
                    children: vec![
                        ZfsVdev {
                            name: "sdc1".into(),
                            ..Default::default()
                        },
                        ZfsVdev {
                            name: "sde2".into(),
                            ..Default::default()
                        },
                        ZfsVdev {
                            name: "dm-0".into(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let no_btrfs = |_: &str| None;
        let parent = |name: &str| (name == "sde2").then(|| "sde".into());
        let slaves = |name: &str| match name {
            "dm-0" => vec!["sda".into(), "sdb".into()],
            _ => Vec::new(),
        };

        let edges = relationships_with(&[fs], &volumes, &no_btrfs, &parent, &slaves);
        let pairs: BTreeSet<_> = edges
            .iter()
            .map(|edge| (edge.kind, edge.from.as_str(), edge.to.as_str()))
            .collect();
        assert!(pairs.contains(&("mount_backed_by", "/mnt/tank", "tank/Projects")));
        assert!(pairs.contains(&("zfs_dataset_of", "tank/Projects", "tank")));
        assert!(pairs.contains(&("zfs_member_of", "sdc1", "tank")));
        assert!(pairs.contains(&("zfs_vdev_member_of", "sdc1", "tank/mirror-0")));
        assert!(pairs.contains(&("zfs_vdev_member_of", "tank/mirror-0", "tank")));
        assert!(pairs.contains(&("zfs_vdev_member_of", "sde2", "tank/mirror-0")));
        assert!(pairs.contains(&("partition_of", "sde2", "sde")));
        assert!(pairs.contains(&("zfs_vdev_member_of", "dm-0", "tank/mirror-0")));
        assert!(pairs.contains(&("block_device_backed_by", "dm-0", "sda")));
        assert!(pairs.contains(&("block_device_backed_by", "dm-0", "sdb")));
    }
}
