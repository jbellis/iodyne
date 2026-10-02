//! Linux btrfs member lookup through sysfs.

use std::collections::BTreeSet;
use std::path::Path;

/// Return every sysfs device name for the btrfs filesystem containing `source`.
pub fn members(source: &str) -> Option<Vec<String>> {
    filesystem(source).map(|(_, members)| members)
}

/// Return the filesystem UUID and every sysfs device name for the filesystem
/// containing `source`.
pub fn filesystem(source: &str) -> Option<(String, Vec<String>)> {
    filesystem_in(Path::new("/sys/fs/btrfs"), source)
}

/// Resolve a mount source to the kernel block name used by sysfs.
pub fn kernel_name(device: &str) -> String {
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    if name.starts_with("mapper/") {
        std::fs::read_link(format!("/dev/{name}"))
            .ok()
            .and_then(|target| {
                target
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| name.to_string())
    } else {
        name.to_string()
    }
}

fn filesystem_in(root: &Path, source: &str) -> Option<(String, Vec<String>)> {
    let filesystems = std::fs::read_dir(root).ok()?;

    for filesystem in filesystems.flatten() {
        let uuid = filesystem.file_name().to_string_lossy().into_owned();
        let devices_path = filesystem.path().join("devices");
        let Ok(entries) = std::fs::read_dir(devices_path) else {
            continue;
        };
        let names: Vec<String> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                (name != "features").then_some(name)
            })
            .collect();
        if names.iter().any(|name| name == source) {
            let members = names
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            return Some((uuid, members));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("iodyne-btrfs-{nonce}"))
    }

    #[test]
    fn lookup_returns_sorted_members_and_skips_features() {
        let root = temp_root();
        let devices = root.join("uuid-a/devices");
        fs::create_dir_all(devices.join("features")).unwrap();
        fs::write(devices.join("sde2"), "").unwrap();
        fs::write(devices.join("sdc"), "").unwrap();
        fs::write(devices.join("sdd"), "").unwrap();

        assert_eq!(
            filesystem_in(&root, "sdc"),
            Some((
                "uuid-a".to_string(),
                vec!["sdc".to_string(), "sdd".to_string(), "sde2".to_string()],
            ))
        );
        assert_eq!(filesystem_in(&root, "missing"), None);

        fs::remove_dir_all(root).unwrap();
    }
}
