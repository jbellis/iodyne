use std::collections::HashMap;

#[cfg(target_os = "macos")]
pub(crate) fn macos_mount_table() -> HashMap<String, String> {
    use std::process::Command;

    let Ok(out) = Command::new("/sbin/mount").output() else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_macos_mount_table(&text)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_macos_mount_table(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        // Each line: "<device> on <mount> (fs, opts...)"
        let Some(on_idx) = line.find(" on ") else {
            continue;
        };
        let device = line[..on_idx].trim();
        let after = &line[on_idx + 4..];
        let Some(paren) = after.rfind(" (") else {
            continue;
        };
        let mount = after[..paren].trim();
        map.insert(mount.to_string(), device.to_string());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_mount_table_sources_by_mount_point() {
        let table = parse_macos_mount_table(
            "/dev/disk3s1s1 on / (apfs, sealed, local)\n\
             /dev/disk3s5 on /System/Volumes/Data (apfs, local)\n\
             map auto_home on /System/Volumes/Data/home (autofs, automounted)\n",
        );

        assert_eq!(table.get("/").map(String::as_str), Some("/dev/disk3s1s1"));
        assert_eq!(
            table.get("/System/Volumes/Data").map(String::as_str),
            Some("/dev/disk3s5")
        );
        assert_eq!(
            table.get("/System/Volumes/Data/home").map(String::as_str),
            Some("map auto_home")
        );
    }
}
