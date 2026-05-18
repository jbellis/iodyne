//! macOS enrichment via `system_profiler -json`.
//!
//! `SPNVMeDataType`, `SPSerialATADataType`, and `SPUSBDataType` each report
//! one entry per *physical controller* with nested `volumes` for the
//! partitions / containers that live on it. We pull model, firmware,
//! serial, SMART status, removability, and total size from each entry.
//!
//! `system_profiler` is slow (~1–2s per data type), so the caller should
//! cache results and refresh on a long cadence (~30s), not the 1Hz UI tick.

use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct MacDevice {
    pub bsd_name: String, // "disk0"
    pub controller_kind: ControllerKind,
    pub model: String,
    pub firmware: Option<String>,
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub removable: bool,
    pub smart_ok: Option<bool>, // None = controller doesn't report SMART
    pub protocol: String,       // "PCIe / NVMe", "USB", "SATA"
    /// Reserved — surfaced once the Devices DETAIL panel grows a trim row.
    #[allow(dead_code)]
    pub trim: Option<bool>,
    /// Reserved — needed when we attribute used bytes per-volume instead
    /// of taking max-used across the container.
    #[allow(dead_code)]
    pub volumes: Vec<MacVolume>,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // Filled in by parse_device for future per-volume attribution.
pub struct MacVolume {
    pub bsd_name: String, // "disk0s2", "disk3s5"
    pub kind: String,     // "Apple_APFS", "Apple_APFS_ISC", etc.
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ControllerKind {
    Nvme,
    Sata,
    Usb,
    #[default]
    Unknown,
}

pub fn collect() -> Vec<MacDevice> {
    let mut out = Vec::new();
    out.extend(query(ControllerKind::Nvme, "SPNVMeDataType", "PCIe / NVMe"));
    out.extend(query(ControllerKind::Sata, "SPSerialATADataType", "SATA"));
    out.extend(query(ControllerKind::Usb, "SPUSBDataType", "USB"));
    out
}

fn query(kind: ControllerKind, data_type: &str, protocol: &str) -> Vec<MacDevice> {
    let Ok(out) = Command::new("system_profiler")
        .args([data_type, "-json"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let Ok(root): Result<serde_json::Value, _> = serde_json::from_slice(&out.stdout) else {
        return Vec::new();
    };
    let mut devices = Vec::new();
    let Some(arr) = root.get(data_type).and_then(|v| v.as_array()) else {
        return devices;
    };
    for entry in arr {
        // For NVMe / SATA, items live under "_items"; for USB the tree is
        // recursive (_items contains hubs containing devices). Walk both.
        walk(entry, kind, protocol, &mut devices);
    }
    devices
}

fn walk(node: &serde_json::Value, kind: ControllerKind, protocol: &str, out: &mut Vec<MacDevice>) {
    if let Some(items) = node.get("_items").and_then(|v| v.as_array()) {
        for it in items {
            walk(it, kind, protocol, out);
        }
    }
    // A storage device has either a bsd_name (NVMe/SATA top-level) or
    // a Media subtree (USB mass storage exposes the storage media under
    // "Media"). Treat both as devices when they carry a bsd_name.
    if let Some(media) = node.get("Media").and_then(|v| v.as_array()) {
        for m in media {
            if let Some(d) = parse_device(m, kind, protocol) {
                out.push(d);
            }
        }
    }
    if node.get("bsd_name").is_some() {
        if let Some(d) = parse_device(node, kind, protocol) {
            out.push(d);
        }
    }
}

fn parse_device(v: &serde_json::Value, kind: ControllerKind, protocol: &str) -> Option<MacDevice> {
    let bsd_name = v.get("bsd_name")?.as_str()?.to_string();
    let model = v
        .get("device_model")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("_name").and_then(|x| x.as_str()))
        .unwrap_or("Unknown")
        .trim()
        .to_string();
    let firmware = v
        .get("device_revision")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let serial = v
        .get("device_serial")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let size_bytes = v.get("size_in_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
    let removable = matches!(
        v.get("removable_media").and_then(|x| x.as_str()),
        Some("yes") | Some("Yes") | Some("YES")
    );
    let smart_ok = v.get("smart_status").and_then(|x| x.as_str()).map(|s| {
        matches!(
            s,
            "Verified" | "verified" | "OK" | "Ok" | "Passed" | "passed"
        )
    });
    let trim = v
        .get("spnvme_trim_support")
        .and_then(|x| x.as_str())
        .map(|s| matches!(s, "Yes" | "yes" | "YES"));

    let volumes = v
        .get("volumes")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|vol| {
                    let bsd = vol.get("bsd_name").and_then(|x| x.as_str())?;
                    let kind = vol
                        .get("iocontent")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let size = vol
                        .get("size_in_bytes")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0);
                    Some(MacVolume {
                        bsd_name: bsd.to_string(),
                        kind,
                        size_bytes: size,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(MacDevice {
        bsd_name,
        controller_kind: kind,
        model,
        firmware,
        serial,
        size_bytes,
        removable,
        smart_ok,
        protocol: protocol.to_string(),
        trim,
        volumes,
    })
}

/// Builds a `disk3 → disk0` style map from synthesized APFS containers
/// to their physical disks. Walks `diskutil list -plist` output.
///
/// `system_profiler` lists physical disks (disk0); sysinfo mounts live on
/// volumes inside synthesized containers (disk3s5). This map closes the gap.
pub fn container_to_physical_map() -> std::collections::HashMap<String, String> {
    let Ok(out) = Command::new("diskutil").args(["list", "-plist"]).output() else {
        return Default::default();
    };
    if !out.status.success() {
        return Default::default();
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // The plist is XML; rather than pull in a plist parser, we parse the
    // plain-text `diskutil list` form instead — it has explicit
    // "Physical Store diskNsN" lines we can grep.
    let Ok(plain) = Command::new("diskutil").arg("list").output() else {
        let _ = s;
        return Default::default();
    };
    let text = String::from_utf8_lossy(&plain.stdout);

    let mut map = std::collections::HashMap::new();
    let mut current_synth: Option<String> = None;
    for line in text.lines() {
        let line = line.trim_start();
        // Headers look like: "/dev/disk3 (synthesized):"
        if let Some(rest) = line.strip_prefix("/dev/") {
            current_synth = None;
            if let Some(end) = rest.find(' ') {
                let name = &rest[..end];
                if rest.contains("(synthesized)") {
                    current_synth = Some(name.to_string());
                }
            }
            continue;
        }
        if let (Some(synth), Some(idx)) = (current_synth.as_ref(), line.find("Physical Store ")) {
            let after = &line[idx + "Physical Store ".len()..];
            let phys_partition: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            // disk0s2 → disk0
            let phys: String = phys_partition
                .chars()
                .scan(false, |seen_digit, c| {
                    if c.is_ascii_digit() {
                        *seen_digit = true;
                        Some(c)
                    } else if *seen_digit {
                        None
                    } else {
                        Some(c)
                    }
                })
                .collect();
            if !phys.is_empty() {
                map.insert(synth.clone(), phys);
            }
        }
    }
    map
}
