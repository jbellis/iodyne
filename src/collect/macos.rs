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
    let Ok(out) = Command::new("/usr/sbin/system_profiler")
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

/// Read command plist output through the system plist converter.
pub(crate) fn plist_json(program: &str, args: &[&str]) -> Option<serde_json::Value> {
    use std::process::Stdio;

    let mut source = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let converted = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "-"])
        .stdin(source.stdout.take()?)
        .stderr(Stdio::null())
        .output();
    let status = source.wait().ok()?;
    let converted = converted.ok()?;
    if !status.success() || !converted.status.success() {
        return None;
    }
    serde_json::from_slice(&converted.stdout).ok()
}
