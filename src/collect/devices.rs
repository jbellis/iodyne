//! Cross-platform device enumeration.
//!
//! - **macOS**: `system_profiler -json` for model / firmware / serial /
//!   SMART / removability, plus `diskutil list` to map APFS-container
//!   volumes back to the physical disk they live on. sysinfo provides
//!   used-byte attribution per mount.
//! - **Other**: `sysinfo::Disks` as the sole source; metadata fields are
//!   left as placeholders until a platform-specific collector lands.

use std::collections::HashMap;

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
    pub firmware: Option<String>,
    pub serial: Option<String>,
    pub smart_ok: Option<bool>,
    pub idle: bool,
}

pub fn collect() -> Vec<DeviceTick> {
    let mounts_used = sysinfo_mount_used();

    #[cfg(target_os = "macos")]
    {
        let mut macs = macos::collect();
        // Apple's internal SSD reports identical model entries per
        // controller occasionally; dedupe by bsd_name.
        macs.sort_by(|a, b| a.bsd_name.cmp(&b.bsd_name));
        macs.dedup_by(|a, b| a.bsd_name == b.bsd_name);

        let cmap = macos::container_to_physical_map();
        let mut used_by_phys: HashMap<String, u64> = HashMap::new();
        for (mount_disk, used) in &mounts_used {
            let phys = cmap.get(mount_disk).cloned().unwrap_or(mount_disk.clone());
            let entry = used_by_phys.entry(phys).or_insert(0);
            if *used > *entry {
                *entry = *used;
            }
        }

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
                    used_bytes: used,
                    is_removable: m.removable,
                    firmware: m.firmware,
                    serial: m.serial,
                    smart_ok: m.smart_ok,
                    idle: m.size_bytes == 0,
                }
            })
            .collect();
        out.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        return out;
    }

    #[cfg(target_os = "linux")]
    {
        let mut used_by_device: HashMap<String, u64> = HashMap::new();
        for (mount_disk, used) in &mounts_used {
            let entry = used_by_device.entry(mount_disk.clone()).or_insert(0);
            // Linux mounts each partition separately — sum used across
            // partitions so the whole-disk total reflects actual usage.
            *entry = entry.saturating_add(*used);
        }
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
                    DeviceKind::Hdd | DeviceKind::Ssd => "SATA / internal".to_string(),
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
        out.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        return out;
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
        out.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        out
    }
}

/// Fast path: re-reads sysinfo and updates `used_bytes` on an existing
/// device list without redoing the slow `system_profiler` enrichment.
///
/// On macOS we re-use the cached container→physical map. If the topology
/// changed (drive plugged in / out) the next full `collect()` picks it up.
pub fn refresh_usage(devices: &mut [DeviceTick]) {
    let mounts = sysinfo_mount_used();

    #[cfg(target_os = "macos")]
    let cmap = macos::container_to_physical_map();

    for d in devices.iter_mut() {
        // macOS APFS shares free across volumes → max-used per
        // physical. Linux mounts partitions independently → sum.
        #[cfg(target_os = "linux")]
        let mut used_sum = 0u64;
        let mut used_max = 0u64;
        for (mount_disk, mu) in &mounts {
            #[cfg(target_os = "macos")]
            let phys = cmap.get(mount_disk).cloned().unwrap_or_else(|| mount_disk.clone());
            #[cfg(not(target_os = "macos"))]
            let phys = mount_disk.clone();
            if phys == d.name {
                if *mu > used_max {
                    used_max = *mu;
                }
                #[cfg(target_os = "linux")]
                {
                    used_sum = used_sum.saturating_add(*mu);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            d.used_bytes = used_sum;
        }
        #[cfg(not(target_os = "linux"))]
        {
            d.used_bytes = used_max;
        }
    }
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
fn sysinfo_mount_used() -> Vec<(String, u64)> {
    let disks = Disks::new_with_refreshed_list();
    #[cfg(target_os = "macos")]
    let mount_table = macos_mount_table();

    let mut by_disk: HashMap<String, u64> = HashMap::new();
    for d in disks.list() {
        let used = d.total_space().saturating_sub(d.available_space());
        if used == 0 {
            continue;
        }
        #[cfg(target_os = "macos")]
        let device_source = {
            let mp = d.mount_point().to_string_lossy().to_string();
            match mount_table.get(&mp) {
                Some(dev) => dev.clone(),
                None => continue, // virtual fs / devfs / unmapped
            }
        };
        #[cfg(not(target_os = "macos"))]
        let device_source = d.name().to_string_lossy().to_string();

        let name = short_name(&device_source);
        let entry = by_disk.entry(name).or_insert(0);
        // APFS containers report the same free across all volumes — max
        // avoids over-counting. On Linux the caller sums instead.
        if used > *entry {
            *entry = used;
        }
    }
    by_disk.into_iter().collect()
}

#[cfg(target_os = "macos")]
fn macos_mount_table() -> HashMap<String, String> {
    use std::process::Command;
    let Ok(out) = Command::new("/sbin/mount").output() else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = HashMap::new();
    for line in text.lines() {
        // Each line: "<device> on <mount> (fs, opts...)"
        let Some(on_idx) = line.find(" on ") else { continue };
        let device = line[..on_idx].trim().to_string();
        let after = &line[on_idx + 4..];
        let Some(paren) = after.rfind(" (") else { continue };
        let mount = after[..paren].trim().to_string();
        map.insert(mount, device);
    }
    map
}

fn short_name(raw: &str) -> String {
    let s = raw.trim_start_matches("/dev/");
    if let Some(rest) = s.strip_prefix("disk") {
        let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !n.is_empty() {
            return format!("disk{}", n);
        }
    }
    if let Some(rest) = s.strip_prefix("nvme") {
        let mut out = String::from("nvme");
        for c in rest.chars() {
            if c.is_ascii_digit() || c == 'n' {
                out.push(c);
            } else {
                break;
            }
        }
        return out;
    }
    if s.starts_with("sd") && s.len() >= 3 {
        return s.chars().take_while(|c| !c.is_ascii_digit()).collect();
    }
    s.to_string()
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
