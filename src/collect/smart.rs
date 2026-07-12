//! SMART attribute collector via the `smartctl` binary.
//!
//! If `smartctl` is on PATH (`brew install smartmontools` on macOS),
//! `smartctl -A --json <device>` returns NVMe SMART data as JSON. We
//! parse the headline fields: temperature, power-on hours, power cycles,
//! and the NVMe-specific data points (percentage_used, available_spare,
//! data_units_*).
//!
//! When smartctl is absent the tab falls back to whatever each platform
//! exposes through cheaper paths (diskutil "SMART Status: Verified" on
//! macOS, already wired into `DeviceTick.smart_ok`).

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct SmartTick {
    /// Reserved for cross-device diff views — not read in the per-device
    /// SMART panel that looks up its tick by key.
    #[allow(dead_code)]
    pub device: String,
    pub temperature_c: Option<i16>,
    pub power_on_hours: Option<u64>,
    pub power_cycles: Option<u64>,
    pub percentage_used: Option<u8>,
    pub available_spare: Option<u8>,
    pub data_units_read: Option<u64>,
    pub data_units_written: Option<u64>,
    /// Free-form attributes for ATA drives — name → (raw, value).
    pub ata_attrs: Vec<AtaAttr>,
}

#[derive(Debug, Clone, Default)]
pub struct AtaAttr {
    pub id: u8,
    pub name: String,
    pub value: u32,
    pub worst: u32,
    pub thresh: Option<u32>,
    pub raw: String,
}

pub struct SmartCollector {
    /// `None` until first probe; `Some(false)` if probe failed.
    have_smartctl: Option<bool>,
    pub by_device: HashMap<String, SmartTick>,
    last_refresh: Instant,
}

impl SmartCollector {
    pub fn new() -> Self {
        Self {
            have_smartctl: None,
            by_device: HashMap::new(),
            last_refresh: Instant::now() - Duration::from_secs(3600),
        }
    }

    /// Called periodically (every 5 minutes per the technical doc —
    /// polling more often shortens drive life on some models). Refreshes
    /// SMART data for every device in the list.
    pub fn refresh_if_due(&mut self, devices: &[crate::collect::DeviceTick]) {
        if self.have_smartctl.is_none() {
            self.have_smartctl = Some(probe_smartctl());
        }
        if !matches!(self.have_smartctl, Some(true)) {
            return;
        }
        if self.last_refresh.elapsed() < Duration::from_secs(300) {
            return;
        }
        self.last_refresh = Instant::now();
        for d in devices {
            if let Some(tick) = query_device(&d.name) {
                self.by_device.insert(d.name.clone(), tick);
            }
        }
    }
}

fn probe_smartctl() -> bool {
    Command::new("smartctl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    // We deliberately don't print to stderr on failure — the SMART tab
    // surfaces the missing-binary state via its own banner.
}

fn query_device(name: &str) -> Option<SmartTick> {
    let dev = format!("/dev/{}", name);
    let out = Command::new("smartctl")
        .args(["-A", "--json", &dev])
        .output()
        .ok()?;
    // smartctl returns nonzero exit on warning-class issues but still
    // emits valid JSON; parse the output regardless of status.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;

    let mut tick = SmartTick {
        device: name.to_string(),
        ..Default::default()
    };

    // NVMe path.
    if let Some(log) = v.get("nvme_smart_health_information_log") {
        tick.temperature_c = log
            .get("temperature")
            .and_then(|x| x.as_i64())
            .map(|n| n as i16);
        tick.power_on_hours = log.get("power_on_hours").and_then(|x| x.as_u64());
        tick.power_cycles = log.get("power_cycles").and_then(|x| x.as_u64());
        tick.percentage_used = log
            .get("percentage_used")
            .and_then(|x| x.as_u64())
            .map(|n| n as u8);
        tick.available_spare = log
            .get("available_spare")
            .and_then(|x| x.as_u64())
            .map(|n| n as u8);
        tick.data_units_read = log.get("data_units_read").and_then(|x| x.as_u64());
        tick.data_units_written = log.get("data_units_written").and_then(|x| x.as_u64());
    }

    // ATA / SATA path.
    if let Some(attrs) = v
        .get("ata_smart_attributes")
        .and_then(|x| x.get("table"))
        .and_then(|x| x.as_array())
    {
        for a in attrs {
            let Some(id) = a.get("id").and_then(|x| x.as_u64()) else {
                continue;
            };
            let name = a
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let value = a.get("value").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let worst = a.get("worst").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let thresh = a.get("thresh").and_then(|x| x.as_u64()).map(|n| n as u32);
            let raw = a
                .get("raw")
                .and_then(|x| x.get("string"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            tick.ata_attrs.push(AtaAttr {
                id: id as u8,
                name,
                value,
                worst,
                thresh,
                raw,
            });
        }
    }
    Some(tick)
}
