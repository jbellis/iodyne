//! Formatting + small UI helpers shared across tabs.

use std::sync::atomic::{AtomicU8, Ordering};

use ratatui::style::Color;
use serde::{Deserialize, Serialize};

use crate::ui::palette as p;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnitMode {
    Binary,
    Decimal,
}

impl Default for UnitMode {
    fn default() -> Self {
        Self::Binary
    }
}

impl UnitMode {
    pub fn label(self) -> &'static str {
        match self {
            UnitMode::Binary => "binary (KiB/MiB)",
            UnitMode::Decimal => "decimal (KB/MB)",
        }
    }

    pub fn toggle(self) -> Self {
        match self {
            UnitMode::Binary => UnitMode::Decimal,
            UnitMode::Decimal => UnitMode::Binary,
        }
    }
}

static UNIT_MODE: AtomicU8 = AtomicU8::new(0);

pub fn set_unit_mode(mode: UnitMode) {
    UNIT_MODE.store(
        match mode {
            UnitMode::Binary => 0,
            UnitMode::Decimal => 1,
        },
        Ordering::Relaxed,
    );
}

pub fn unit_mode() -> UnitMode {
    match UNIT_MODE.load(Ordering::Relaxed) {
        1 => UnitMode::Decimal,
        _ => UnitMode::Binary,
    }
}

/// Byte formatter. Defaults to binary units (TiB / GiB / MiB / KiB / B);
/// decimal units are available through persisted settings.
pub fn fmt_size(b: u64) -> String {
    match unit_mode() {
        UnitMode::Binary => fmt_size_binary(b),
        UnitMode::Decimal => fmt_size_decimal(b),
    }
}

fn fmt_size_binary(b: u64) -> String {
    const TIB: u64 = 1 << 40;
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    const KIB: u64 = 1 << 10;
    if b >= TIB {
        format!("{:.1} TiB", b as f64 / TIB as f64)
    } else if b >= GIB {
        format!("{:.0} GiB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.0} MiB", b as f64 / MIB as f64)
    } else if b >= KIB {
        format!("{:.0} KiB", b as f64 / KIB as f64)
    } else {
        format!("{} B", b)
    }
}

fn fmt_size_decimal(b: u64) -> String {
    const TB: u64 = 1_000_000_000_000;
    const GB: u64 = 1_000_000_000;
    const MB: u64 = 1_000_000;
    const KB: u64 = 1_000;
    if b >= TB {
        format!("{:.1} TB", b as f64 / TB as f64)
    } else if b >= GB {
        format!("{:.0} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.0} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.0} KB", b as f64 / KB as f64)
    } else {
        format!("{} B", b)
    }
}

/// Bytes-per-second formatter for IO rates.
pub fn fmt_rate(bps: f64) -> String {
    match unit_mode() {
        UnitMode::Binary => fmt_rate_binary(bps),
        UnitMode::Decimal => fmt_rate_decimal(bps),
    }
}

fn fmt_rate_binary(bps: f64) -> String {
    const MIB: f64 = 1_048_576.0;
    const KIB: f64 = 1024.0;
    if bps < 1.0 {
        return "   -- ".to_string();
    }
    if bps >= MIB {
        format!("{:>5} MiB/s", pretty_amount(bps / MIB))
    } else if bps >= KIB {
        format!("{:>5} KiB/s", pretty_amount(bps / KIB))
    } else {
        format!("{:>5.0}  B/s", bps)
    }
}

fn fmt_rate_decimal(bps: f64) -> String {
    if bps < 1.0 {
        return "   -- ".to_string();
    }
    if bps >= 1_000_000.0 {
        format!("{:>5.1} MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:>5.1} KB/s", bps / 1_000.0)
    } else {
        format!("{:>5.0}  B/s", bps)
    }
}

fn pretty_amount(v: f64) -> String {
    if v >= 10.0 || (v.round() - v).abs() < 0.05 {
        format!("{:.0}", v)
    } else {
        format!("{:.1}", v)
    }
}

pub fn pad_right(s: &str, n: usize) -> String {
    let len = s.chars().count();
    if len >= n {
        s.chars().take(n).collect()
    } else {
        let mut out = s.to_string();
        out.push_str(&" ".repeat(n - len));
        out
    }
}

pub fn pad_left(s: &str, n: usize) -> String {
    let len = s.chars().count();
    if len >= n {
        s.chars().take(n).collect()
    } else {
        let mut out = " ".repeat(n - len);
        out.push_str(s);
        out
    }
}

/// `green < 80, yellow 80-89, red >= 90` — matches JSX usage-bar thresholds.
pub fn usage_color(used_pct: u32) -> Color {
    if used_pct >= 90 {
        p::RED
    } else if used_pct >= 80 {
        p::YELLOW
    } else {
        p::FG
    }
}

/// Same thresholds, but returns the bar fill color (green when ok).
pub fn usage_bar_color(used_pct: u32) -> Color {
    if used_pct >= 90 {
        p::RED
    } else if used_pct >= 80 {
        p::YELLOW
    } else {
        p::GREEN
    }
}
