use std::io::{self, Write};

use anyhow::Result;
use clap::Parser;

mod app;
mod collect;
mod config;
mod insights;
mod tabs;
mod ui;

#[derive(Parser, Debug)]
#[command(
    name = "diskwatch",
    version,
    about = "Single-host disk diagnostics TUI"
)]
struct Cli {
    /// Start on a specific tab (overview, devices, volumes, fs, io, smart, insights).
    #[arg(long)]
    tab: Option<String>,

    /// Print collected state and exit without launching the TUI.
    /// Useful for diagnosing what each collector is seeing.
    #[arg(long)]
    diag: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.diag {
        return match run_diag() {
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe) =>
            {
                Ok(())
            }
            result => result,
        };
    }
    app::run(app::Options { start_tab: cli.tab })
}

fn run_diag() -> Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let latency = collect::ebpf::EbpfLatencyCollector::new();
    writeln!(out, "=== Latency tracing ===")?;
    writeln!(
        out,
        "  latency source={:?}  status={:?}",
        latency.source(),
        latency.status()
    )?;
    writeln!(
        out,
        "  VFS activity source={:?}  status={:?}",
        latency.vfs_source(),
        latency.vfs_status()
    )?;

    let devices = collect::devices::collect();
    writeln!(out, "\n=== Devices ({}) ===", devices.len())?;
    for d in &devices {
        writeln!(
            out,
            "  {}  kind={:?}  size={}  used={}  model={:?}  smart={:?}",
            d.name, d.kind, d.size_bytes, d.used_bytes, d.model, d.smart_ok
        )?;
    }
    let total: u64 = devices.iter().map(|d| d.size_bytes).sum();
    let used: u64 = devices.iter().map(|d| d.used_bytes).sum();
    let pct = if total > 0 {
        (used as f64 / total as f64 * 100.0).round() as u32
    } else {
        0
    };
    writeln!(out, "  TOTAL: size={}  used={}  pct={}%", total, used, pct)?;

    #[cfg(target_os = "macos")]
    {
        writeln!(out, "\n=== container_to_physical map ===")?;
        let cmap = collect::macos::container_to_physical_map();
        if cmap.is_empty() {
            writeln!(out, "  (empty)")?;
        }
        for (synth, phys) in &cmap {
            writeln!(out, "  {} -> {}", synth, phys)?;
        }
    }

    writeln!(
        out,
        "\n=== Filesystems ({}) ===",
        collect::filesystems::collect().len()
    )?;
    for m in collect::filesystems::collect() {
        writeln!(
            out,
            "  {} -> {}  ({})  size={}  used={}",
            m.device, m.mount, m.fs_type, m.size_bytes, m.used_bytes
        )?;
    }

    Ok(())
}
