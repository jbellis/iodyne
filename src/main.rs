use anyhow::Result;
use clap::Parser;

mod app;
mod collect;
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
    /// Start on a specific tab (overview, devices, volumes, fs, io, smart, hot, insights).
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
        return run_diag();
    }
    app::run(app::Options { start_tab: cli.tab })
}

fn run_diag() -> Result<()> {
    let devices = collect::devices::collect();
    println!("=== Devices ({}) ===", devices.len());
    for d in &devices {
        println!(
            "  {}  kind={:?}  size={}  used={}  model={:?}  smart={:?}",
            d.name, d.kind, d.size_bytes, d.used_bytes, d.model, d.smart_ok
        );
    }
    let total: u64 = devices.iter().map(|d| d.size_bytes).sum();
    let used: u64 = devices.iter().map(|d| d.used_bytes).sum();
    let pct = if total > 0 {
        (used as f64 / total as f64 * 100.0).round() as u32
    } else {
        0
    };
    println!("  TOTAL: size={}  used={}  pct={}%", total, used, pct);

    #[cfg(target_os = "macos")]
    {
        println!("\n=== container_to_physical map ===");
        let cmap = collect::macos::container_to_physical_map();
        if cmap.is_empty() {
            println!("  (empty)");
        }
        for (synth, phys) in &cmap {
            println!("  {} -> {}", synth, phys);
        }
    }

    println!(
        "\n=== Filesystems ({}) ===",
        collect::filesystems::collect().len()
    );
    for m in collect::filesystems::collect() {
        println!(
            "  {} -> {}  ({})  size={}  used={}",
            m.device, m.mount, m.fs_type, m.size_bytes, m.used_bytes
        );
    }

    Ok(())
}
