use std::env;
use std::io::{self, Write};

use anyhow::{bail, Result};

mod app;
mod collect;
mod config;
mod screen;
mod ui;

#[derive(Debug)]
enum Command {
    Run,
    Diag,
    Help,
    Version,
}

fn main() -> Result<()> {
    match parse_args(env::args().skip(1))? {
        Command::Run => app::run(),
        Command::Diag => match run_diag() {
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe) =>
            {
                Ok(())
            }
            result => result,
        },
        Command::Help => {
            println!("{}", help_text());
            Ok(())
        }
        Command::Version => {
            println!("iodyne {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command> {
    let mut command = Command::Run;
    for arg in args {
        command = match arg.as_str() {
            "--diag" => Command::Diag,
            "-h" | "--help" => Command::Help,
            "-V" | "--version" => Command::Version,
            _ => bail!("unexpected argument: {arg}\n\n{}", help_text()),
        };
    }
    Ok(command)
}

fn help_text() -> &'static str {
    "Live per-device disk IO, latency, topology, and health TUI\n\nUsage: iodyne [--diag]\n\nOptions:\n      --diag     Print collected state and exit without launching the TUI\n  -h, --help     Print help\n  -V, --version  Print version"
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
    writeln!(
        out,
        "  VFS event paths status={:?}",
        latency.vfs_path_status()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_supported_flags() {
        assert!(matches!(parse_args(args(&[])).unwrap(), Command::Run));
        assert!(matches!(
            parse_args(args(&["--diag"])).unwrap(),
            Command::Diag
        ));
        assert!(matches!(
            parse_args(args(&["--help"])).unwrap(),
            Command::Help
        ));
        assert!(matches!(
            parse_args(args(&["-V"])).unwrap(),
            Command::Version
        ));
    }

    #[test]
    fn rejects_unknown_flags_with_help() {
        let error = parse_args(args(&["--wat"])).unwrap_err().to_string();
        assert!(error.contains("unexpected argument: --wat"));
        assert!(error.contains("Usage: iodyne [--diag]"));
    }
}
