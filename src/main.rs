use std::env;
use std::io::{self, Write};
use std::time::Duration;

use anyhow::{bail, Result};

mod app;
mod collect;
mod config;
mod jsonl;
mod screen;
mod ui;

#[derive(Debug)]
enum Command {
    Run {
        interval: Duration,
        intervals: Option<u64>,
    },
    Jsonl {
        interval: Duration,
        intervals: Option<u64>,
    },
    Diag,
    Help,
    Version,
}

fn main() -> Result<()> {
    match parse_args(env::args().skip(1))? {
        Command::Run {
            interval,
            intervals,
        } => app::run(interval, intervals),
        Command::Jsonl {
            interval,
            intervals,
        } => jsonl::run(interval, intervals),
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
    let mut mode: Option<Command> = None;
    let mut interval = collect::io::DEFAULT_SAMPLE_INTERVAL;
    let mut intervals = None;
    let mut interval_set = false;
    let mut intervals_set = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--jsonl" => set_mode(
                &mut mode,
                Command::Jsonl {
                    interval,
                    intervals,
                },
            )?,
            "--diag" => set_mode(&mut mode, Command::Diag)?,
            "-h" | "--help" => set_mode(&mut mode, Command::Help)?,
            "-V" | "--version" => set_mode(&mut mode, Command::Version)?,
            "--interval-ms" => {
                let value = args.next().ok_or_else(|| {
                    anyhow::anyhow!("--interval-ms requires a value\n\n{}", help_text())
                })?;
                interval = parse_interval(&value)?;
                interval_set = true;
            }
            _ if arg.starts_with("--interval-ms=") => {
                interval = parse_interval(arg.trim_start_matches("--interval-ms="))?;
                interval_set = true;
            }
            "--intervals" => {
                let value = args.next().ok_or_else(|| {
                    anyhow::anyhow!("--intervals requires a value\n\n{}", help_text())
                })?;
                intervals = Some(parse_intervals(&value)?);
                intervals_set = true;
            }
            _ if arg.starts_with("--intervals=") => {
                intervals = Some(parse_intervals(arg.trim_start_matches("--intervals="))?);
                intervals_set = true;
            }
            _ => bail!("unexpected argument: {arg}\n\n{}", help_text()),
        }
    }
    match mode {
        None | Some(Command::Run { .. }) => Ok(Command::Run {
            interval,
            intervals,
        }),
        Some(Command::Jsonl { .. }) => Ok(Command::Jsonl {
            interval,
            intervals,
        }),
        Some(_) if interval_set => {
            bail!(
                "--interval-ms is valid only in TUI or JSONL mode\n\n{}",
                help_text()
            )
        }
        Some(_) if intervals_set => {
            bail!(
                "--intervals is valid only in TUI or JSONL mode\n\n{}",
                help_text()
            )
        }
        Some(command) => Ok(command),
    }
}

fn set_mode(mode: &mut Option<Command>, command: Command) -> Result<()> {
    if mode.is_some() {
        bail!(
            "only one of --jsonl, --diag, --help, or --version may be used\n\n{}",
            help_text()
        );
    }
    *mode = Some(command);
    Ok(())
}

fn parse_interval(value: &str) -> Result<Duration> {
    let millis = value
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid --interval-ms value: {value}"))?;
    let interval = Duration::from_millis(millis);
    if !(app::MIN_SAMPLE_INTERVAL..=app::MAX_SAMPLE_INTERVAL).contains(&interval) {
        bail!("--interval-ms must be between 100 and 10000");
    }
    Ok(interval)
}

fn parse_intervals(value: &str) -> Result<u64> {
    let intervals = value
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid --intervals value: {value}"))?;
    if intervals < 1 {
        bail!("--intervals must be at least 1");
    }
    Ok(intervals)
}

fn help_text() -> &'static str {
    "Live per-device disk IO, latency, topology, and health\n\nUsage: iodyne [--jsonl] [--interval-ms N] [--intervals N]\n       iodyne --diag\n\nOptions:\n      --jsonl          Write one JSON object per line instead of launching the TUI\n      --interval-ms N  Sampling interval for TUI or JSONL mode (100-10000; default 2000)\n      --intervals N    Exit after processing N sampling intervals (TUI or JSONL mode)\n      --diag           Print collected state and exit without launching the TUI\n  -h, --help           Print help\n  -V, --version        Print version"
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
    writeln!(
        out,
        "  FUSE requester attribution status={:?}",
        latency.vfs_fuse_status()
    )?;
    writeln!(
        out,
        "  FUSE PID-0 writeback attribution status={:?}",
        latency.vfs_fuse_writeback_status()
    )?;
    writeln!(
        out,
        "  OverlayFS backing attribution status={:?}",
        latency.vfs_overlay_status()
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
        assert!(matches!(
            parse_args(args(&[])).unwrap(),
            Command::Run { interval, intervals } if interval == Duration::from_secs(2) && intervals.is_none()
        ));
        assert!(matches!(
            parse_args(args(&["--interval-ms", "500"])).unwrap(),
            Command::Run { interval, intervals } if interval == Duration::from_millis(500) && intervals.is_none()
        ));
        assert!(matches!(
            parse_args(args(&["--jsonl", "--interval-ms=750"])).unwrap(),
            Command::Jsonl { interval, intervals } if interval == Duration::from_millis(750) && intervals.is_none()
        ));
        assert!(matches!(
            parse_args(args(&["--intervals", "3"])).unwrap(),
            Command::Run { interval, intervals } if interval == Duration::from_secs(2) && intervals == Some(3)
        ));
        assert!(matches!(
            parse_args(args(&["--jsonl", "--intervals=4"])).unwrap(),
            Command::Jsonl { interval, intervals } if interval == Duration::from_secs(2) && intervals == Some(4)
        ));
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
        assert!(error.contains("Usage: iodyne [--jsonl]"));
    }

    #[test]
    fn validates_interval_and_mode_combinations() {
        assert!(parse_args(args(&["--interval-ms", "99"])).is_err());
        assert!(parse_args(args(&["--interval-ms=10001"])).is_err());
        assert!(parse_args(args(&["--intervals", "0"])).is_err());
        assert!(parse_args(args(&["--intervals"])).is_err());
        assert!(parse_args(args(&["--diag", "--interval-ms", "500"])).is_err());
        assert!(parse_args(args(&["--diag", "--intervals", "1"])).is_err());
        assert!(parse_args(args(&["--jsonl", "--diag"])).is_err());
    }
}
