# DiskWatch

DiskWatch is a single-host, read-only disk IO diagnostics TUI. It puts every
device on one comparable latency scale, then gives the selected device enough
space for directional latency, workload history, storage topology, health
facts, and active files.

It is designed for the moment when a disk is slow or unexpectedly busy and you
would otherwise assemble the answer from `iostat`, `iotop`, `smartctl`,
`lsblk`, `df`, and `/proc/mdstat`.

## Install

```bash
# Homebrew (macOS / Linux)
brew install matthart1983/tap/diskwatch

# Cargo
cargo install diskwatch

# From source
git clone https://github.com/matthart1983/diskwatch.git
cd diskwatch
cargo build --release
./target/release/diskwatch
```

Pre-built Linux and macOS archives are available from
[Releases](https://github.com/matthart1983/diskwatch/releases/latest).

Rust 1.75+ is required only when building from source. Linux has no required
system packages. macOS uses the standard `ioreg`, `diskutil`, and
`system_profiler` commands. `smartmontools` is optional on both platforms; when
`smartctl` is available, DiskWatch adds NVMe and ATA health evidence to the
selected-device detail.

## The Screen

The upper device overview is visual rather than tabular. Every disk gets split
read and write latency-density lanes on the same fixed logarithmic axis, so an
outlier is visible without comparing device-specific scales or reading a table
of percentiles.

The selected-device detail contains:

- separate read and write latency distributions over the last 60 seconds;
- aligned 60-second graphs for IOPS, throughput, request size, merges, and
  interval-average await;
- model, bus, device kind and capacity, filesystem/free-space facts, and SMART
  evidence when available;
- mdraid membership, degraded/recovery state, or APFS physical-store topology;
- rolling VFS file activity, with requested rates and resolved paths when Linux
  eBPF tracing is active.

`u` switches between mounted devices and all devices. `j`/`k` or the arrow keys
move the selected-device detail without changing the overview.

## Collection Modes

Unprivileged Linux and macOS use aggregate interval-average await. The overview
and detail remain useful in this mode, but aggregate counters cannot provide a
true per-request latency distribution.

On Linux 5.11 or newer, privileged execution additionally attempts the embedded
eBPF probes:

```bash
sudo "$(command -v diskwatch)"
```

When the kernel accepts the probes, DiskWatch shows per-request read/write
latency distributions and bounded VFS activity. Kernel policy may deny tracing;
DiskWatch then falls back automatically. It never creates recursive filesystem
watches. VFS activity measures requested application IO, not physical media IO:
reads may come from cache and buffered writes may reach disk later.

Use `diskwatch --diag` to print collector and tracing status without entering
the TUI.

## Keys

| Key | Action |
|---|---|
| `j` / `k`, `Down` / `Up` | Select device |
| `u` | Toggle mounted/all devices |
| `p` | Pause/resume sampling |
| `,` | Open settings |
| `b` | Toggle binary/decimal units in settings |
| `q` / `Esc` | Quit |

## Data Sources

| Fact | macOS | Linux |
|---|---|---|
| Device identity/topology | `system_profiler`, `diskutil` | `/sys/block`, `/proc/mdstat` |
| Read/write rates and workload | IOKit statistics | `/proc/diskstats` |
| Interval-average await | IOKit total time/operations | `/proc/diskstats` |
| Per-request latency | unavailable | eBPF when privileged |
| VFS requested activity | unavailable | eBPF when privileged |
| SMART evidence | `smartctl`, basic `diskutil` status | `smartctl` |
| Filesystem capacity/mounts | `sysinfo` | `sysinfo` |

ZFS and LVM-specific topology are not currently decoded.

## Design And Scope

DiskWatch uses the Watch-family terminal palette and targets a 130x36 character
grid with responsive behavior at 110x30. Smaller terminals are supported on a
best-effort basis without panicking.

DiskWatch is not a daemon, benchmark, cleaner, backup product, or multi-host
monitor. It observes the current machine and does not mutate storage.

## License

MIT
