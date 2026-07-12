<p align="center">
  <h1 align="center">DiskWatch</h1>
  <p align="center">
    <strong>Single-host disk diagnostics in your terminal. The terminal you open when the disk light won't stop blinking — before you reach for iostat, iotop, smartctl, lsblk, df, du, and a panic.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue" alt="Platform">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    <img src="https://img.shields.io/badge/status-v0.1-yellow" alt="Status">
  </p>
</p>

<p align="center">
  <em>Sibling to <a href="https://github.com/matthart1983/netwatch">NetWatch</a> and <a href="https://github.com/matthart1983/syswatch">SysWatch</a>. Same chrome. Same palette. Seven tabs covering every disk on one box.</em>
</p>

<p align="center">
  <img src="demo.gif" alt="DiskWatch — Overview, Devices, Volumes, FS, IO, SMART, Insights" width="800">
</p>

---

## What it shows

| # | Tab | Replaces |
|---|---|---|
| 1 | Overview | one screen across capacity, IO, health, and VFS activity |
| 2 | Devices | `lsblk`, `nvme list`, `diskutil list`, `hdparm -I` |
| 3 | Volumes | `lvs` + `vgs`, `mdadm --detail`, `diskutil apfs list` |
| 4 | FS | `df -h`, `df -i`, `mount`, `findmnt` |
| 5 | IO | `iostat -x 1`, biolatency-style averages |
| 6 | SMART | `smartctl -A`, `nvme smart-log` |
| 7 | Insights | plain-English anomaly summaries |

Where `lsblk` shows you *which disks exist*, DiskWatch shows you *what's happening on them* — capacity trending, IO throughput, p99 latency, SMART health, and, with privileged Linux tracing, the files with current VFS activity — and tells you why in plain English when something's anomalous.

## Install

```bash
# Homebrew (macOS / Linux)
brew install matthart1983/tap/diskwatch

# Cargo
cargo install diskwatch

# Pre-built binaries — see Releases
```

<details>
<summary><strong>All platforms & options</strong></summary>

| Platform | Download |
|----------|----------|
| Linux (x86_64) | [`diskwatch-linux-x86_64.tar.gz`](https://github.com/matthart1983/diskwatch/releases/latest) |
| Linux (aarch64) | [`diskwatch-linux-aarch64.tar.gz`](https://github.com/matthart1983/diskwatch/releases/latest) |
| Linux (x86_64, static) | [`diskwatch-linux-x86_64-static.tar.gz`](https://github.com/matthart1983/diskwatch/releases/latest) |
| Linux (aarch64, static) | [`diskwatch-linux-aarch64-static.tar.gz`](https://github.com/matthart1983/diskwatch/releases/latest) |
| macOS (Intel) | [`diskwatch-macos-x86_64.tar.gz`](https://github.com/matthart1983/diskwatch/releases/latest) |
| macOS (Apple Silicon) | [`diskwatch-macos-aarch64.tar.gz`](https://github.com/matthart1983/diskwatch/releases/latest) |

**From source:**

```bash
git clone https://github.com/matthart1983/diskwatch.git && cd diskwatch
cargo build --release
./target/release/diskwatch
```

</details>

**Prerequisites:** Rust 1.75+ (only if building from source). No system dependencies on Linux. macOS calls the standard `ioreg`, `diskutil`, and `system_profiler` binaries — all preinstalled. Optional: `smartmontools` (`brew install smartmontools` / `apt install smartmontools`) for full SMART attribute tables — without it, the SMART tab falls back to the basic verified/failing flag from `diskutil`.

On Linux, `diskwatch` uses unprivileged aggregate await statistics. On Linux 5.11 or newer, running `sudo diskwatch` additionally attempts the embedded eBPF probe for per-request latency distributions and bounded VFS file activity; kernel policy may still deny tracing, in which case DiskWatch falls back automatically. No recursive filesystem watches are created. `diskwatch --diag` reports the active tracing source and load status.

## Keys

| Key | Action |
|---|---|
| `1`–`7` | Switch tabs |
| `↑` / `↓` / `j` / `k` | Move selection (Devices, FS, IO) |
| `p` | Pause / resume sampling |
| `q` / `Esc` | Quit |
| `--diag` | Print collected state and exit (no TUI) |

## Tabs in detail

**[1] Overview** — 5 KPI tiles (capacity, IO, p99 latency, health, insights), per-device summary, aggregate IO sparkline, top VFS file activity when tracing is available, top insights, segmented capacity bar.

**[2] Devices** — block-device table with model, firmware, serial, used %, SMART status. Detail panel for the selected device.

**[3] Volumes** — APFS containers (macOS) with nested volumes, role, mount, FileVault. mdraid arrays (Linux) with members, slot state `[UUUU]`, resync/recovery progress.

**[4] FS** — mounted filesystems with inline usage bars, threshold colors, system/user/removable classification.

**[5] IO** — full-width per-device visual bands with IOPS, throughput, request size, and a shared logarithmic latency scale. Standard mode shows one-second read/write await timelines; privileged Linux mode uses eBPF for per-request distributions, a 60s p99 timeline, and selected-device VFS file activity.

**[6] SMART** — full NVMe / ATA attribute tables when `smartctl` is on PATH; degraded banner with install instructions when not. Always shows the basic verified/failing flag.

**[7] Insights** — anomaly cards over the collected state: capacity warnings, SMART failures, NVMe wear, drive temperature, p99 latency outliers, IO-dominant devices, and removable drives.

## What's real, what's deferred

| Metric | macOS | Linux |
|---|---|---|
| Device model / serial / firmware | ✅ `system_profiler` + IOKit | ✅ `/sys/block/*/device/{model,serial,firmware_rev}` |
| Per-device used bytes | ✅ via APFS container map | ✅ summed from `sysinfo` mounts |
| Read/write byte rates (split) | ✅ IOKit `Statistics` | ✅ `/proc/diskstats` cols 5/9 |
| Interval-average await | ✅ `Total Time / Operations` | ✅ `/proc/diskstats` cols 6/10 |
| Await timeline | ✅ one-second buckets over 60s | ✅ one-second buckets over 60s |
| True per-request histogram / p99 | ❌ needs IOReport entitlement | ✅ eBPF when privileged; aggregate fallback otherwise |
| SMART attributes | ✅ `smartctl` if installed | ✅ `smartctl` if installed |
| Volumes — APFS | ✅ `diskutil apfs list` | n/a |
| Volumes — mdraid | n/a | ✅ `/proc/mdstat` |
| Volumes — ZFS, LVM | ⏳ deferred | ⏳ deferred |
| VFS file activity — bytes / pid | ❌ unavailable | ✅ eBPF when privileged; unavailable otherwise |

VFS activity measures application reads and writes at the VFS layer. It is not physical disk traffic: reads may be served from cache and buffered writes may reach the device later under a different process.

## Design

Inherits the *Watch family chrome — `#0c1418` background, terminal-green accent, JetBrains Mono, 130×36 character grid with responsive reflow ≥ 110×30. The same character-grid mockups that drive NetWatch and SysWatch drive DiskWatch.

## Anti-goals

- **Not multi-host.** Use NetWatch Cloud if you need a fleet view.
- **Not a daemon.** No long-running collector, no persisted DB.
- **Not a deduper / cleaner.** We surface what's eating disk; we don't delete anything. Mutation is a different tool.
- **Not a backup product.** Snapshots are observed, not authored.
- **Not a benchmark.** We measure what's happening, not what's possible.

## License

MIT.
