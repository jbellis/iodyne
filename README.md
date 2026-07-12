# iodyne

`iodyne` is a read-only terminal view of storage behavior on one host. It keeps
all devices on comparable scales, so the busy or slow device stands out before
you inspect its numbers.

The top of the screen is the device overview:

- free space, bandwidth, and IOPS, with bandwidth and IOPS histories scaled
  across the visible devices;
- separate read and write latency-density lanes on one fixed logarithmic axis;
- one selected device whose evidence fills the rest of the screen.

The detail view splits reads from writes and shows 60-second latency
distributions plus aligned histories for IOPS, throughput, request size,
merges, and await. Its header identifies the mount and backing-device topology,
followed by available filesystem, device, mdraid, APFS, and SMART facts. On
Linux, VFS tracing adds the processes and paths currently requesting the most
file IO.

This is the view for answering "which device, which direction, and what kind of
workload?" It complements `iostat`; it is not a benchmark or a long-term
metrics store.

## Install

Install the published crate and run it directly:

```sh
cargo install iodyne
iodyne
```

On Linux, run the same binary as root to enable the embedded eBPF collectors:

```sh
sudo "$(command -v iodyne)"
```

No kernel module, daemon, recursive filesystem watch, or separate eBPF build is
installed. If the kernel rejects a probe, `iodyne` keeps running with the data
sources that remain available.

## Collection modes

Unprivileged Linux and macOS provide bandwidth, IOPS, request size, and
interval-average await from cumulative device counters. In this mode the
latency display is derived from aggregate samples; it is not a distribution of
individual requests.

Privileged Linux additionally attempts two independent eBPF collectors:

- **Block latency** measures each block request from issue to final completion,
  including time queued and in service. Bounded in-kernel histograms are read
  once per display interval; individual events are not streamed to userspace.
- **VFS activity** attributes requested bytes and operations to filesystem
  device, inode, and process. A `security_file_permission` fentry probe calls
  `bpf_d_path()` while the file path is valid, so short-lived files normally
  retain their path. Paths are bounded to 256 bytes; `/proc/<pid>/fd` remains a
  fallback when event-time capture is unavailable.

These are deliberately different accounting layers. The block view describes
physical requests reaching a device. The VFS view describes bytes requested by
applications at `vfs_read`/`vfs_write` entry: reads satisfied by page cache are
included, and buffered writes are charged when requested rather than when
writeback later reaches storage. Requested bytes can exceed returned bytes.

Use diagnostics to see which probes and collectors actually loaded:

```sh
sudo "$(command -v iodyne)" --diag
```

## Platforms

**Linux:** aggregate statistics come from `/proc/diskstats`; device and mount
facts come from sysfs, `sysinfo`, and `/proc/mdstat`. Per-request latency needs
Linux 5.11 or newer, kernel BTF at `/sys/kernel/btf/vmlinux`, the expected block
tracepoints, and permission to load tracing BPF. VFS probes are supplied for
x86_64 and arm64. Root usually has the required permission, but lockdown,
containers, vendor kernels, or LSM policy can still reject a probe.

**macOS:** workload statistics come from IOKit; topology comes from `diskutil`
and `system_profiler`. APFS containers are attributed to their physical stores.
Per-request latency and VFS path attribution are not available, so the display
uses aggregate await.

When `smartctl` is on `PATH`, `iodyne` adds available ATA or NVMe evidence such
as temperature, wear, spare, and power-on time. `smartmontools` is optional.

## Keys

| Key | Action |
|---|---|
| `j` / `k`, `Down` / `Up` | Select a device |
| `u` | Show mounted devices or all devices |
| `p` | Pause or resume sampling |
| `,` | Open settings |
| `b` | Toggle binary/decimal units while settings are open |
| `q` / `Esc` | Quit |

Settings are stored under `$XDG_CONFIG_HOME/iodyne/` when that variable is set,
otherwise under `~/.config/iodyne/`.

## Limits

- VFS activity is a rolling 10-second hot set, not an audit log. Its bounded
  8,192-entry kernel map can evict colder entries.
- mmap IO, metadata IO, and paths that bypass `vfs_read`/`vfs_write` (including
  some `io_uring` operations) are absent from VFS attribution.
- Long paths may fall back to a basename and inode. Hard links are represented
  by the first observed path for that identity.
- LVM and ZFS-specific topology are not decoded. Device-mapper IO remains
  visible, but the detail header may not reconstruct the complete stack.
- SMART access varies by controller, bridge, permissions, and device support;
  missing fields are omitted rather than inferred.
- The interface is designed around a 130x36 terminal and remains useful at
  110x30. Smaller terminals necessarily omit detail.

`iodyne` does not write storage, change kernel settings, or persist telemetry.

## Development

Rust 1.75 or newer is required to build from source:

```sh
git clone https://github.com/matthart1983/diskwatch.git
cd diskwatch
cargo build --release
./target/release/iodyne
```

To compile Linux without the eBPF loader and its Aya dependency:

```sh
cargo build --release --no-default-features
```

## License

MIT
