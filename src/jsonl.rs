use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::collect::devices::{DeviceKind, DeviceTick};
use crate::collect::ebpf::{
    EbpfStatus, VfsActivityDelta, VfsAttributionKind, VfsPathSource, LATENCY_BUCKETS,
};
use crate::collect::io::{DeviceInterval, MergeRates, VfsFileActivity};
use crate::collect::{self, FsTick, IoCollector};

const SCHEMA_VERSION: u32 = 1;
const TOPOLOGY_REFRESH: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub fn run(interval: Duration) -> Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    match run_stream(interval, &mut out) {
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        result => result,
    }
}

fn run_stream(interval: Duration, out: &mut impl Write) -> Result<()> {
    let started = Utc::now();
    let stream_id = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id()
    );
    let mut collector = IoCollector::new();
    collector.prime();
    let mut inventory = collect_inventory(interval, &collector);
    let mut sampled_device_names = collector.sampled_device_names();
    let mut inventory_revision = 1_u64;
    let mut sequence = 0_u64;
    write_record(
        out,
        &InventoryRecord {
            schema_version: SCHEMA_VERSION,
            record_type: "inventory",
            stream_id: &stream_id,
            sequence,
            timestamp: started,
            inventory_revision,
            inventory: &inventory,
        },
    )?;
    sequence += 1;

    let mut last_topology_refresh = Instant::now();
    loop {
        if collector.sample(interval) {
            let current_device_names = collector.sampled_device_names();
            if current_device_names != sampled_device_names
                || last_topology_refresh.elapsed() >= TOPOLOGY_REFRESH
            {
                let refreshed = collect_inventory(interval, &collector);
                if refreshed != inventory {
                    inventory = refreshed;
                    inventory_revision += 1;
                    write_record(
                        out,
                        &InventoryRecord {
                            schema_version: SCHEMA_VERSION,
                            record_type: "inventory",
                            stream_id: &stream_id,
                            sequence,
                            timestamp: Utc::now(),
                            inventory_revision,
                            inventory: &inventory,
                        },
                    )?;
                    sequence += 1;
                }
                sampled_device_names = current_device_names;
                last_topology_refresh = Instant::now();
            }
            let ended = Utc::now();
            let elapsed_ns = collector.latest_elapsed.as_nanos().min(u64::MAX as u128) as u64;
            let started =
                ended - chrono::Duration::nanoseconds(elapsed_ns.min(i64::MAX as u64) as i64);
            let sample = sample_data(&collector, elapsed_ns);
            write_record(
                out,
                &SampleRecord {
                    schema_version: SCHEMA_VERSION,
                    record_type: "sample",
                    stream_id: &stream_id,
                    sequence,
                    timestamp: ended,
                    inventory_revision,
                    interval_start: started,
                    interval_end: ended,
                    elapsed_ns,
                    sample,
                },
            )?;
            sequence += 1;
        }
        thread::sleep(POLL_INTERVAL.min(interval));
    }
}

fn write_record(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

#[derive(Serialize)]
struct InventoryRecord<'a> {
    schema_version: u32,
    record_type: &'static str,
    stream_id: &'a str,
    sequence: u64,
    timestamp: DateTime<Utc>,
    inventory_revision: u64,
    #[serde(flatten)]
    inventory: &'a Inventory,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct Inventory {
    iodyne_version: &'static str,
    sample_interval_ms: u64,
    host: HostInventory,
    devices: Vec<DeviceInventory>,
    mounts: Vec<MountInventory>,
    topology: Vec<collect::topology::TopologyEdge>,
    latency_bucket_bounds_us: Vec<BucketBounds>,
    collectors: CollectorStatuses,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HostInventory {
    hostname: Option<String>,
    boot_id: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    kernel_release: Option<String>,
    arch: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DeviceInventory {
    id: String,
    name: String,
    major: Option<u32>,
    minor: Option<u32>,
    kind: &'static str,
    model: Option<String>,
    bus: Option<String>,
    size_bytes: u64,
    removable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MountInventory {
    path: String,
    source: String,
    filesystem: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BucketBounds {
    lower_us: u64,
    upper_us: Option<u64>,
}

fn collect_inventory(interval: Duration, collector: &IoCollector) -> Inventory {
    let mut devices: Vec<_> = collect::devices::collect()
        .into_iter()
        .map(device_inventory)
        .collect();
    for name in collector.sampled_device_names() {
        if devices.iter().any(|device| device.name == name) {
            continue;
        }
        let (major, minor) = block_device_numbers(&name).unwrap_or((None, None));
        devices.push(DeviceInventory {
            id: match (major, minor) {
                (Some(major), Some(minor)) => format!("{major}:{minor}"),
                _ => name.clone(),
            },
            name: name.clone(),
            major,
            minor,
            kind: "logical",
            model: None,
            bus: None,
            size_bytes: block_device_size(&name).unwrap_or(0),
            removable: false,
        });
    }
    devices.sort_by(|a, b| a.id.cmp(&b.id));
    let filesystems = collect::filesystems::collect();
    let volumes = collect::volumes::collect();
    let mut mounts: Vec<_> = filesystems.iter().map(mount_inventory).collect();
    mounts.sort_by(|a, b| a.path.cmp(&b.path).then(a.source.cmp(&b.source)));
    Inventory {
        iodyne_version: env!("CARGO_PKG_VERSION"),
        sample_interval_ms: interval.as_millis() as u64,
        host: HostInventory {
            hostname: sysinfo::System::host_name(),
            boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|value| value.trim().to_string()),
            os: sysinfo::System::name(),
            os_version: sysinfo::System::os_version(),
            kernel_release: sysinfo::System::kernel_version(),
            arch: std::env::consts::ARCH,
        },
        devices,
        mounts,
        topology: collect::topology::relationships(&filesystems, &volumes),
        latency_bucket_bounds_us: (0..LATENCY_BUCKETS)
            .map(|index| BucketBounds {
                lower_us: if index == 0 { 0 } else { 1_u64 << index },
                upper_us: (index + 1 < LATENCY_BUCKETS).then_some(1_u64 << (index + 1)),
            })
            .collect(),
        collectors: collector_statuses(collector),
    }
}

fn device_inventory(device: DeviceTick) -> DeviceInventory {
    let name = collect::topology::device_name(&device.name).to_string();
    let (major, minor) = block_device_numbers(&name).unwrap_or((None, None));
    let id = match (major, minor) {
        (Some(major), Some(minor)) => format!("{major}:{minor}"),
        _ => name.clone(),
    };
    DeviceInventory {
        id,
        name,
        major,
        minor,
        kind: match device.kind {
            DeviceKind::Nvme => "nvme",
            DeviceKind::Ssd => "ssd",
            DeviceKind::Hdd => "hdd",
            DeviceKind::UsbMassStorage => "usb_mass_storage",
            DeviceKind::Unknown => "unknown",
        },
        model: meaningful(device.model),
        bus: meaningful(device.bus),
        size_bytes: device.size_bytes,
        removable: device.is_removable,
    }
}

fn meaningful(value: String) -> Option<String> {
    (!value.is_empty() && value != "Unknown" && value != "?").then_some(value)
}

fn mount_inventory(fs: &FsTick) -> MountInventory {
    MountInventory {
        path: fs.mount.clone(),
        source: collect::topology::device_name(&fs.device).to_string(),
        filesystem: fs.fs_type.clone(),
    }
}

#[cfg(target_os = "linux")]
fn block_device_numbers(name: &str) -> Option<(Option<u32>, Option<u32>)> {
    let value = std::fs::read_to_string(format!("/sys/class/block/{name}/dev")).ok()?;
    let (major, minor) = value.trim().split_once(':')?;
    Some((major.parse().ok(), minor.parse().ok()))
}

#[cfg(target_os = "linux")]
fn block_device_size(name: &str) -> Option<u64> {
    let sectors = std::fs::read_to_string(format!("/sys/class/block/{name}/size"))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    sectors.checked_mul(512)
}

#[cfg(not(target_os = "linux"))]
fn block_device_numbers(_name: &str) -> Option<(Option<u32>, Option<u32>)> {
    None
}

#[cfg(not(target_os = "linux"))]
fn block_device_size(_name: &str) -> Option<u64> {
    None
}

#[derive(Serialize)]
struct SampleRecord<'a> {
    schema_version: u32,
    record_type: &'static str,
    stream_id: &'a str,
    sequence: u64,
    timestamp: DateTime<Utc>,
    inventory_revision: u64,
    interval_start: DateTime<Utc>,
    interval_end: DateTime<Utc>,
    elapsed_ns: u64,
    #[serde(flatten)]
    sample: SampleData,
}

#[derive(Serialize)]
struct SampleData {
    devices: Vec<DeviceSample>,
    vfs: VfsSample,
    collectors: CollectorStatuses,
    quality: Quality,
}

fn sample_data(collector: &IoCollector, elapsed_ns: u64) -> SampleData {
    SampleData {
        devices: collector
            .latest_intervals
            .iter()
            .map(|interval| device_sample(interval, collector, elapsed_ns))
            .collect(),
        vfs: VfsSample {
            observations: collector.latest_vfs.iter().map(vfs_observation).collect(),
            hot_window_ns: Duration::from_secs(10).as_nanos() as u64,
            hot_files: collector.hot_files.iter().map(hot_file).collect(),
        },
        collectors: collector_statuses(collector),
        quality: Quality {
            vfs_observations: collector.latest_vfs.len(),
            vfs_ring_dropped_events: collector
                .hot_files_status()
                .is_active()
                .then_some(collector.latest_vfs_dropped_events),
        },
    }
}

#[derive(Serialize)]
struct DeviceSample {
    device: String,
    raw: DeviceRaw,
    derived: DeviceDerived,
    latency_histogram: Option<LatencyHistogram>,
}

#[derive(Serialize)]
struct DeviceRaw {
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
    read_merges: Option<u64>,
    write_merges: Option<u64>,
    read_time_ns: u64,
    write_time_ns: u64,
    weighted_io_time_ns: Option<u64>,
    discard_ops: Option<u64>,
    discard_merges: Option<u64>,
    discard_bytes: Option<u64>,
    discard_time_ns: Option<u64>,
    flush_ops: Option<u64>,
    flush_time_ns: Option<u64>,
}

#[derive(Serialize)]
struct DeviceDerived {
    read_bps: f64,
    write_bps: f64,
    total_bps: f64,
    read_iops: f64,
    write_iops: f64,
    total_iops: f64,
    read_request_bytes: Option<f64>,
    write_request_bytes: Option<f64>,
    average_request_bytes: Option<f64>,
    read_merges_per_sec: Option<f64>,
    write_merges_per_sec: Option<f64>,
    read_await_us: Option<f64>,
    write_await_us: Option<f64>,
    discard_bps: Option<f64>,
    discard_iops: Option<f64>,
    discard_await_us: Option<f64>,
    flush_iops: Option<f64>,
    flush_await_us: Option<f64>,
    queue_depth: Option<f64>,
    rolling_tick_await_us: Option<RollingAwait>,
}

#[derive(Serialize)]
struct RollingAwait {
    p50_read: f64,
    p99_read: f64,
    p999_read: f64,
    p50_write: f64,
    p99_write: f64,
    p999_write: f64,
}

#[derive(Serialize)]
struct LatencyHistogram {
    read_counts: [u64; LATENCY_BUCKETS],
    write_counts: [u64; LATENCY_BUCKETS],
}

fn device_sample(
    interval: &DeviceInterval,
    collector: &IoCollector,
    elapsed_ns: u64,
) -> DeviceSample {
    let tick = &interval.derived;
    let elapsed_seconds = (elapsed_ns as f64 / 1_000_000_000.0).max(0.001);
    let workload = collector
        .history
        .get(&interval.device)
        .and_then(|history| history.workload_samples.back())
        .copied()
        .unwrap_or_default();
    let (read_merges_per_sec, write_merges_per_sec) = match workload.merge_rates {
        MergeRates::Available {
            read_per_sec,
            write_per_sec,
        } => (Some(read_per_sec), Some(write_per_sec)),
        MergeRates::Unavailable => (None, None),
    };
    let discard_bps = interval
        .raw
        .discard_bytes
        .map(|bytes| bytes as f64 / elapsed_seconds);
    let discard_iops = interval
        .raw
        .discard_ops
        .map(|ops| ops as f64 / elapsed_seconds);
    let discard_await_us = match (interval.raw.discard_time_ns, interval.raw.discard_ops) {
        (Some(time_ns), Some(ops)) if ops > 0 => Some(time_ns as f64 / ops as f64 / 1_000.0),
        _ => None,
    };
    let flush_iops = interval
        .raw
        .flush_ops
        .map(|ops| ops as f64 / elapsed_seconds);
    let flush_await_us = match (interval.raw.flush_time_ns, interval.raw.flush_ops) {
        (Some(time_ns), Some(ops)) if ops > 0 => Some(time_ns as f64 / ops as f64 / 1_000.0),
        _ => None,
    };
    DeviceSample {
        device: interval.device.clone(),
        raw: DeviceRaw {
            read_bytes: interval.raw.read_bytes,
            write_bytes: interval.raw.write_bytes,
            read_ops: interval.raw.read_ops,
            write_ops: interval.raw.write_ops,
            read_merges: interval.raw.read_merges,
            write_merges: interval.raw.write_merges,
            read_time_ns: interval.raw.read_time_ns,
            write_time_ns: interval.raw.write_time_ns,
            weighted_io_time_ns: interval.raw.weighted_io_time_ns,
            discard_ops: interval.raw.discard_ops,
            discard_merges: interval.raw.discard_merges,
            discard_bytes: interval.raw.discard_bytes,
            discard_time_ns: interval.raw.discard_time_ns,
            flush_ops: interval.raw.flush_ops,
            flush_time_ns: interval.raw.flush_time_ns,
        },
        derived: DeviceDerived {
            read_bps: workload.read_bps,
            write_bps: workload.write_bps,
            total_bps: tick.bps,
            read_iops: workload.read_iops,
            write_iops: workload.write_iops,
            total_iops: tick.iops,
            read_request_bytes: workload.read_request_bytes,
            write_request_bytes: workload.write_request_bytes,
            average_request_bytes: tick.avg_request_bytes,
            read_merges_per_sec,
            write_merges_per_sec,
            read_await_us: tick.await_sample.read_us,
            write_await_us: tick.await_sample.write_us,
            discard_bps,
            discard_iops,
            discard_await_us,
            flush_iops,
            flush_await_us,
            queue_depth: tick.queue_depth,
            rolling_tick_await_us: tick.latency_pct.as_ref().map(|pct| RollingAwait {
                p50_read: pct.p50_r,
                p99_read: pct.p99_r,
                p999_read: pct.p999_r,
                p50_write: pct.p50_w,
                p99_write: pct.p99_w,
                p999_write: pct.p999_w,
            }),
        },
        latency_histogram: collector
            .traced_history
            .get(&interval.device)
            .and_then(|history| history.back())
            .map(|sample| LatencyHistogram {
                read_counts: sample.read,
                write_counts: sample.write,
            }),
    }
}

#[derive(Serialize)]
struct VfsSample {
    observations: Vec<VfsObservation>,
    hot_window_ns: u64,
    hot_files: Vec<HotFile>,
}

#[derive(Serialize)]
struct VfsObservation {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    basename: String,
    path: Option<String>,
    path_source: &'static str,
    executor: ProcessIdentity,
    captured_requester: Option<ProcessIdentity>,
    attributed_process: ProcessIdentity,
    attributed_parent: Option<ProcessIdentity>,
    attribution: String,
    container_owned: bool,
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
}

#[derive(Serialize)]
struct ProcessIdentity {
    pid: u32,
    tgid: u32,
    comm: Option<String>,
    cgroup_id: Option<u64>,
}

fn vfs_observation(value: &VfsActivityDelta) -> VfsObservation {
    VfsObservation {
        device_major: value.device.major,
        device_minor: value.device.minor,
        inode: value.inode,
        basename: value.basename.clone(),
        path: (!value.path.is_empty()).then(|| value.path.clone()),
        path_source: match value.path_source {
            VfsPathSource::Ebpf => "ebpf",
            VfsPathSource::ProcFd => "proc_fd",
            VfsPathSource::BasenameFallback => "basename_fallback",
            VfsPathSource::Unresolved => "unresolved",
        },
        executor: ProcessIdentity {
            pid: value.executor_pid,
            tgid: value.executor_tgid,
            comm: meaningful(value.executor_comm.clone()),
            cgroup_id: (value.executor_cgroup_id != 0).then_some(value.executor_cgroup_id),
        },
        captured_requester: (value.origin_pid != 0 && value.origin_pid != u32::MAX).then(|| {
            ProcessIdentity {
                pid: value.origin_pid,
                tgid: value.origin_tgid,
                comm: meaningful(value.origin_comm.clone()),
                cgroup_id: (value.origin_cgroup_id != 0).then_some(value.origin_cgroup_id),
            }
        }),
        attributed_process: ProcessIdentity {
            pid: value.pid,
            tgid: value.tgid,
            comm: meaningful(value.comm.clone()),
            cgroup_id: (value.origin_cgroup_id != 0)
                .then_some(value.origin_cgroup_id)
                .or_else(|| (value.executor_cgroup_id != 0).then_some(value.executor_cgroup_id)),
        },
        attributed_parent: (value.parent_tgid != 0).then(|| ProcessIdentity {
            pid: value.parent_tgid,
            tgid: value.parent_tgid,
            comm: meaningful(value.parent_comm.clone()),
            cgroup_id: None,
        }),
        attribution: match value.attribution_kind {
            VfsAttributionKind::Direct => "direct".into(),
            VfsAttributionKind::FuseProtocol => "fuse_protocol".into(),
            VfsAttributionKind::FuseWriteback => "fuse_writeback".into(),
            VfsAttributionKind::FusePidZero => "fuse_pid_zero".into(),
            VfsAttributionKind::FuseUnresolved => "fuse_unresolved".into(),
            VfsAttributionKind::Unknown(value) => format!("unknown:{value}"),
        },
        container_owned: value.container_owned,
        read_bytes: value.read_bytes,
        write_bytes: value.write_bytes,
        read_ops: value.read_ops,
        write_ops: value.write_ops,
    }
}

#[derive(Serialize)]
struct HotFile {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    basename: String,
    path: String,
    path_source: &'static str,
    read_bps: f64,
    write_bps: f64,
    read_ops_per_sec: f64,
    write_ops_per_sec: f64,
    contributors: Vec<HotContributor>,
    rollups: Vec<ProcessRollup>,
    workloads: Vec<WorkloadLabel>,
}

#[derive(Serialize)]
struct HotContributor {
    comm: String,
    pid: u32,
    tgid: u32,
}

#[derive(Serialize)]
struct ProcessRollup {
    child_tgid: u32,
    display_comm: String,
    display_tgid: u32,
}

#[derive(Serialize)]
struct WorkloadLabel {
    display_tgid: u32,
    label: String,
}

fn hot_file(value: &VfsFileActivity) -> HotFile {
    let rollups = value
        .process_rollups
        .iter()
        .map(|(child_tgid, display_comm, display_tgid)| ProcessRollup {
            child_tgid: *child_tgid,
            display_comm: display_comm.clone(),
            display_tgid: *display_tgid,
        })
        .collect();
    HotFile {
        device_major: value.fs_device.major,
        device_minor: value.fs_device.minor,
        inode: value.inode,
        basename: value.basename.clone(),
        path: value.path.clone(),
        path_source: match value.path_source {
            VfsPathSource::Ebpf => "ebpf",
            VfsPathSource::ProcFd => "proc_fd",
            VfsPathSource::BasenameFallback => "basename_fallback",
            VfsPathSource::Unresolved => "unresolved",
        },
        read_bps: value.read_bps,
        write_bps: value.write_bps,
        read_ops_per_sec: value.read_ops,
        write_ops_per_sec: value.write_ops,
        contributors: value
            .processes
            .iter()
            .map(|(comm, pid, tgid)| HotContributor {
                comm: comm.clone(),
                pid: *pid,
                tgid: *tgid,
            })
            .collect(),
        rollups,
        workloads: value
            .display_workloads
            .iter()
            .map(|(pid, label)| WorkloadLabel {
                display_tgid: *pid,
                label: label.clone(),
            })
            .collect(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct CollectorStatuses {
    block_io: Status,
    latency: Status,
    vfs_activity: Status,
    vfs_paths: Status,
    fuse_requester: Status,
    fuse_writeback: Status,
    overlay_backing: Status,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Status {
    state: &'static str,
    detail: Option<String>,
}

fn collector_statuses(collector: &IoCollector) -> CollectorStatuses {
    CollectorStatuses {
        block_io: if collector.sampled_device_names().is_empty() {
            Status {
                state: "unavailable",
                detail: Some("no block-device counters were discovered".into()),
            }
        } else {
            Status {
                state: "active",
                detail: None,
            }
        },
        latency: status(collector.latency_status()),
        vfs_activity: status(collector.hot_files_status()),
        vfs_paths: status(collector.vfs_path_status()),
        fuse_requester: status(collector.vfs_fuse_status()),
        fuse_writeback: status(collector.vfs_fuse_writeback_status()),
        overlay_backing: status(collector.vfs_overlay_status()),
    }
}

fn status(value: &EbpfStatus) -> Status {
    match value {
        EbpfStatus::Active => Status {
            state: "active",
            detail: None,
        },
        EbpfStatus::DisabledAtBuild => Status {
            state: "disabled_at_build",
            detail: None,
        },
        EbpfStatus::UnsupportedPlatform => Status {
            state: "unsupported_platform",
            detail: None,
        },
        EbpfStatus::Unavailable(detail) => Status {
            state: "unavailable",
            detail: Some(detail.clone()),
        },
    }
}

#[derive(Serialize)]
struct Quality {
    vfs_observations: usize,
    vfs_ring_dropped_events: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_vfs_serialization_keeps_executor_and_attributed_process() {
        let value = VfsActivityDelta {
            device: collect::ebpf::BlockDeviceId { major: 8, minor: 1 },
            inode: 42,
            pid: 100,
            tgid: 100,
            comm: "rg".into(),
            executor_pid: 200,
            executor_tgid: 200,
            executor_comm: "fuse-overlayfs".into(),
            origin_pid: 7,
            origin_tgid: 100,
            origin_comm: "rg".into(),
            attribution_kind: VfsAttributionKind::FuseProtocol,
            read_bytes: 4096,
            read_ops: 1,
            ..Default::default()
        };
        let encoded = serde_json::to_value(vfs_observation(&value)).unwrap();
        assert_eq!(encoded["executor"]["comm"], "fuse-overlayfs");
        assert_eq!(encoded["attributed_process"]["comm"], "rg");
        assert_eq!(encoded["attribution"], "fuse_protocol");
        assert_eq!(encoded["read_bytes"], 4096);
    }

    #[test]
    fn bucket_bounds_match_bpf_log2_layout() {
        let collector = IoCollector::new_for_test();
        let inventory = collect_inventory(Duration::from_secs(2), &collector);
        assert_eq!(inventory.latency_bucket_bounds_us[0].lower_us, 0);
        assert_eq!(inventory.latency_bucket_bounds_us[0].upper_us, Some(2));
        assert_eq!(inventory.latency_bucket_bounds_us[31].upper_us, None);
    }

    #[test]
    fn device_jsonl_includes_discard_and_flush_raw_and_derived_values() {
        let collector = IoCollector::new_for_test();
        let interval = DeviceInterval {
            device: "sda".into(),
            raw: crate::collect::io::DeviceIntervalRaw {
                discard_ops: Some(4),
                discard_merges: Some(1),
                discard_bytes: Some(8_192),
                discard_time_ns: Some(8_000_000),
                flush_ops: Some(2),
                flush_time_ns: Some(1_000_000),
                ..Default::default()
            },
            derived: crate::collect::io::IoTick {
                device: "sda".into(),
                ..Default::default()
            },
        };

        let encoded =
            serde_json::to_value(device_sample(&interval, &collector, 2_000_000_000)).unwrap();

        assert_eq!(encoded["raw"]["discard_ops"], 4);
        assert_eq!(encoded["raw"]["discard_merges"], 1);
        assert_eq!(encoded["raw"]["discard_bytes"], 8_192);
        assert_eq!(encoded["raw"]["discard_time_ns"], 8_000_000);
        assert_eq!(encoded["raw"]["flush_ops"], 2);
        assert_eq!(encoded["raw"]["flush_time_ns"], 1_000_000);
        assert_eq!(encoded["derived"]["discard_bps"].as_f64().unwrap(), 4_096.0);
        assert_eq!(encoded["derived"]["discard_iops"].as_f64().unwrap(), 2.0);
        assert_eq!(
            encoded["derived"]["discard_await_us"].as_f64().unwrap(),
            2_000.0
        );
        assert_eq!(encoded["derived"]["flush_iops"].as_f64().unwrap(), 1.0);
        assert_eq!(
            encoded["derived"]["flush_await_us"].as_f64().unwrap(),
            500.0
        );
    }
}
