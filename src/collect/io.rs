//! Per-device IO sampling in one-second display buckets.
//!
//! Both supported platforms expose cumulative split-direction byte +
//! operation + request-time counters:
//! - **macOS**: `IOBlockStorageDriver` Statistics dict via
//!   `collect::iokit` (`ioreg -c IOBlockStorageDriver -r -l -w 0`).
//! - **Linux**: `/proc/diskstats` columns 5/9 (sectors) and 6/10
//!   (milliseconds spent on IO).
//!
//! Each sample computes interval-average await (Total Time Δ /
//! Operations Δ). Await includes both queue and device service time;
//! it is not device service time alone. We retain the last
//! `LATENCY_WINDOW` of those active-tick observations per device and surface
//! `p50 / p99 / p999` against that rolling window.
//!
//! **Honest scope:** these are *percentiles of per-tick averages*, not
//! of individual operations. They catch sustained slow stretches; they
//! cannot see a single 50ms outlier hiding inside an otherwise-fast
//! display bucket. Real per-op p99 needs eBPF biolatency (Linux)
//! or IOReport subscription (macOS), both deferred.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub use crate::collect::ebpf::VfsActivitySource;
use crate::collect::ebpf::{
    BlockDeviceId, EbpfLatencyCollector, EbpfStatus, IoDirection, LatencySource, VfsActivityDelta,
    LATENCY_BUCKETS,
};

/// One-second buckets keep the visual timelines calm while the optional eBPF
/// program continues accounting for every request inside the kernel.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// One minute of throughput history.
const RING_LEN: usize = 60;

/// One minute of aligned latency observations.
const LATENCY_WINDOW: usize = 60;

/// Maximum host-wide VFS entries retained for presentation. Kernel event and
/// path storage are separately bounded.
const HOT_FILE_LIMIT: usize = 64;
/// Smooth VFS activity over ten seconds so short collector intervals do not
/// make the hottest-file ranking flicker. Samples remain bounded by the
/// kernel event ring and this finite time window.
const VFS_ACTIVITY_WINDOW: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const PROC_FD_SCAN_LIMIT: usize = 256;

/// Rolling host-wide VFS activity attributed to a file and process. Rates are
/// averaged over up to the most recent ten seconds. Byte rates are completed
/// VFS byte counts, not physical disk traffic.
#[derive(Debug, Clone, PartialEq)]
pub struct VfsFileActivity {
    pub fs_device: BlockDeviceId,
    pub inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    /// Deduplicated process names and process IDs contributing to this file.
    pub processes: Vec<(String, u32, u32)>,
    /// Presentation identities, collapsed to immediate parents when available.
    pub display_processes: Vec<(String, u32)>,
    /// Container/workload labels keyed by displayed host PID.
    pub display_workloads: Vec<(u32, String)>,
    pub basename: String,
    pub path: String,
    pub read_bps: f64,
    pub write_bps: f64,
    pub read_ops: f64,
    pub write_ops: f64,
}

#[derive(Debug, Default, Clone)]
pub struct IoTick {
    pub device: String,
    /// Combined read + write bytes/sec.
    pub bps: f64,
    /// Per-direction byte rates.
    pub split: Option<(f64, f64)>,
    /// Combined read + write operations/sec.
    pub iops: f64,
    /// Per-direction operation rates: (read, write).
    pub iops_split: Option<(f64, f64)>,
    /// Mean bytes per completed operation in this interval.
    pub avg_request_bytes: Option<f64>,
    /// Average number of requests queued or in service during this
    /// interval. Linux derives this from weighted I/O time; unavailable
    /// on macOS.
    pub queue_depth: Option<f64>,
    /// Wall-clock-aligned interval-average await for this tick.
    pub await_sample: AwaitSample,
    /// Compatibility alias for interval-average await in µs, encoded as
    /// `(read, write)` with a zero for an inactive direction. `None` when
    /// no operations completed. Prefer `await_sample`.
    #[allow(dead_code)]
    pub latency_avg: Option<(f64, f64)>,
    /// Percentiles of active-tick interval-average await samples. These are
    /// not percentiles of individual requests; see the module docs.
    pub latency_pct: Option<LatencyPct>,
}

/// Await observations from one collector tick. Missing means that direction
/// completed no operations. Retaining the observation preserves idle gaps and
/// keeps read and write timelines aligned to wall clock.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct AwaitSample {
    pub read_us: Option<f64>,
    pub write_us: Option<f64>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LatencyPct {
    #[allow(dead_code)]
    pub p50_r: f64,
    pub p99_r: f64,
    /// p99.9 — surfaces with a 300-sample window what p99 can't catch
    /// with only 100. Not yet displayed; reserved for a drill-in view.
    #[allow(dead_code)]
    pub p999_r: f64,
    #[allow(dead_code)]
    pub p50_w: f64,
    pub p99_w: f64,
    #[allow(dead_code)]
    pub p999_w: f64,
}

#[derive(Debug, Default, Clone)]
pub struct DeviceHistory {
    pub combined: VecDeque<f64>,
    /// One wall-clock-aligned workload observation per sample while the
    /// device is present. Idle intervals are retained as zero-rate samples.
    pub workload_samples: VecDeque<WorkloadSample>,
    /// One entry per sample while the device is present. Fully idle ticks have
    /// two `None` values.
    pub await_samples: VecDeque<AwaitSample>,
    /// Active-tick interval-average read await in µs. Compatibility-only
    /// sparse history used by the temporary percentile view.
    pub read_us: VecDeque<f64>,
    /// Active-tick interval-average write await in µs. Compatibility-only
    /// sparse history used by the temporary percentile view.
    pub write_us: VecDeque<f64>,
}

/// Work completed by one device during a collector interval, normalized to
/// per-second rates. Request sizes are absent when that direction completed no
/// operations during the interval.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct WorkloadSample {
    pub read_iops: f64,
    pub write_iops: f64,
    pub read_bps: f64,
    pub write_bps: f64,
    pub read_request_bytes: Option<f64>,
    pub write_request_bytes: Option<f64>,
    pub merge_rates: MergeRates,
}

/// Directional request merge rates. Linux diskstats reports these counters;
/// macOS does not. `Available` values may legitimately both be zero.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum MergeRates {
    Available {
        read_per_sec: f64,
        write_per_sec: f64,
    },
    #[default]
    Unavailable,
}

/// Per-request latency counts captured during one collector tick. Counts are
/// logarithmic microsecond buckets supplied by the Linux eBPF backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracedLatencySample {
    pub read: [u64; LATENCY_BUCKETS],
    pub write: [u64; LATENCY_BUCKETS],
}

impl Default for TracedLatencySample {
    fn default() -> Self {
        Self {
            read: [0; LATENCY_BUCKETS],
            write: [0; LATENCY_BUCKETS],
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct DeviceTotals {
    bytes_read: u64,
    bytes_written: u64,
    ops_read: u64,
    ops_written: u64,
    /// Cumulative request merges. Absent on platforms that do not expose
    /// directional merge counters.
    merges: Option<(u64, u64)>,
    total_time_read_ns: u64,
    total_time_write_ns: u64,
    /// Weighted I/O time accumulates elapsed time multiplied by the number of
    /// requests queued or in service. Present for Linux diskstats only.
    weighted_io_time_ns: Option<u64>,
}

#[derive(Debug, Default, Clone, Copy)]
struct IntervalMetrics {
    read_bps: f64,
    write_bps: f64,
    read_iops: f64,
    write_iops: f64,
    avg_request_bytes: Option<f64>,
    workload: WorkloadSample,
    queue_depth: Option<f64>,
    await_sample: AwaitSample,
}

fn interval_metrics(
    current: DeviceTotals,
    previous: DeviceTotals,
    elapsed: f64,
) -> IntervalMetrics {
    let elapsed = elapsed.max(0.001);
    let read_bytes = current.bytes_read.saturating_sub(previous.bytes_read) as f64;
    let write_bytes = current.bytes_written.saturating_sub(previous.bytes_written) as f64;
    let read_ops = current.ops_read.saturating_sub(previous.ops_read);
    let write_ops = current.ops_written.saturating_sub(previous.ops_written);
    let read_time = current
        .total_time_read_ns
        .saturating_sub(previous.total_time_read_ns);
    let write_time = current
        .total_time_write_ns
        .saturating_sub(previous.total_time_write_ns);
    let total_ops = read_ops.saturating_add(write_ops);

    let read_request_bytes = if read_ops > 0 {
        Some(read_bytes / read_ops as f64)
    } else {
        None
    };
    let write_request_bytes = if write_ops > 0 {
        Some(write_bytes / write_ops as f64)
    } else {
        None
    };
    let merge_rates = match (current.merges, previous.merges) {
        (Some((current_read, current_write)), Some((previous_read, previous_write))) => {
            MergeRates::Available {
                read_per_sec: current_read.saturating_sub(previous_read) as f64 / elapsed,
                write_per_sec: current_write.saturating_sub(previous_write) as f64 / elapsed,
            }
        }
        _ => MergeRates::Unavailable,
    };

    let queue_depth = match (current.weighted_io_time_ns, previous.weighted_io_time_ns) {
        (Some(current), Some(previous)) => {
            let weighted_seconds = current.saturating_sub(previous) as f64 / 1_000_000_000.0;
            Some(weighted_seconds / elapsed)
        }
        _ => None,
    };

    IntervalMetrics {
        read_bps: read_bytes / elapsed,
        write_bps: write_bytes / elapsed,
        read_iops: read_ops as f64 / elapsed,
        write_iops: write_ops as f64 / elapsed,
        avg_request_bytes: if total_ops > 0 {
            Some((read_bytes + write_bytes) / total_ops as f64)
        } else {
            None
        },
        workload: WorkloadSample {
            read_iops: read_ops as f64 / elapsed,
            write_iops: write_ops as f64 / elapsed,
            read_bps: read_bytes / elapsed,
            write_bps: write_bytes / elapsed,
            read_request_bytes,
            write_request_bytes,
            merge_rates,
        },
        queue_depth,
        await_sample: AwaitSample {
            read_us: if read_ops > 0 {
                Some((read_time as f64 / read_ops as f64) / 1_000.0)
            } else {
                None
            },
            write_us: if write_ops > 0 {
                Some((write_time as f64 / write_ops as f64) / 1_000.0)
            } else {
                None
            },
        },
    }
}

pub struct IoCollector {
    last_sample: Instant,
    prev_totals: HashMap<String, DeviceTotals>,
    pub history: HashMap<String, DeviceHistory>,
    /// Wall-clock-aligned per-request histogram deltas. Empty samples are
    /// retained so each device's p99 timeline represents real time.
    pub traced_history: HashMap<String, VecDeque<TracedLatencySample>>,
    pub latest: Vec<IoTick>,
    /// Bounded, host-wide VFS completed-byte activity sorted hottest first.
    pub hot_files: Vec<VfsFileActivity>,
    vfs_activity_window: VfsActivityWindow,
    latency_probe: EbpfLatencyCollector,
}

impl IoCollector {
    pub fn new() -> Self {
        Self {
            // Offset the baseline back so the first `sample()` actually runs.
            last_sample: Instant::now() - SAMPLE_INTERVAL,
            prev_totals: HashMap::new(),
            history: HashMap::new(),
            traced_history: HashMap::new(),
            latest: Vec::new(),
            hot_files: Vec::new(),
            vfs_activity_window: VfsActivityWindow::default(),
            latency_probe: EbpfLatencyCollector::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self {
            last_sample: Instant::now(),
            prev_totals: HashMap::new(),
            history: HashMap::new(),
            traced_history: HashMap::new(),
            latest: Vec::new(),
            hot_files: Vec::new(),
            vfs_activity_window: VfsActivityWindow::default(),
            latency_probe: EbpfLatencyCollector::unavailable_for_test(),
        }
    }

    pub fn latency_source(&self) -> LatencySource {
        self.latency_probe.source()
    }

    pub fn hot_files_source(&self) -> VfsActivitySource {
        self.latency_probe.vfs_source()
    }

    pub fn hot_files_status(&self) -> &EbpfStatus {
        self.latency_probe.vfs_status()
    }

    /// Called from the main loop. Internally rate-limits to 1Hz, so
    /// it's safe to call as often as the loop tick fires.
    pub fn sample(&mut self) {
        let now = Instant::now();
        let elapsed_dur = now - self.last_sample;
        if elapsed_dur < SAMPLE_INTERVAL {
            return;
        }
        let elapsed = elapsed_dur.as_secs_f64().max(0.001);
        self.last_sample = now;

        let totals = self.read_totals();
        let mut new_latest: Vec<IoTick> = Vec::new();
        for (device, t) in &totals {
            let Some(prev) = self.prev_totals.get(device).copied() else {
                // Cumulative kernel counters need one baseline observation.
                // Treating zero as the previous value would render all I/O
                // since boot as a single startup burst.
                continue;
            };

            let metrics = interval_metrics(*t, prev, elapsed);
            let read_bps = metrics.read_bps;
            let write_bps = metrics.write_bps;
            let bps = read_bps + write_bps;
            let sample_r_us = metrics.await_sample.read_us;
            let sample_w_us = metrics.await_sample.write_us;
            let latency_avg = if sample_r_us.is_some() || sample_w_us.is_some() {
                Some((sample_r_us.unwrap_or(0.0), sample_w_us.unwrap_or(0.0)))
            } else {
                None
            };

            let h = self.history.entry(device.clone()).or_default();
            record_history(h, metrics.workload, metrics.await_sample);

            // Recompute percentiles from the windows. Sorts a copy each
            // time — cheap at this scale (≤300 samples).
            let latency_pct = if !h.read_us.is_empty() || !h.write_us.is_empty() {
                let (p50_r, p99_r, p999_r) = percentiles(&h.read_us);
                let (p50_w, p99_w, p999_w) = percentiles(&h.write_us);
                Some(LatencyPct {
                    p50_r,
                    p99_r,
                    p999_r,
                    p50_w,
                    p99_w,
                    p999_w,
                })
            } else {
                None
            };

            new_latest.push(IoTick {
                device: device.clone(),
                bps,
                split: Some((read_bps, write_bps)),
                iops: metrics.read_iops + metrics.write_iops,
                iops_split: Some((metrics.read_iops, metrics.write_iops)),
                avg_request_bytes: metrics.avg_request_bytes,
                queue_depth: metrics.queue_depth,
                await_sample: metrics.await_sample,
                latency_avg,
                latency_pct,
            });
        }
        new_latest.sort_by(|a, b| a.device.cmp(&b.device));
        self.latest = new_latest;
        self.prev_totals = totals;
        self.sample_traced_latency();
        self.sample_hot_files(elapsed);
    }

    fn sample_hot_files(&mut self, elapsed: f64) {
        if self.latency_probe.vfs_source() != VfsActivitySource::EbpfCompletedBytes {
            self.hot_files.clear();
            self.vfs_activity_window.clear();
            return;
        }
        let deltas = self.latency_probe.vfs_snapshot();
        if self.latency_probe.vfs_source() != VfsActivitySource::EbpfCompletedBytes {
            self.hot_files.clear();
            self.vfs_activity_window.clear();
            return;
        }
        self.vfs_activity_window.push(deltas, elapsed);
        self.hot_files = self.vfs_activity_window.ranked(HOT_FILE_LIMIT);
        resolve_hot_file_paths(&mut self.hot_files);
        collapse_hot_file_processes(&mut self.hot_files);
        annotate_workload_processes(&mut self.hot_files);
    }

    fn sample_traced_latency(&mut self) {
        let source = self.latency_probe.source();
        reconcile_traced_history(source, &mut self.traced_history);
        if source != LatencySource::EbpfPerRequest {
            return;
        }

        let snapshots = self.latency_probe.snapshot();
        let source = self.latency_probe.source();
        reconcile_traced_history(source, &mut self.traced_history);
        if source != LatencySource::EbpfPerRequest {
            return;
        }

        let mut samples: HashMap<String, TracedLatencySample> = HashMap::new();
        for snapshot in snapshots {
            let Some(device) = block_device_name(snapshot.device) else {
                continue;
            };
            let sample = samples.entry(device).or_default();
            let destination = match snapshot.direction {
                IoDirection::Read => &mut sample.read,
                IoDirection::Write => &mut sample.write,
            };
            for (index, bucket) in snapshot.buckets.into_iter().enumerate() {
                if let Some(count) = destination.get_mut(index) {
                    *count = bucket.count;
                }
            }
        }

        for tick in &self.latest {
            let sample = samples.remove(&tick.device).unwrap_or_default();
            let history = self.traced_history.entry(tick.device.clone()).or_default();
            push_ring(history, sample, LATENCY_WINDOW);
        }
    }

    fn read_totals(&self) -> HashMap<String, DeviceTotals> {
        #[cfg(target_os = "macos")]
        {
            totals_macos()
        }
        #[cfg(target_os = "linux")]
        {
            diskstats_totals_linux()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            HashMap::new()
        }
    }
}

fn fallback_file_path(basename: &str, inode: u64) -> String {
    if basename.is_empty() {
        format!("inode {inode}")
    } else {
        format!("{basename} [inode {inode}]")
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct VfsActivityKey {
    device: BlockDeviceId,
    inode: u64,
    tgid: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct VfsActivityCounts {
    read_bytes: f64,
    write_bytes: f64,
    read_ops: f64,
    write_ops: f64,
}

impl VfsActivityCounts {
    fn add(&mut self, other: Self) {
        self.read_bytes += other.read_bytes;
        self.write_bytes += other.write_bytes;
        self.read_ops += other.read_ops;
        self.write_ops += other.write_ops;
    }

    fn subtract_scaled(&mut self, other: Self, scale: f64) {
        self.read_bytes = (self.read_bytes - other.read_bytes * scale).max(0.0);
        self.write_bytes = (self.write_bytes - other.write_bytes * scale).max(0.0);
        self.read_ops = (self.read_ops - other.read_ops * scale).max(0.0);
        self.write_ops = (self.write_ops - other.write_ops * scale).max(0.0);
    }

    fn scale(&mut self, scale: f64) {
        self.read_bytes *= scale;
        self.write_bytes *= scale;
        self.read_ops *= scale;
        self.write_ops *= scale;
    }

    fn is_empty(self) -> bool {
        self.read_bytes == 0.0
            && self.write_bytes == 0.0
            && self.read_ops == 0.0
            && self.write_ops == 0.0
    }
}

#[derive(Clone, Debug)]
struct VfsActivityTotal {
    counts: VfsActivityCounts,
    pid: u32,
    comm: String,
    container_owned: bool,
    basename: String,
    path: String,
}

#[derive(Debug)]
struct VfsActivityFrame {
    elapsed: f64,
    counts: HashMap<VfsActivityKey, VfsActivityCounts>,
}

/// A time-weighted rolling sum of requested VFS operations. This queue retains
/// only frames intersecting the last ten seconds and therefore has a fixed
/// time/memory bound at the 1 Hz collector cadence. No file tree is watched or
/// traversed.
#[derive(Debug, Default)]
struct VfsActivityWindow {
    frames: VecDeque<VfsActivityFrame>,
    totals: HashMap<VfsActivityKey, VfsActivityTotal>,
    elapsed: f64,
}

impl VfsActivityWindow {
    fn clear(&mut self) {
        self.frames.clear();
        self.totals.clear();
        self.elapsed = 0.0;
    }

    fn push(&mut self, deltas: Vec<VfsActivityDelta>, elapsed: f64) {
        let window = VFS_ACTIVITY_WINDOW.as_secs_f64();
        let elapsed = elapsed.max(0.001);
        let retained_elapsed = elapsed.min(window);
        // If collection was delayed beyond the window, assume activity was
        // uniform across that interval. This preserves the observed rate
        // without presenting old counts as a ten-second burst.
        let retained_fraction = retained_elapsed / elapsed;
        let mut frame_counts = HashMap::<VfsActivityKey, VfsActivityCounts>::new();

        if elapsed >= window {
            self.clear();
        }

        for delta in deltas {
            let key = VfsActivityKey {
                device: delta.device,
                inode: delta.inode,
                tgid: delta.tgid,
            };
            let mut counts = VfsActivityCounts {
                read_bytes: delta.read_bytes as f64,
                write_bytes: delta.write_bytes as f64,
                read_ops: delta.read_ops as f64,
                write_ops: delta.write_ops as f64,
            };
            counts.scale(retained_fraction);
            frame_counts.entry(key.clone()).or_default().add(counts);
            let total = self.totals.entry(key).or_insert_with(|| VfsActivityTotal {
                counts: VfsActivityCounts::default(),
                pid: delta.pid,
                comm: delta.comm.clone(),
                container_owned: delta.container_owned,
                basename: delta.basename.clone(),
                path: delta.path.clone(),
            });
            total.counts.add(counts);
            // Keep presentation metadata current if a PID or filename is
            // refreshed while the same filesystem identity remains hot.
            total.pid = delta.pid;
            total.comm = delta.comm;
            total.container_owned |= delta.container_owned;
            total.basename = delta.basename;
            if !delta.path.is_empty() {
                total.path = delta.path;
            }
        }

        self.frames.push_back(VfsActivityFrame {
            elapsed: retained_elapsed,
            counts: frame_counts,
        });
        self.elapsed += retained_elapsed;
        self.trim_to(window);
    }

    fn trim_to(&mut self, window: f64) {
        let mut overflow = (self.elapsed - window).max(0.0);
        while overflow > f64::EPSILON {
            let Some(front_elapsed) = self.frames.front().map(|frame| frame.elapsed) else {
                break;
            };
            if front_elapsed <= overflow + f64::EPSILON {
                let frame = self.frames.pop_front().expect("front frame exists");
                subtract_vfs_counts(&mut self.totals, &frame.counts, 1.0);
                self.elapsed -= frame.elapsed;
                overflow -= frame.elapsed;
            } else {
                let scale = overflow / front_elapsed;
                let frame = self.frames.front_mut().expect("front frame exists");
                subtract_vfs_counts(&mut self.totals, &frame.counts, scale);
                for counts in frame.counts.values_mut() {
                    counts.scale(1.0 - scale);
                }
                frame.elapsed -= overflow;
                self.elapsed -= overflow;
                overflow = 0.0;
            }
        }
    }

    fn ranked(&self, limit: usize) -> Vec<VfsFileActivity> {
        let elapsed = self.elapsed.max(0.001);
        let mut activity: Vec<_> = self
            .totals
            .iter()
            .map(|(key, total)| VfsFileActivity {
                fs_device: key.device,
                inode: key.inode,
                pid: total.pid,
                tgid: key.tgid,
                path: if total.path.is_empty() {
                    fallback_file_path(&total.basename, key.inode)
                } else {
                    total.path.clone()
                },
                comm: total.comm.clone(),
                processes: vec![(total.comm.clone(), total.pid, key.tgid)],
                display_processes: vec![(total.comm.clone(), key.tgid)],
                display_workloads: total
                    .container_owned
                    .then(|| (key.tgid, "container".to_string()))
                    .into_iter()
                    .collect(),
                basename: total.basename.clone(),
                read_bps: total.counts.read_bytes / elapsed,
                write_bps: total.counts.write_bytes / elapsed,
                read_ops: total.counts.read_ops / elapsed,
                write_ops: total.counts.write_ops / elapsed,
            })
            .collect();
        merge_vfs_processes(&mut activity);
        rank_vfs_activity(&mut activity, limit);
        activity
    }
}

fn merge_vfs_processes(activity: &mut Vec<VfsFileActivity>) {
    let mut merged = HashMap::<(BlockDeviceId, u64), VfsFileActivity>::new();
    for item in activity.drain(..) {
        let key = (item.fs_device, item.inode);
        if let Some(existing) = merged.get_mut(&key) {
            existing.read_bps += item.read_bps;
            existing.write_bps += item.write_bps;
            existing.read_ops += item.read_ops;
            existing.write_ops += item.write_ops;
            existing.processes.extend(item.processes);
            existing.display_workloads.extend(item.display_workloads);
            if existing.path.starts_with(&existing.basename)
                && !item.path.starts_with(&item.basename)
            {
                existing.path = item.path;
            }
        } else {
            merged.insert(key, item);
        }
    }
    for item in merged.values_mut() {
        item.processes
            .sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)).then(a.1.cmp(&b.1)));
        item.processes.dedup();
        item.display_processes = item
            .processes
            .iter()
            .map(|(comm, _, tgid)| (comm.clone(), *tgid))
            .collect();
        item.display_processes.sort();
        item.display_processes.dedup();
        item.display_workloads.sort();
        item.display_workloads.dedup();
    }
    activity.extend(merged.into_values());
}

fn subtract_vfs_counts(
    totals: &mut HashMap<VfsActivityKey, VfsActivityTotal>,
    counts: &HashMap<VfsActivityKey, VfsActivityCounts>,
    scale: f64,
) {
    let mut empty = Vec::new();
    for (key, contribution) in counts {
        if let Some(total) = totals.get_mut(key) {
            total.counts.subtract_scaled(*contribution, scale);
            if total.counts.is_empty() {
                empty.push(key.clone());
            }
        }
    }
    for key in empty {
        totals.remove(&key);
    }
}

fn rank_vfs_activity(activity: &mut Vec<VfsFileActivity>, limit: usize) {
    activity.sort_by(|a, b| {
        let a_total = a.read_bps + a.write_bps;
        let b_total = b.read_bps + b.write_bps;
        b_total
            .partial_cmp(&a_total)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.tgid.cmp(&b.tgid))
            .then_with(|| a.inode.cmp(&b.inode))
    });
    activity.truncate(limit);
}

/// Opportunistically resolves only already-ranked candidates. Each process's
/// fd directory is scanned at most once and each scan is capped; no filesystem
/// tree traversal occurs.
#[cfg(target_os = "linux")]
fn resolve_hot_file_paths(activity: &mut [VfsFileActivity]) {
    resolve_hot_file_paths_at(activity, std::path::Path::new("/proc"));
}

#[cfg(target_os = "linux")]
fn resolve_hot_file_paths_at(activity: &mut [VfsFileActivity], proc_root: &std::path::Path) {
    use std::collections::{HashMap as StdHashMap, HashSet};
    use std::os::unix::fs::MetadataExt;

    let mut wanted: StdHashMap<u32, HashSet<(u32, u32, u32, u64)>> = StdHashMap::new();
    for item in activity.iter() {
        // Event-time eBPF capture is authoritative. Only unresolved entries
        // pay the bounded /proc descriptor scan cost.
        if item.path != fallback_file_path(&item.basename, item.inode) {
            continue;
        }
        for (_, pid, tgid) in &item.processes {
            let identity = (
                *tgid,
                item.fs_device.major,
                item.fs_device.minor,
                item.inode,
            );
            wanted.entry(*pid).or_default().insert(identity);
            wanted.entry(*tgid).or_default().insert(identity);
        }
    }

    let mut resolved: StdHashMap<(u32, u32, u32, u64), String> = StdHashMap::new();
    for (pid, keys) in wanted {
        let Ok(entries) = std::fs::read_dir(proc_root.join(pid.to_string()).join("fd")) else {
            continue;
        };
        for entry in entries.flatten().take(PROC_FD_SCAN_LIMIT) {
            // `/proc/<pid>/fd/*` entries are symlinks; follow them to compare
            // the open file's identity rather than the procfs symlink inode.
            let Ok(metadata) = std::fs::metadata(entry.path()) else {
                continue;
            };
            let dev = metadata.dev();
            let file_identity = (linux_dev_major(dev), linux_dev_minor(dev), metadata.ino());
            let Some(key) = keys
                .iter()
                .find(|key| (key.1, key.2, key.3) == file_identity)
            else {
                continue;
            };
            if let Ok(path) = std::fs::read_link(entry.path()) {
                resolved.insert(*key, path.to_string_lossy().into_owned());
            }
        }
    }

    for item in activity {
        let path = item.processes.iter().find_map(|(_, _, tgid)| {
            resolved.get(&(
                *tgid,
                item.fs_device.major,
                item.fs_device.minor,
                item.inode,
            ))
        });
        if let Some(path) = path {
            item.path.clone_from(path);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn resolve_hot_file_paths(_activity: &mut [VfsFileActivity]) {}

#[cfg(target_os = "linux")]
fn collapse_hot_file_processes(activity: &mut [VfsFileActivity]) {
    collapse_hot_file_processes_at(activity, std::path::Path::new("/proc"));
}

#[cfg(target_os = "linux")]
fn collapse_hot_file_processes_at(activity: &mut [VfsFileActivity], proc_root: &std::path::Path) {
    let mut cache = HashMap::<u32, Option<(String, u32)>>::new();
    for item in activity {
        let candidates: Vec<_> = item
            .processes
            .iter()
            .map(|(comm, _, tgid)| {
                let parent = cache
                    .entry(*tgid)
                    .or_insert_with(|| parent_process_at(*tgid, proc_root))
                    .clone();
                ((comm.clone(), *tgid), parent)
            })
            .collect();
        let mut sibling_counts = HashMap::<(String, u32), usize>::new();
        for (_, parent) in &candidates {
            if let Some(parent) = parent {
                *sibling_counts.entry(parent.clone()).or_default() += 1;
            }
        }
        item.display_processes = candidates
            .into_iter()
            .map(|(child, parent)| {
                parent
                    .filter(|parent| sibling_counts.get(parent).copied().unwrap_or(0) >= 2)
                    .unwrap_or(child)
            })
            .collect();
        item.display_processes.sort();
        item.display_processes.dedup();
    }
}

#[cfg(target_os = "linux")]
fn parent_process_at(pid: u32, proc_root: &std::path::Path) -> Option<(String, u32)> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_name = stat.rsplit_once(')')?.1.trim_start();
    let mut fields = after_name.split_whitespace();
    fields.next()?; // state
    let parent = fields.next()?.parse::<u32>().ok()?;
    if parent <= 1 {
        return None;
    }
    let comm = std::fs::read_to_string(proc_root.join(parent.to_string()).join("comm"))
        .ok()?
        .trim()
        .to_string();
    (!comm.is_empty()).then_some((comm, parent))
}

#[cfg(not(target_os = "linux"))]
fn collapse_hot_file_processes(_activity: &mut [VfsFileActivity]) {}

#[cfg(target_os = "linux")]
fn annotate_workload_processes(activity: &mut [VfsFileActivity]) {
    annotate_workload_processes_at(activity, std::path::Path::new("/proc"));
}

#[cfg(target_os = "linux")]
fn annotate_workload_processes_at(activity: &mut [VfsFileActivity], proc_root: &std::path::Path) {
    let mut cache = HashMap::<u32, Option<String>>::new();
    for item in activity {
        for (_, pid) in &item.display_processes {
            let exact = cache
                .entry(*pid)
                .or_insert_with(|| workload_label_at(*pid, proc_root))
                .clone();
            if let Some(label) = exact {
                if let Some(existing) = item
                    .display_workloads
                    .iter_mut()
                    .find(|(workload_pid, _)| workload_pid == pid)
                {
                    existing.1 = label;
                } else {
                    item.display_workloads.push((*pid, label));
                }
            }
        }
        item.display_workloads.sort();
        item.display_workloads.dedup();
    }
}

#[cfg(not(target_os = "linux"))]
fn annotate_workload_processes(_activity: &mut [VfsFileActivity]) {}

#[cfg(target_os = "linux")]
fn workload_label_at(pid: u32, proc_root: &std::path::Path) -> Option<String> {
    let cgroups = std::fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    container_workload_label(&cgroups)
}

#[cfg(target_os = "linux")]
pub(crate) fn container_workload_label(cgroups: &str) -> Option<String> {
    for line in cgroups.lines() {
        let path = line.splitn(3, ':').nth(2)?;
        let components: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
        for (index, component) in components.iter().enumerate() {
            let scope = component.strip_suffix(".scope").unwrap_or(component);
            for (prefix, runtime) in [
                ("docker-", "docker"),
                ("libpod-", "podman"),
                ("cri-containerd-", "containerd"),
                ("crio-", "cri-o"),
            ] {
                if let Some(id) = scope.strip_prefix(prefix).filter(|id| container_id(id)) {
                    return Some(format!("{runtime} {}", &id[..id.len().min(12)]));
                }
            }
            if *component == "docker" {
                if let Some(id) = components.get(index + 1).filter(|id| container_id(id)) {
                    return Some(format!("docker {}", &id[..id.len().min(12)]));
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn container_id(value: &str) -> bool {
    value.len() >= 12 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Decode glibc's userspace dev_t representation (the inverse of makedev).
#[cfg(target_os = "linux")]
fn linux_dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000)) as u32
}

#[cfg(target_os = "linux")]
fn linux_dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & 0xffff_ff00)) as u32
}

fn reconcile_traced_history(
    source: LatencySource,
    history: &mut HashMap<String, VecDeque<TracedLatencySample>>,
) {
    if source != LatencySource::EbpfPerRequest {
        history.clear();
    }
}

#[cfg(target_os = "linux")]
fn block_device_name(device: BlockDeviceId) -> Option<String> {
    let path = format!("/sys/dev/block/{}:{}", device.major, device.minor);
    std::fs::canonicalize(path)
        .ok()?
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

#[cfg(not(target_os = "linux"))]
fn block_device_name(_device: BlockDeviceId) -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn totals_macos() -> HashMap<String, DeviceTotals> {
    let raw = crate::collect::iokit::collect();
    raw.into_iter()
        .map(|(name, s)| {
            (
                name,
                DeviceTotals {
                    bytes_read: s.bytes_read,
                    bytes_written: s.bytes_written,
                    ops_read: s.ops_read,
                    ops_written: s.ops_written,
                    merges: None,
                    total_time_read_ns: s.total_time_read_ns,
                    total_time_write_ns: s.total_time_write_ns,
                    weighted_io_time_ns: None,
                },
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn diskstats_totals_linux() -> HashMap<String, DeviceTotals> {
    let Ok(text) = std::fs::read_to_string("/proc/diskstats") else {
        return HashMap::new();
    };
    parse_diskstats_linux(&text)
}

#[cfg(target_os = "linux")]
fn parse_diskstats_linux(text: &str) -> HashMap<String, DeviceTotals> {
    const SECTOR_BYTES: u64 = 512;
    const MS_TO_NS: u64 = 1_000_000;
    let mut out = HashMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 11 {
            continue;
        }
        let name = fields[2];
        if name.starts_with("loop") || name.starts_with("ram") {
            continue;
        }
        if is_partition_name(name) {
            continue;
        }
        let Ok(reads) = fields[3].parse::<u64>() else {
            continue;
        };
        let Ok(reads_merged) = fields[4].parse::<u64>() else {
            continue;
        };
        let Ok(sectors_read) = fields[5].parse::<u64>() else {
            continue;
        };
        let Ok(ms_reading) = fields[6].parse::<u64>() else {
            continue;
        };
        let Ok(writes) = fields[7].parse::<u64>() else {
            continue;
        };
        let Ok(writes_merged) = fields[8].parse::<u64>() else {
            continue;
        };
        let Ok(sectors_written) = fields[9].parse::<u64>() else {
            continue;
        };
        let Ok(ms_writing) = fields[10].parse::<u64>() else {
            continue;
        };
        let weighted_ms = fields.get(13).and_then(|value| value.parse::<u64>().ok());
        out.insert(
            name.to_string(),
            DeviceTotals {
                bytes_read: sectors_read.saturating_mul(SECTOR_BYTES),
                bytes_written: sectors_written.saturating_mul(SECTOR_BYTES),
                ops_read: reads,
                ops_written: writes,
                merges: Some((reads_merged, writes_merged)),
                total_time_read_ns: ms_reading.saturating_mul(MS_TO_NS),
                total_time_write_ns: ms_writing.saturating_mul(MS_TO_NS),
                weighted_io_time_ns: weighted_ms.map(|ms| ms.saturating_mul(MS_TO_NS)),
            },
        );
    }
    out
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_partition_name(name: &str) -> bool {
    if name.starts_with("nvme") {
        return name.contains('p');
    }
    if name.starts_with("mmcblk") {
        return name.contains('p');
    }
    if name.starts_with("dm-") {
        return false;
    }
    name.chars()
        .last()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
}

fn push_ring<T>(q: &mut VecDeque<T>, v: T, cap: usize) {
    if q.len() == cap {
        q.pop_front();
    }
    q.push_back(v);
}

fn record_history(
    history: &mut DeviceHistory,
    workload: WorkloadSample,
    await_sample: AwaitSample,
) {
    let bps = workload.read_bps + workload.write_bps;
    push_ring(&mut history.combined, bps, RING_LEN);
    push_ring(&mut history.workload_samples, workload, RING_LEN);
    push_ring(&mut history.await_samples, await_sample, LATENCY_WINDOW);
    if let Some(value) = await_sample.read_us {
        push_ring(&mut history.read_us, value, LATENCY_WINDOW);
    }
    if let Some(value) = await_sample.write_us {
        push_ring(&mut history.write_us, value, LATENCY_WINDOW);
    }
}

/// Returns (p50, p99, p999) of the values in `samples`. Empty input
/// yields zeros so the caller can use them in arithmetic without
/// branching.
fn percentiles(samples: &VecDeque<f64>) -> (f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mut v: Vec<f64> = samples.iter().copied().collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pct = |p: f64| {
        let idx = ((p / 100.0) * (v.len() - 1) as f64).round() as usize;
        v[idx.min(v.len() - 1)]
    };
    (pct(50.0), pct(99.0), pct(99.9))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totals(
        bytes_read: u64,
        bytes_written: u64,
        ops_read: u64,
        ops_written: u64,
        read_time_ns: u64,
        write_time_ns: u64,
        weighted_io_time_ns: Option<u64>,
    ) -> DeviceTotals {
        DeviceTotals {
            bytes_read,
            bytes_written,
            ops_read,
            ops_written,
            merges: None,
            total_time_read_ns: read_time_ns,
            total_time_write_ns: write_time_ns,
            weighted_io_time_ns,
        }
    }

    fn assert_near(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 0.000_001,
            "expected {expected}, got {actual}"
        );
    }

    fn vfs_delta(inode: u64, read_bytes: u64, write_bytes: u64) -> VfsActivityDelta {
        VfsActivityDelta {
            device: BlockDeviceId { major: 8, minor: 1 },
            inode,
            pid: 101,
            tgid: 100,
            comm: "writer".into(),
            container_owned: false,
            basename: format!("file-{inode}"),
            path: String::new(),
            read_bytes,
            write_bytes,
            read_ops: 2,
            write_ops: 3,
        }
    }

    #[test]
    fn hot_file_ranking_uses_total_completed_rate_and_limit() {
        let mut window = VfsActivityWindow::default();
        window.push(vec![vfs_delta(1, 100, 0), vfs_delta(2, 50, 200)], 0.5);
        let ranked = window.ranked(1);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].inode, 2);
        assert_near(ranked[0].read_bps, 100.0);
        assert_near(ranked[0].write_bps, 400.0);
        assert_near(ranked[0].read_ops, 4.0);
        assert_near(ranked[0].write_ops, 6.0);
    }

    #[test]
    fn hot_file_rows_merge_processes_and_rates_by_file_identity() {
        let mut first = vfs_delta(42, 100, 0);
        first.comm = "alpha".into();
        first.pid = 101;
        first.tgid = 100;
        let mut second = vfs_delta(42, 0, 50);
        second.comm = "beta".into();
        second.pid = 201;
        second.tgid = 200;
        let mut window = VfsActivityWindow::default();
        window.push(vec![first, second], 1.0);

        let ranked = window.ranked(64);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].read_bps, 100.0);
        assert_eq!(ranked[0].write_bps, 50.0);
        assert_eq!(
            ranked[0].processes,
            vec![("alpha".into(), 101, 100), ("beta".into(), 201, 200)]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hot_file_processes_collapse_to_a_common_parent() {
        let root =
            std::env::temp_dir().join(format!("iodyne-parent-fixture-{}", std::process::id()));
        for pid in [100_u32, 101, 200] {
            std::fs::create_dir_all(root.join(pid.to_string())).unwrap();
        }
        std::fs::write(root.join("100/stat"), "100 (relay one) S 200 0 0 0\n").unwrap();
        std::fs::write(root.join("101/stat"), "101 (relay two) S 200 0 0 0\n").unwrap();
        std::fs::write(root.join("200/comm"), "codex\n").unwrap();

        let mut item = VfsActivityWindow::default();
        let mut first = vfs_delta(42, 1, 0);
        first.comm = "Relay(1)".into();
        first.pid = 100;
        first.tgid = 100;
        let mut second = vfs_delta(42, 1, 0);
        second.comm = "Relay(2)".into();
        second.pid = 101;
        second.tgid = 101;
        item.push(vec![first, second], 1.0);
        let mut activity = item.ranked(64);
        collapse_hot_file_processes_at(&mut activity, &root);

        assert_eq!(activity[0].display_processes, vec![("codex".into(), 200)]);
        assert_eq!(activity[0].processes.len(), 2);

        let mut single = VfsActivityWindow::default();
        let mut child = vfs_delta(43, 1, 0);
        child.comm = "worker".into();
        child.pid = 100;
        child.tgid = 100;
        single.push(vec![child], 1.0);
        let mut activity = single.ranked(64);
        collapse_hot_file_processes_at(&mut activity, &root);
        assert_eq!(activity[0].display_processes, vec![("worker".into(), 100)]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn container_workloads_are_parsed_from_common_cgroup_layouts() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            container_workload_label(&format!("0::/system.slice/docker-{id}.scope\n")),
            Some("docker 0123456789ab".into())
        );
        assert_eq!(
            container_workload_label(&format!("8:cpu:/docker/{id}\n")),
            Some("docker 0123456789ab".into())
        );
        assert_eq!(
            container_workload_label(&format!("0::/user.slice/libpod-{id}.scope\n")),
            Some("podman 0123456789ab".into())
        );
        assert_eq!(
            container_workload_label(&format!("0::/kubepods.slice/cri-containerd-{id}.scope\n")),
            Some("containerd 0123456789ab".into())
        );
        assert_eq!(container_workload_label("0::/user.slice/app.scope\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn displayed_processes_receive_workload_labels() {
        let root =
            std::env::temp_dir().join(format!("iodyne-cgroup-fixture-{}", std::process::id()));
        std::fs::create_dir_all(root.join("100")).unwrap();
        std::fs::write(
            root.join("100/cgroup"),
            "0::/system.slice/docker-0123456789abcdef.scope\n",
        )
        .unwrap();
        let mut window = VfsActivityWindow::default();
        let mut delta = vfs_delta(42, 1, 0);
        delta.container_owned = true;
        window.push(vec![delta], 1.0);
        let mut activity = window.ranked(64);

        annotate_workload_processes_at(&mut activity, &root);

        assert_eq!(
            activity[0].display_workloads,
            vec![(100, "docker 0123456789ab".into())]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_overlay_container_marker_survives_requester_exit() {
        let mut delta = vfs_delta(42, 1, 0);
        delta.container_owned = true;
        let mut window = VfsActivityWindow::default();
        window.push(vec![delta], 1.0);
        let mut activity = window.ranked(64);

        annotate_workload_processes_at(&mut activity, std::path::Path::new("/does/not/exist"));

        assert_eq!(
            activity[0].display_workloads,
            vec![(100, "container".into())]
        );
    }

    #[test]
    fn event_time_path_is_preferred_and_survives_empty_later_samples() {
        let mut window = VfsActivityWindow::default();
        let mut first = vfs_delta(1, 100, 0);
        first.path = "/srv/archive/data.bin".into();
        window.push(vec![first], 1.0);
        window.push(vec![vfs_delta(1, 50, 0)], 1.0);

        assert_eq!(window.ranked(1)[0].path, "/srv/archive/data.bin");
    }

    #[test]
    fn hot_file_rates_average_over_rolling_window_including_idle_time() {
        let mut window = VfsActivityWindow::default();
        window.push(vec![vfs_delta(1, 1_000, 0)], 1.0);
        window.push(Vec::new(), 1.0);

        let ranked = window.ranked(64);
        assert_eq!(ranked.len(), 1);
        assert_near(ranked[0].read_bps, 500.0);
        assert_near(ranked[0].read_ops, 1.0);
    }

    #[test]
    fn hot_file_activity_expires_after_ten_seconds() {
        let mut window = VfsActivityWindow::default();
        window.push(vec![vfs_delta(1, 1_000, 0)], 1.0);
        window.push(Vec::new(), 9.0);
        assert_near(window.ranked(64)[0].read_bps, 100.0);

        window.push(Vec::new(), 1.0);
        assert!(window.ranked(64).is_empty());
        assert_near(window.elapsed, 10.0);
    }

    #[test]
    fn hot_file_window_trims_only_expired_fraction_of_oldest_sample() {
        let mut window = VfsActivityWindow::default();
        window.push(vec![vfs_delta(1, 600, 0)], 6.0);
        window.push(vec![vfs_delta(1, 800, 0)], 8.0);

        // Four of the first sample's six seconds expired, leaving 200 + 800
        // completed bytes in the ten-second window.
        assert_near(window.ranked(64)[0].read_bps, 100.0);
        assert_near(window.elapsed, 10.0);
    }

    #[test]
    fn delayed_hot_file_sample_preserves_observed_rate() {
        let mut window = VfsActivityWindow::default();
        window.push(vec![vfs_delta(1, 20_000, 0)], 20.0);

        assert_near(window.ranked(64)[0].read_bps, 1_000.0);
        assert_near(window.elapsed, 10.0);
        assert_eq!(window.frames.len(), 1);
    }

    #[test]
    fn clearing_hot_file_window_discards_rates_and_frames() {
        let mut window = VfsActivityWindow::default();
        window.push(vec![vfs_delta(1, 100, 0)], 1.0);
        window.clear();

        assert!(window.ranked(64).is_empty());
        assert!(window.frames.is_empty());
        assert_near(window.elapsed, 0.0);
    }

    #[test]
    fn unresolved_hot_file_path_is_explicit_inode_fallback() {
        assert_eq!(fallback_file_path("data.log", 42), "data.log [inode 42]");
        assert_eq!(fallback_file_path("", 42), "inode 42");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn userspace_dev_t_decodes_major_and_minor() {
        // glibc makedev(259, 65537)
        let dev = ((259_u64 & 0xffff_f000) << 32)
            | ((259_u64 & 0xfff) << 8)
            | ((65537_u64 & 0xffff_ff00) << 12)
            | (65537_u64 & 0xff);
        assert_eq!(linux_dev_major(dev), 259);
        assert_eq!(linux_dev_minor(dev), 65537);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_proc_fd_resolution_matches_device_and_inode() {
        use std::os::unix::fs::MetadataExt;

        let file = std::fs::File::open("Cargo.toml").unwrap();
        let metadata = file.metadata().unwrap();
        let pid = std::process::id();
        let mut activity = vec![VfsFileActivity {
            fs_device: BlockDeviceId {
                major: linux_dev_major(metadata.dev()),
                minor: linux_dev_minor(metadata.dev()),
            },
            inode: metadata.ino(),
            pid,
            tgid: pid,
            comm: "test".into(),
            processes: vec![("test".into(), pid, pid)],
            display_processes: vec![("test".into(), pid)],
            display_workloads: Vec::new(),
            basename: "Cargo.toml".into(),
            path: fallback_file_path("Cargo.toml", metadata.ino()),
            read_bps: 1.0,
            write_bps: 0.0,
            read_ops: 1.0,
            write_ops: 0.0,
        }];
        resolve_hot_file_paths(&mut activity);
        assert!(activity[0].path.ends_with("Cargo.toml"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_resolution_does_not_replace_event_time_path() {
        let mut activity = vec![VfsFileActivity {
            fs_device: BlockDeviceId { major: 8, minor: 1 },
            inode: 42,
            pid: std::process::id(),
            tgid: std::process::id(),
            comm: "test".into(),
            processes: vec![("test".into(), std::process::id(), std::process::id())],
            display_processes: vec![("test".into(), std::process::id())],
            display_workloads: Vec::new(),
            basename: "data.log".into(),
            path: "/captured/at/event/time/data.log".into(),
            read_bps: 1.0,
            write_bps: 0.0,
            read_ops: 1.0,
            write_ops: 0.0,
        }];

        resolve_hot_file_paths_at(&mut activity, std::path::Path::new("/does/not/exist"));
        assert_eq!(activity[0].path, "/captured/at/event/time/data.log");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_fd_resolution_checks_the_recorded_task_before_the_group_leader() {
        use std::os::unix::fs::{symlink, MetadataExt};

        let file = std::fs::File::open("Cargo.toml").unwrap();
        let metadata = file.metadata().unwrap();
        let root = std::env::temp_dir().join(format!(
            "iodyne-proc-fixture-{}-{}",
            std::process::id(),
            metadata.ino()
        ));
        let task_pid = 2001;
        let leader_pid = 2000;
        let fd_dir = root.join(task_pid.to_string()).join("fd");
        std::fs::create_dir_all(&fd_dir).unwrap();
        symlink(
            std::fs::canonicalize("Cargo.toml").unwrap(),
            fd_dir.join("7"),
        )
        .unwrap();

        let mut activity = vec![VfsFileActivity {
            fs_device: BlockDeviceId {
                major: linux_dev_major(metadata.dev()),
                minor: linux_dev_minor(metadata.dev()),
            },
            inode: metadata.ino(),
            pid: task_pid,
            tgid: leader_pid,
            comm: "worker".into(),
            processes: vec![("worker".into(), task_pid, leader_pid)],
            display_processes: vec![("worker".into(), leader_pid)],
            display_workloads: Vec::new(),
            basename: "Cargo.toml".into(),
            path: fallback_file_path("Cargo.toml", metadata.ino()),
            read_bps: 1.0,
            write_bps: 0.0,
            read_ops: 1.0,
            write_ops: 0.0,
        }];

        resolve_hot_file_paths_at(&mut activity, &root);
        assert!(activity[0].path.ends_with("Cargo.toml"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sata_disks_and_partitions() {
        assert!(!is_partition_name("sda"));
        assert!(!is_partition_name("sdb"));
        assert!(is_partition_name("sda1"));
        assert!(is_partition_name("sdb12"));
    }

    #[test]
    fn nvme_disks_and_partitions() {
        assert!(!is_partition_name("nvme0n1"));
        assert!(is_partition_name("nvme0n1p1"));
        assert!(is_partition_name("nvme1n2p5"));
    }

    #[test]
    fn mmc_quirks() {
        assert!(!is_partition_name("mmcblk0"));
        assert!(is_partition_name("mmcblk0p1"));
    }

    #[test]
    fn device_mapper_is_whole() {
        assert!(!is_partition_name("dm-0"));
        assert!(!is_partition_name("dm-12"));
    }

    #[test]
    fn interval_rates_request_size_await_and_queue() {
        let previous = totals(
            1_000,
            2_000,
            100,
            50,
            1_000_000_000,
            2_000_000_000,
            Some(3_000_000_000),
        );
        let current = totals(
            51_000,
            27_000,
            120,
            55,
            1_040_000_000,
            2_050_000_000,
            Some(3_750_000_000),
        );

        let metrics = interval_metrics(current, previous, 0.5);
        assert_near(metrics.read_bps, 100_000.0);
        assert_near(metrics.write_bps, 50_000.0);
        assert_near(metrics.read_iops, 40.0);
        assert_near(metrics.write_iops, 10.0);
        assert_near(metrics.avg_request_bytes.unwrap(), 3_000.0);
        assert_near(metrics.workload.read_request_bytes.unwrap(), 2_500.0);
        assert_near(metrics.workload.write_request_bytes.unwrap(), 5_000.0);
        assert_eq!(metrics.workload.merge_rates, MergeRates::Unavailable);
        assert_near(metrics.queue_depth.unwrap(), 1.5);
        assert_near(metrics.await_sample.read_us.unwrap(), 2_000.0);
        assert_near(metrics.await_sample.write_us.unwrap(), 10_000.0);
    }

    #[test]
    fn interval_without_operations_has_no_request_size_or_await() {
        let previous = totals(1_000, 2_000, 100, 50, 1_000, 2_000, None);
        let metrics = interval_metrics(previous, previous, 0.2);

        assert_eq!(metrics.avg_request_bytes, None);
        assert_eq!(metrics.queue_depth, None);
        assert_eq!(metrics.await_sample, AwaitSample::default());
        assert_eq!(metrics.read_iops, 0.0);
        assert_eq!(metrics.write_iops, 0.0);
        assert_eq!(metrics.workload.read_request_bytes, None);
        assert_eq!(metrics.workload.write_request_bytes, None);
        assert_eq!(metrics.workload.merge_rates, MergeRates::Unavailable);
    }

    #[test]
    fn aligned_histories_preserve_idle_ticks() {
        let mut history = DeviceHistory::default();
        let first = AwaitSample {
            read_us: Some(500.0),
            write_us: None,
        };
        let idle = AwaitSample::default();
        let third = AwaitSample {
            read_us: None,
            write_us: Some(2_000.0),
        };

        let workloads = [
            WorkloadSample {
                read_iops: 1.0,
                read_bps: 1_000.0,
                ..WorkloadSample::default()
            },
            WorkloadSample::default(),
            WorkloadSample {
                write_iops: 1.0,
                write_bps: 2_000.0,
                ..WorkloadSample::default()
            },
        ];

        record_history(&mut history, workloads[0], first);
        record_history(&mut history, workloads[1], idle);
        record_history(&mut history, workloads[2], third);

        assert_eq!(
            history.workload_samples.iter().copied().collect::<Vec<_>>(),
            workloads
        );
        assert_eq!(
            history.combined.iter().copied().collect::<Vec<_>>(),
            vec![1_000.0, 0.0, 2_000.0]
        );
        assert_eq!(
            history.await_samples.iter().copied().collect::<Vec<_>>(),
            vec![first, idle, third]
        );
        assert_eq!(
            history.read_us.iter().copied().collect::<Vec<_>>(),
            vec![500.0]
        );
        assert_eq!(
            history.write_us.iter().copied().collect::<Vec<_>>(),
            vec![2_000.0]
        );
    }

    #[test]
    fn directional_merge_rates_preserve_available_zero() {
        let previous = DeviceTotals {
            merges: Some((10, 20)),
            ..DeviceTotals::default()
        };
        let current = DeviceTotals {
            merges: Some((13, 20)),
            ..DeviceTotals::default()
        };

        assert_eq!(
            interval_metrics(current, previous, 0.5)
                .workload
                .merge_rates,
            MergeRates::Available {
                read_per_sec: 6.0,
                write_per_sec: 0.0,
            }
        );
    }

    #[test]
    fn merge_rates_are_unavailable_when_platform_has_no_counters() {
        let previous = DeviceTotals::default();
        let current = DeviceTotals {
            bytes_read: 4_096,
            ops_read: 1,
            ..DeviceTotals::default()
        };

        assert_eq!(
            interval_metrics(current, previous, 1.0)
                .workload
                .merge_rates,
            MergeRates::Unavailable
        );
    }

    #[test]
    fn workload_history_is_capped_without_losing_alignment() {
        let mut history = DeviceHistory::default();
        for second in 0..=RING_LEN {
            record_history(
                &mut history,
                WorkloadSample {
                    read_iops: second as f64,
                    ..WorkloadSample::default()
                },
                AwaitSample::default(),
            );
        }

        assert_eq!(history.workload_samples.len(), RING_LEN);
        assert_eq!(history.await_samples.len(), RING_LEN);
        assert_eq!(history.combined.len(), RING_LEN);
        assert_eq!(history.workload_samples.front().unwrap().read_iops, 1.0);
        assert_eq!(
            history.workload_samples.back().unwrap().read_iops,
            RING_LEN as f64
        );
    }

    #[test]
    fn aggregate_fallback_clears_traced_history() {
        let mut history = HashMap::from([(
            "sda".to_string(),
            VecDeque::from([TracedLatencySample::default()]),
        )]);

        reconcile_traced_history(LatencySource::EbpfPerRequest, &mut history);
        assert_eq!(history.len(), 1);

        reconcile_traced_history(LatencySource::AggregateAwait, &mut history);
        assert!(history.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_diskstats_counters_including_weighted_io_time() {
        let input = concat!(
            "   8 0 sda 100 2 200 300 50 4 600 700 1 800 900 0 0 0 0\n",
            "   8 1 sda1 10 0 20 30 5 0 60 70 0 80 90 0 0 0 0\n",
            "   7 0 loop0 1 0 2 3 4 0 5 6 0 7 8 0 0 0 0\n",
        );

        let parsed = parse_diskstats_linux(input);
        assert_eq!(parsed.len(), 1);
        let disk = parsed.get("sda").unwrap();
        assert_eq!(disk.bytes_read, 200 * 512);
        assert_eq!(disk.bytes_written, 600 * 512);
        assert_eq!(disk.ops_read, 100);
        assert_eq!(disk.ops_written, 50);
        assert_eq!(disk.merges, Some((2, 4)));
        assert_eq!(disk.total_time_read_ns, 300_000_000);
        assert_eq!(disk.total_time_write_ns, 700_000_000);
        assert_eq!(disk.weighted_io_time_ns, Some(900_000_000));
    }

    #[test]
    fn percentiles_basic() {
        let v: VecDeque<f64> = (1..=100).map(|x| x as f64).collect();
        let (p50, p99, p999) = percentiles(&v);
        // Nearest-rank with (N-1) indexing: idx = round(p * 99 / 100).
        // p50 → idx 50 → v[50] = 51.
        // p99 → idx 98 → v[98] = 99.
        // p999 → idx 99 → v[99] = 100.
        assert_eq!(p50, 51.0);
        assert_eq!(p99, 99.0);
        assert_eq!(p999, 100.0);
    }

    #[test]
    fn percentiles_with_outlier() {
        // 99 fast samples + 1 huge outlier. With only 100 samples, the
        // outlier surfaces at p99.9 (round(0.999 * 99) = 99 → last
        // value) but not at p99 (round(0.99 * 99) = 98 → second-last).
        // This is the limitation the IO tab footer note is about.
        let mut v: VecDeque<f64> = (0..99).map(|_| 100.0).collect();
        v.push_back(50_000.0);
        let (p50, p99, p999) = percentiles(&v);
        assert_eq!(p50, 100.0);
        assert_eq!(p99, 100.0);
        assert_eq!(p999, 50_000.0);
    }

    #[test]
    fn percentiles_empty() {
        let v: VecDeque<f64> = VecDeque::new();
        assert_eq!(percentiles(&v), (0.0, 0.0, 0.0));
    }
}
