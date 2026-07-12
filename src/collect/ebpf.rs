//! Optional per-request block latency collection.
//!
//! The UI can construct this collector unconditionally. Builds without the
//! `ebpf` feature, non-Linux systems, and Linux systems which reject BPF loads
//! all report an ordinary status and continue using `/proc/diskstats`.

use std::collections::HashMap;

pub const LATENCY_BUCKETS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlockDeviceId {
    pub major: u32,
    pub minor: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IoDirection {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LatencySource {
    AggregateAwait,
    EbpfPerRequest,
}

/// Source and byte semantics for filesystem activity attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsActivitySource {
    Unavailable,
    /// Counts the byte count requested at `vfs_read`/`vfs_write` entry.
    /// This is not the syscall return value or physical-device traffic.
    EbpfRequestedBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum EbpfStatus {
    Active,
    DisabledAtBuild,
    UnsupportedPlatform,
    Unavailable(String),
}

fn independent_vfs_status(result: Result<(), String>) -> EbpfStatus {
    result.map_or_else(EbpfStatus::Unavailable, |_| EbpfStatus::Active)
}

impl EbpfStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatencyBucket {
    /// Inclusive lower bound in microseconds.
    pub lower_us: u64,
    /// Exclusive upper bound. `None` means the final overflow bucket.
    pub upper_us: Option<u64>,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceLatencyHistogram {
    pub device: BlockDeviceId,
    pub direction: IoDirection,
    pub source: LatencySource,
    pub buckets: Vec<LatencyBucket>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
struct HistogramKey {
    major: u32,
    minor: u32,
    direction: u32,
    bucket: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
struct VfsFileKey {
    major: u32,
    minor: u32,
    inode: u64,
    tgid: u32,
    _padding: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct VfsFileValue {
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
    pid: u32,
    _padding: u32,
    comm: [u8; 16],
    basename: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VfsActivityDelta {
    pub device: BlockDeviceId,
    pub inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub basename: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
unsafe impl aya::Pod for HistogramKey {}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
unsafe impl aya::Pod for VfsFileKey {}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
unsafe impl aya::Pod for VfsFileValue {}

pub struct EbpfLatencyCollector {
    status: EbpfStatus,
    vfs_status: EbpfStatus,
    previous: HashMap<HistogramKey, u64>,
    vfs_previous: HashMap<VfsFileKey, VfsFileValue>,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    latency_bpf: Option<aya::Bpf>,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    vfs_bpf: Option<aya::Bpf>,
}

impl EbpfLatencyCollector {
    /// Loads and attaches the embedded programs when this build and host allow
    /// it. Permission, lockdown, verifier, and kernel-support errors are data,
    /// not process-fatal errors.
    pub fn new() -> Self {
        Self::load()
    }

    #[allow(dead_code)]
    pub fn status(&self) -> &EbpfStatus {
        &self.status
    }

    pub fn source(&self) -> LatencySource {
        if self.status.is_active() {
            LatencySource::EbpfPerRequest
        } else {
            LatencySource::AggregateAwait
        }
    }

    pub fn vfs_status(&self) -> &EbpfStatus {
        &self.vfs_status
    }

    pub fn vfs_source(&self) -> VfsActivitySource {
        if self.vfs_status.is_active() {
            VfsActivitySource::EbpfRequestedBytes
        } else {
            VfsActivitySource::Unavailable
        }
    }

    /// Returns counts accumulated since the previous call, grouped by device
    /// and direction. Empty histograms are omitted.
    pub fn snapshot(&mut self) -> Vec<DeviceLatencyHistogram> {
        let current = match self.read_counts() {
            Ok(counts) => counts,
            Err(message) => {
                self.status = EbpfStatus::Unavailable(message);
                return Vec::new();
            }
        };

        let delta = histogram_delta(&self.previous, &current);
        self.previous = current;
        snapshots_from_counts(delta)
    }

    /// Returns bounded per-file VFS requested-byte deltas since the previous
    /// sample. A VFS map failure disables only this capability.
    pub(crate) fn vfs_snapshot(&mut self) -> Vec<VfsActivityDelta> {
        if !self.vfs_status.is_active() {
            return Vec::new();
        }
        let current = match self.read_vfs_counts() {
            Ok(counts) => counts,
            Err(message) => {
                self.vfs_status = EbpfStatus::Unavailable(message);
                self.vfs_previous.clear();
                return Vec::new();
            }
        };
        let deltas = vfs_deltas(&self.vfs_previous, &current);
        self.vfs_previous = current;
        deltas
    }

    /// Discards all counts accumulated since the previous display sample.
    /// Used when resuming after a UI pause so the pause interval is not
    /// rendered as one oversized latency bucket.
    pub fn reset_baseline(&mut self) {
        if !self.status.is_active() {
            self.previous.clear();
        } else {
            match self.read_counts() {
                Ok(counts) => self.previous = counts,
                Err(message) => {
                    self.status = EbpfStatus::Unavailable(message);
                    self.previous.clear();
                }
            }
        }
        self.reset_vfs_baseline();
    }

    fn reset_vfs_baseline(&mut self) {
        if !self.vfs_status.is_active() {
            self.vfs_previous.clear();
            return;
        }
        match self.read_vfs_counts() {
            Ok(counts) => self.vfs_previous = counts,
            Err(message) => {
                self.vfs_status = EbpfStatus::Unavailable(message);
                self.vfs_previous.clear();
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn load() -> Self {
        match load_linux() {
            Ok(latency_bpf) => {
                let (vfs_bpf, vfs_status) = match load_vfs_linux() {
                    Ok(bpf) => (Some(bpf), EbpfStatus::Active),
                    Err(error) => (None, independent_vfs_status(Err(error))),
                };
                Self {
                    status: EbpfStatus::Active,
                    vfs_status,
                    previous: HashMap::new(),
                    vfs_previous: HashMap::new(),
                    latency_bpf: Some(latency_bpf),
                    vfs_bpf,
                }
            }
            Err(error) => Self {
                status: EbpfStatus::Unavailable(error.clone()),
                vfs_status: EbpfStatus::Unavailable(format!(
                    "block probe initialization failed before VFS attach: {error}"
                )),
                previous: HashMap::new(),
                vfs_previous: HashMap::new(),
                latency_bpf: None,
                vfs_bpf: None,
            },
        }
    }

    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    fn load() -> Self {
        Self {
            status: EbpfStatus::DisabledAtBuild,
            vfs_status: EbpfStatus::DisabledAtBuild,
            previous: HashMap::new(),
            vfs_previous: HashMap::new(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn load() -> Self {
        Self {
            status: EbpfStatus::UnsupportedPlatform,
            vfs_status: EbpfStatus::UnsupportedPlatform,
            previous: HashMap::new(),
            vfs_previous: HashMap::new(),
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn read_counts(&mut self) -> Result<HashMap<HistogramKey, u64>, String> {
        use aya::maps::PerCpuHashMap;

        let bpf = self
            .latency_bpf
            .as_mut()
            .ok_or_else(|| "eBPF collector is not loaded".to_string())?;
        let map = bpf
            .map_mut("HISTOGRAMS")
            .ok_or_else(|| "eBPF histogram map is missing".to_string())?;
        let map = PerCpuHashMap::<_, HistogramKey, u64>::try_from(map)
            .map_err(|error| format!("cannot access eBPF histogram map: {error}"))?;
        map.iter()
            .map(|entry| {
                let (key, counts) =
                    entry.map_err(|error| format!("cannot read eBPF histogram: {error}"))?;
                Ok((key, counts.iter().copied().fold(0_u64, u64::saturating_add)))
            })
            .collect()
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn read_vfs_counts(&mut self) -> Result<HashMap<VfsFileKey, VfsFileValue>, String> {
        use aya::maps::HashMap as AyaHashMap;

        let bpf = self
            .vfs_bpf
            .as_mut()
            .ok_or_else(|| "eBPF collector is not loaded".to_string())?;
        let map = bpf
            .map_mut("VFS_FILES")
            .ok_or_else(|| "eBPF VFS activity map is missing".to_string())?;
        let map = AyaHashMap::<_, VfsFileKey, VfsFileValue>::try_from(map)
            .map_err(|error| format!("cannot access eBPF VFS activity map: {error}"))?;
        map.iter()
            .map(|entry| entry.map_err(|error| format!("cannot read eBPF VFS activity: {error}")))
            .collect()
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn read_counts(&mut self) -> Result<HashMap<HistogramKey, u64>, String> {
        Ok(HashMap::new())
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn read_vfs_counts(&mut self) -> Result<HashMap<VfsFileKey, VfsFileValue>, String> {
        Ok(HashMap::new())
    }
}

impl Default for EbpfLatencyCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn load_linux() -> Result<aya::Bpf, String> {
    use aya::programs::RawTracePoint;

    enforce_linux_trace_abi()?;

    // The block program itself is architecture-independent; parallel variants
    // keep the checked-in build products symmetric with the VFS probe.
    #[cfg(target_arch = "x86_64")]
    let bytes = aya::include_bytes_aligned!("ebpf/disk_latency-x86.bpf.o");
    #[cfg(target_arch = "aarch64")]
    let bytes = aya::include_bytes_aligned!("ebpf/disk_latency-arm64.bpf.o");
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let bytes: &[u8] = {
        return Err("eBPF probes support only x86_64 and arm64".into());
    };
    let mut bpf = aya::Bpf::load(bytes).map_err(|error| format!("cannot load eBPF: {error}"))?;

    for (program_name, tracepoint_name) in [
        ("diskwatch_block_issue", "block_rq_issue"),
        ("diskwatch_block_complete", "block_rq_complete"),
    ] {
        let program: &mut RawTracePoint = bpf
            .program_mut(program_name)
            .ok_or_else(|| format!("eBPF program {program_name} is missing"))?
            .try_into()
            .map_err(|error| format!("invalid eBPF program {program_name}: {error}"))?;
        program
            .load()
            .map_err(|error| format!("cannot load {program_name}: {error}"))?;
        program
            .attach(tracepoint_name)
            .map_err(|error| format!("cannot attach {program_name}: {error}"))?;
    }
    Ok(bpf)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn load_vfs_linux() -> Result<aya::Bpf, String> {
    use aya::programs::KProbe;

    #[cfg(target_arch = "x86_64")]
    let bytes = aya::include_bytes_aligned!("ebpf/vfs_activity-x86.bpf.o");
    #[cfg(target_arch = "aarch64")]
    let bytes = aya::include_bytes_aligned!("ebpf/vfs_activity-arm64.bpf.o");
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let bytes: &[u8] = {
        return Err("eBPF VFS attribution supports only x86_64 and arm64".into());
    };
    let mut bpf =
        aya::Bpf::load(bytes).map_err(|error| format!("cannot load VFS eBPF object: {error}"))?;
    for (program_name, function_name) in [
        ("diskwatch_vfs_read", "vfs_read"),
        ("diskwatch_vfs_write", "vfs_write"),
    ] {
        let program: &mut KProbe = bpf
            .program_mut(program_name)
            .ok_or_else(|| format!("eBPF program {program_name} is missing"))?
            .try_into()
            .map_err(|error| format!("invalid eBPF program {program_name}: {error}"))?;
        program
            .load()
            .map_err(|error| format!("cannot load {program_name}: {error}"))?;
        program
            .attach(function_name, 0)
            .map_err(|error| format!("cannot attach {program_name}: {error}"))?;
    }
    Ok(bpf)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn enforce_linux_trace_abi() -> Result<(), String> {
    const MINIMUM: (u32, u32) = (5, 11);
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|error| format!("cannot read kernel release: {error}"))?;
    let version = parse_linux_version(&release)
        .ok_or_else(|| format!("cannot parse kernel release {release:?}"))?;
    if version < MINIMUM {
        return Err(format!(
            "eBPF block latency requires Linux 5.11+ (running {}.{})",
            version.0, version.1
        ));
    }
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").is_file() {
        return Err("eBPF block latency requires kernel BTF at /sys/kernel/btf/vmlinux".into());
    }
    Ok(())
}

fn parse_linux_version(release: &str) -> Option<(u32, u32)> {
    let mut components = release.trim().split(['.', '-']);
    Some((
        components.next()?.parse().ok()?,
        components.next()?.parse().ok()?,
    ))
}

fn histogram_delta(
    previous: &HashMap<HistogramKey, u64>,
    current: &HashMap<HistogramKey, u64>,
) -> HashMap<HistogramKey, u64> {
    current
        .iter()
        .filter_map(|(key, count)| {
            let old = previous.get(key).copied().unwrap_or(0);
            // A smaller counter means the kernel map was replaced or reset;
            // treat its current value as new rather than hiding samples until
            // it catches up to the old process-local baseline.
            let delta = if count >= &old { count - old } else { *count };
            (delta != 0).then_some((*key, delta))
        })
        .collect()
}

fn counter_delta(previous: u64, current: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

fn bpf_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn vfs_deltas(
    previous: &HashMap<VfsFileKey, VfsFileValue>,
    current: &HashMap<VfsFileKey, VfsFileValue>,
) -> Vec<VfsActivityDelta> {
    let mut deltas = Vec::new();
    for (key, value) in current {
        let old = previous.get(key);
        let read_bytes = counter_delta(old.map_or(0, |v| v.read_bytes), value.read_bytes);
        let write_bytes = counter_delta(old.map_or(0, |v| v.write_bytes), value.write_bytes);
        let read_ops = counter_delta(old.map_or(0, |v| v.read_ops), value.read_ops);
        let write_ops = counter_delta(old.map_or(0, |v| v.write_ops), value.write_ops);
        if read_bytes == 0 && write_bytes == 0 && read_ops == 0 && write_ops == 0 {
            continue;
        }
        deltas.push(VfsActivityDelta {
            device: BlockDeviceId {
                major: key.major,
                minor: key.minor,
            },
            inode: key.inode,
            pid: value.pid,
            tgid: key.tgid,
            comm: bpf_string(&value.comm),
            basename: bpf_string(&value.basename),
            read_bytes,
            write_bytes,
            read_ops,
            write_ops,
        });
    }
    deltas.sort_by(|a, b| {
        b.read_bytes
            .saturating_add(b.write_bytes)
            .cmp(&a.read_bytes.saturating_add(a.write_bytes))
    });
    deltas
}

fn bucket_bounds(index: usize) -> (u64, Option<u64>) {
    if index == 0 {
        (0, Some(2))
    } else if index + 1 == LATENCY_BUCKETS {
        (1_u64 << index, None)
    } else {
        (1_u64 << index, Some(1_u64 << (index + 1)))
    }
}

fn snapshots_from_counts(counts: HashMap<HistogramKey, u64>) -> Vec<DeviceLatencyHistogram> {
    let mut grouped: HashMap<(BlockDeviceId, IoDirection), [u64; LATENCY_BUCKETS]> = HashMap::new();
    for (key, count) in counts {
        let direction = match key.direction {
            0 => IoDirection::Read,
            1 => IoDirection::Write,
            _ => continue,
        };
        if key.bucket as usize >= LATENCY_BUCKETS {
            continue;
        }
        grouped
            .entry((
                BlockDeviceId {
                    major: key.major,
                    minor: key.minor,
                },
                direction,
            ))
            .or_insert([0; LATENCY_BUCKETS])[key.bucket as usize] += count;
    }

    let mut snapshots: Vec<_> = grouped
        .into_iter()
        .map(|((device, direction), counts)| DeviceLatencyHistogram {
            device,
            direction,
            source: LatencySource::EbpfPerRequest,
            buckets: counts
                .iter()
                .enumerate()
                .map(|(index, count)| {
                    let (lower_us, upper_us) = bucket_bounds(index);
                    LatencyBucket {
                        lower_us,
                        upper_us,
                        count: *count,
                    }
                })
                .collect(),
        })
        .collect();
    snapshots.sort_by_key(|snapshot| {
        (
            snapshot.device.major,
            snapshot.device.minor,
            match snapshot.direction {
                IoDirection::Read => 0,
                IoDirection::Write => 1,
            },
        )
    });
    snapshots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(bucket: u32) -> HistogramKey {
        HistogramKey {
            major: 8,
            minor: 0,
            direction: 0,
            bucket,
        }
    }

    fn vfs_key() -> VfsFileKey {
        VfsFileKey {
            major: 8,
            minor: 1,
            inode: 42,
            tgid: 1000,
            _padding: 0,
        }
    }

    fn vfs_value(read_bytes: u64, write_bytes: u64) -> VfsFileValue {
        let mut comm = [0; 16];
        comm[..4].copy_from_slice(b"test");
        let mut basename = [0; 64];
        basename[..8].copy_from_slice(b"data.log");
        VfsFileValue {
            read_bytes,
            write_bytes,
            read_ops: read_bytes / 10,
            write_ops: write_bytes / 10,
            pid: 1001,
            _padding: 0,
            comm,
            basename,
        }
    }

    #[test]
    fn bucket_bounds_are_logarithmic_and_overflow_is_open_ended() {
        assert_eq!(bucket_bounds(0), (0, Some(2)));
        assert_eq!(bucket_bounds(1), (2, Some(4)));
        assert_eq!(bucket_bounds(10), (1024, Some(2048)));
        assert_eq!(bucket_bounds(31), (1_u64 << 31, None));
    }

    #[test]
    fn delta_uses_new_counts_and_tolerates_map_resets() {
        let previous = HashMap::from([(key(4), 12), (key(5), 9)]);
        let current = HashMap::from([(key(4), 17), (key(5), 2), (key(6), 3)]);
        let delta = histogram_delta(&previous, &current);
        assert_eq!(delta.get(&key(4)), Some(&5));
        assert_eq!(delta.get(&key(5)), Some(&2));
        assert_eq!(delta.get(&key(6)), Some(&3));
    }

    #[test]
    fn vfs_key_and_strings_decode_into_delta_schema() {
        let current = HashMap::from([(vfs_key(), vfs_value(120, 30))]);
        let deltas = vfs_deltas(&HashMap::new(), &current);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].device, BlockDeviceId { major: 8, minor: 1 });
        assert_eq!(deltas[0].inode, 42);
        assert_eq!(deltas[0].pid, 1001);
        assert_eq!(deltas[0].tgid, 1000);
        assert_eq!(deltas[0].comm, "test");
        assert_eq!(deltas[0].basename, "data.log");
    }

    #[test]
    fn vfs_deltas_handle_growth_reset_and_idle_entries() {
        let previous = HashMap::from([(vfs_key(), vfs_value(100, 50))]);
        let current = HashMap::from([(vfs_key(), vfs_value(140, 2))]);
        let deltas = vfs_deltas(&previous, &current);
        assert_eq!(deltas[0].read_bytes, 40);
        assert_eq!(deltas[0].write_bytes, 2);

        assert!(vfs_deltas(&current, &current).is_empty());
    }

    #[test]
    fn vfs_failure_status_is_independent_data() {
        let latency_status = EbpfStatus::Active;
        let vfs_status = independent_vfs_status(Err("vfs hook absent".into()));
        assert_eq!(latency_status, EbpfStatus::Active);
        assert_eq!(
            vfs_status,
            EbpfStatus::Unavailable("vfs hook absent".into())
        );
    }

    #[test]
    fn snapshots_group_by_device_and_direction() {
        let mut write_key = key(7);
        write_key.direction = 1;
        let snapshots = snapshots_from_counts(HashMap::from([(key(3), 4), (write_key, 2)]));
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].direction, IoDirection::Read);
        assert_eq!(snapshots[0].buckets[3].count, 4);
        assert_eq!(snapshots[1].direction, IoDirection::Write);
        assert_eq!(snapshots[1].buckets[7].count, 2);
    }

    #[test]
    fn parses_supported_kernel_release_formats() {
        assert_eq!(
            parse_linux_version("6.6.87.2-microsoft-standard-WSL2\n"),
            Some((6, 6))
        );
        assert_eq!(parse_linux_version("5.11.0-49-generic"), Some((5, 11)));
        assert_eq!(parse_linux_version("not-a-version"), None);
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn embedded_object_load_failure_is_nonfatal() {
        let collector = EbpfLatencyCollector::new();
        assert!(matches!(
            collector.status(),
            EbpfStatus::Active | EbpfStatus::Unavailable(_)
        ));
    }

    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    #[test]
    fn reports_feature_disabled() {
        let collector = EbpfLatencyCollector::new();
        assert_eq!(collector.status(), &EbpfStatus::DisabledAtBuild);
        assert_eq!(collector.source(), LatencySource::AggregateAwait);
    }
}
