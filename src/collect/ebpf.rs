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

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct VfsFilePath {
    path: [u8; 256],
}

#[derive(Clone, Copy, Debug)]
struct VfsFileSample {
    counts: VfsFileValue,
    path: VfsFilePath,
    /// Retry one subsequent sample when counters became visible immediately
    /// before the permission hook captured its path.
    path_pending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VfsActivityDelta {
    pub device: BlockDeviceId,
    pub inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub basename: String,
    pub path: String,
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

#[cfg(all(target_os = "linux", feature = "ebpf"))]
unsafe impl aya::Pod for VfsFilePath {}

pub struct EbpfLatencyCollector {
    status: EbpfStatus,
    vfs_status: EbpfStatus,
    vfs_path_status: EbpfStatus,
    previous: HashMap<HistogramKey, u64>,
    vfs_previous: HashMap<VfsFileKey, VfsFileSample>,
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

    #[cfg(test)]
    pub(crate) fn unavailable_for_test() -> Self {
        Self {
            status: EbpfStatus::Unavailable("test fixture".into()),
            vfs_status: EbpfStatus::Unavailable("test fixture".into()),
            vfs_path_status: EbpfStatus::Unavailable("test fixture".into()),
            previous: HashMap::new(),
            vfs_previous: HashMap::new(),
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            latency_bpf: None,
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            vfs_bpf: None,
        }
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

    /// Event-time full-path capture is optional and independent of VFS
    /// requested-byte accounting. Diagnostics expose this separately so a
    /// host can distinguish kernel paths from the userspace fallback.
    pub fn vfs_path_status(&self) -> &EbpfStatus {
        &self.vfs_path_status
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
                let (vfs_bpf, vfs_status, vfs_path_status) = match load_vfs_linux() {
                    Ok((bpf, path_status)) => (Some(bpf), EbpfStatus::Active, path_status),
                    Err(error) => (
                        None,
                        independent_vfs_status(Err(error.clone())),
                        EbpfStatus::Unavailable(format!(
                            "VFS activity initialization failed before path attach: {error}"
                        )),
                    ),
                };
                Self {
                    status: EbpfStatus::Active,
                    vfs_status,
                    vfs_path_status,
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
                vfs_path_status: EbpfStatus::Unavailable(format!(
                    "block probe initialization failed before VFS path attach: {error}"
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
            vfs_path_status: EbpfStatus::DisabledAtBuild,
            previous: HashMap::new(),
            vfs_previous: HashMap::new(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn load() -> Self {
        Self {
            status: EbpfStatus::UnsupportedPlatform,
            vfs_status: EbpfStatus::UnsupportedPlatform,
            vfs_path_status: EbpfStatus::UnsupportedPlatform,
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
    fn read_vfs_counts(&mut self) -> Result<HashMap<VfsFileKey, VfsFileSample>, String> {
        use aya::maps::HashMap as AyaHashMap;

        let path_capture_active = self.vfs_path_status.is_active();
        let bpf = self
            .vfs_bpf
            .as_mut()
            .ok_or_else(|| "eBPF collector is not loaded".to_string())?;
        let counts = bpf
            .map_mut("VFS_FILES")
            .ok_or_else(|| "eBPF VFS activity map is missing".to_string())?;
        let counts = AyaHashMap::<_, VfsFileKey, VfsFileValue>::try_from(counts)
            .map_err(|error| format!("cannot access eBPF VFS activity map: {error}"))?;
        let counts: HashMap<_, _> = counts
            .iter()
            .map(|entry| entry.map_err(|error| format!("cannot read eBPF VFS activity: {error}")))
            .collect::<Result<_, _>>()?;

        let mut samples: HashMap<_, _> = counts
            .into_iter()
            .map(|(key, counts)| {
                let (sample, should_lookup, counts_changed) =
                    prepare_vfs_sample(self.vfs_previous.get(&key), counts, path_capture_active);
                (key, (sample, should_lookup, counts_changed))
            })
            .collect();

        if path_capture_active {
            if let Err(error) = read_active_vfs_paths(bpf, &mut samples) {
                self.vfs_path_status = EbpfStatus::Unavailable(error);
                for (sample, _, _) in samples.values_mut() {
                    sample.path_pending = false;
                }
            }
        }

        Ok(samples
            .into_iter()
            .map(|(key, (sample, _, _))| (key, sample))
            .collect())
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn read_counts(&mut self) -> Result<HashMap<HistogramKey, u64>, String> {
        Ok(HashMap::new())
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn read_vfs_counts(&mut self) -> Result<HashMap<VfsFileKey, VfsFileSample>, String> {
        Ok(HashMap::new())
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn read_active_vfs_paths(
    bpf: &mut aya::Bpf,
    samples: &mut HashMap<VfsFileKey, (VfsFileSample, bool, bool)>,
) -> Result<(), String> {
    use aya::maps::{HashMap as AyaHashMap, MapError};

    let paths = bpf
        .map_mut("VFS_PATHS")
        .ok_or_else(|| "eBPF VFS path map is missing".to_string())?;
    let paths = AyaHashMap::<_, VfsFileKey, VfsFilePath>::try_from(paths)
        .map_err(|error| format!("cannot access eBPF VFS path map: {error}"))?;
    for (key, (sample, should_lookup, counts_changed)) in samples {
        if !*should_lookup {
            continue;
        }
        let captured = match paths.get(key, 0) {
            Ok(path) => Some(path),
            Err(MapError::KeyNotFound) => None,
            Err(error) => return Err(format!("cannot read eBPF VFS path: {error}")),
        };
        complete_vfs_path_lookup(sample, captured, *counts_changed);
    }
    Ok(())
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
fn load_vfs_linux() -> Result<(aya::Bpf, EbpfStatus), String> {
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
    // Path capture is a separate, newer capability. Count probes remain
    // attached when BTF lookup, verifier policy, or the helper allowlist
    // rejects this program.
    let path_status = attach_vfs_path_linux(&mut bpf);
    Ok((bpf, independent_vfs_status(path_status)))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn attach_vfs_path_linux(bpf: &mut aya::Bpf) -> Result<(), String> {
    use aya::programs::FEntry;
    use aya::Btf;

    let btf = Btf::from_sys_fs().map_err(|error| format!("cannot read kernel BTF: {error}"))?;
    let program_name = "diskwatch_vfs_path";
    let program: &mut FEntry = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("eBPF program {program_name} is missing"))?
        .try_into()
        .map_err(|error| format!("invalid eBPF program {program_name}: {error}"))?;
    program
        .load("security_file_permission", &btf)
        .map_err(|error| format!("cannot load {program_name}: {error}"))?;
    program
        .attach()
        .map_err(|error| format!("cannot attach {program_name}: {error}"))?;
    Ok(())
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

fn vfs_counters_changed(old: &VfsFileValue, current: &VfsFileValue) -> bool {
    old.read_bytes != current.read_bytes
        || old.write_bytes != current.write_bytes
        || old.read_ops != current.read_ops
        || old.write_ops != current.write_ops
}

fn vfs_counters_reset(old: &VfsFileValue, current: &VfsFileValue) -> bool {
    current.read_bytes < old.read_bytes
        || current.write_bytes < old.write_bytes
        || current.read_ops < old.read_ops
        || current.write_ops < old.write_ops
}

fn prepare_vfs_sample(
    old: Option<&VfsFileSample>,
    counts: VfsFileValue,
    path_capture_active: bool,
) -> (VfsFileSample, bool, bool) {
    let counts_changed = old.map_or(true, |old| vfs_counters_changed(&old.counts, &counts));
    let counts_reset = old.is_some_and(|old| vfs_counters_reset(&old.counts, &counts));
    let path = if counts_reset {
        VfsFilePath { path: [0; 256] }
    } else {
        old.map_or(VfsFilePath { path: [0; 256] }, |old| old.path)
    };
    let path_pending = old.is_some_and(|old| old.path_pending);
    let should_lookup = path_capture_active
        && (counts_changed || path_pending)
        && (path.path[0] == 0 || path_pending);
    (
        VfsFileSample {
            counts,
            path,
            path_pending: false,
        },
        should_lookup,
        counts_changed,
    )
}

fn complete_vfs_path_lookup(
    sample: &mut VfsFileSample,
    captured: Option<VfsFilePath>,
    counts_changed: bool,
) {
    if let Some(captured) = captured.filter(|path| path.path[0] != 0) {
        sample.path = captured;
        sample.path_pending = false;
    } else {
        // Changed counters earn one follow-up lookup. If this was already the
        // follow-up on an idle entry, stop polling it until activity resumes.
        sample.path_pending = counts_changed && sample.path.path[0] == 0;
    }
}

fn vfs_deltas(
    previous: &HashMap<VfsFileKey, VfsFileSample>,
    current: &HashMap<VfsFileKey, VfsFileSample>,
) -> Vec<VfsActivityDelta> {
    let mut deltas = Vec::new();
    for (key, sample) in current {
        let value = &sample.counts;
        let old = previous.get(key);
        let old_counts = old.map(|sample| &sample.counts);
        let read_bytes = counter_delta(old_counts.map_or(0, |v| v.read_bytes), value.read_bytes);
        let write_bytes = counter_delta(old_counts.map_or(0, |v| v.write_bytes), value.write_bytes);
        let read_ops = counter_delta(old_counts.map_or(0, |v| v.read_ops), value.read_ops);
        let write_ops = counter_delta(old_counts.map_or(0, |v| v.write_ops), value.write_ops);
        let path_changed =
            old.is_some_and(|old| old.path.path != sample.path.path && sample.path.path[0] != 0);
        if read_bytes == 0 && write_bytes == 0 && read_ops == 0 && write_ops == 0 && !path_changed {
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
            path: bpf_string(&sample.path.path),
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

    fn vfs_sample(read_bytes: u64, write_bytes: u64, path: &str) -> VfsFileSample {
        let mut captured = [0; 256];
        captured[..path.len()].copy_from_slice(path.as_bytes());
        VfsFileSample {
            counts: vfs_value(read_bytes, write_bytes),
            path: VfsFilePath { path: captured },
            path_pending: false,
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
        let current = HashMap::from([(vfs_key(), vfs_sample(120, 30, "/srv/data.log"))]);
        let deltas = vfs_deltas(&HashMap::new(), &current);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].device, BlockDeviceId { major: 8, minor: 1 });
        assert_eq!(deltas[0].inode, 42);
        assert_eq!(deltas[0].pid, 1001);
        assert_eq!(deltas[0].tgid, 1000);
        assert_eq!(deltas[0].comm, "test");
        assert_eq!(deltas[0].basename, "data.log");
        assert_eq!(deltas[0].path, "/srv/data.log");
    }

    #[test]
    fn vfs_deltas_handle_growth_reset_and_idle_entries() {
        let previous = HashMap::from([(vfs_key(), vfs_sample(100, 50, ""))]);
        let current = HashMap::from([(vfs_key(), vfs_sample(140, 2, ""))]);
        let deltas = vfs_deltas(&previous, &current);
        assert_eq!(deltas[0].read_bytes, 40);
        assert_eq!(deltas[0].write_bytes, 2);

        assert!(vfs_deltas(&current, &current).is_empty());
    }

    #[test]
    fn vfs_path_arriving_after_count_sample_emits_metadata_delta() {
        let previous = HashMap::from([(vfs_key(), vfs_sample(140, 2, ""))]);
        let current = HashMap::from([(vfs_key(), vfs_sample(140, 2, "/srv/late-path.log"))]);

        let deltas = vfs_deltas(&previous, &current);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].path, "/srv/late-path.log");
        assert_eq!(deltas[0].read_bytes, 0);
        assert_eq!(deltas[0].write_bytes, 0);
    }

    #[test]
    fn vfs_path_lookup_gets_one_idle_retry_then_stops() {
        let counts = vfs_value(100, 0);
        let (mut first, should_lookup, changed) = prepare_vfs_sample(None, counts, true);
        assert!(should_lookup);
        complete_vfs_path_lookup(&mut first, None, changed);
        assert!(first.path_pending);

        let (mut retry, should_lookup, changed) = prepare_vfs_sample(Some(&first), counts, true);
        assert!(should_lookup);
        assert!(!changed);
        complete_vfs_path_lookup(&mut retry, None, changed);
        assert!(!retry.path_pending);

        let (_, should_lookup, _) = prepare_vfs_sample(Some(&retry), counts, true);
        assert!(!should_lookup);
    }

    #[test]
    fn vfs_path_lookup_reuses_cache_and_skips_inactive_capture() {
        let resolved = vfs_sample(100, 0, "/srv/data.log");
        let (_, should_lookup, _) = prepare_vfs_sample(Some(&resolved), resolved.counts, true);
        assert!(!should_lookup);

        let changed = vfs_value(200, 0);
        let (sample, should_lookup, counts_changed) =
            prepare_vfs_sample(Some(&resolved), changed, true);
        assert!(counts_changed);
        assert!(!should_lookup);
        assert_eq!(bpf_string(&sample.path.path), "/srv/data.log");

        let (_, should_lookup, _) = prepare_vfs_sample(None, resolved.counts, false);
        assert!(!should_lookup);

        let reset = vfs_value(1, 0);
        let (sample, should_lookup, _) = prepare_vfs_sample(Some(&resolved), reset, true);
        assert!(should_lookup);
        assert_eq!(sample.path.path[0], 0);
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
