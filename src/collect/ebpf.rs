//! Optional per-request block latency collection.
//!
//! The UI can construct this collector unconditionally. Builds without the
//! `ebpf` feature, non-Linux systems, and Linux systems which reject BPF loads
//! all report an ordinary status and continue using `/proc/diskstats`.

use std::collections::HashMap;

pub const LATENCY_BUCKETS: usize = 32;
const FUSE_ORIGIN_UNKNOWN: u32 = u32::MAX;
const FUSE_ORIGIN_PROTOCOL: u32 = 1;
const FUSE_ORIGIN_WRITEBACK: u32 = 2;
const FUSE_ORIGIN_PID_ZERO: u32 = 3;
/// One ringful at the current event size. Bounding each synchronous drain
/// guarantees that sustained producers cannot monopolize the UI thread.
const MAX_VFS_EVENTS_PER_DRAIN: usize = 8192;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
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
    /// Counts bytes completed by VFS read/write calls. This is filesystem
    /// traffic rather than physical-device traffic and can include cache hits.
    EbpfCompletedBytes,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VfsAttributionKind {
    Direct,
    FuseProtocol,
    FuseWriteback,
    FusePidZero,
    FuseUnresolved,
    Unknown(u32),
}

impl Default for VfsAttributionKind {
    fn default() -> Self {
        Self::Direct
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VfsPathSource {
    Ebpf,
    ProcFd,
    BasenameFallback,
    Unresolved,
}

impl Default for VfsPathSource {
    fn default() -> Self {
        Self::Unresolved
    }
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
struct VfsEvent {
    key: VfsFileKey,
    bytes: u64,
    pid: u32,
    direction: u32,
    origin_pid: u32,
    origin_tgid: u32,
    comm: [u8; 16],
    origin_comm: [u8; 16],
    basename: [u8; 64],
    cgroup_id: u64,
    parent_tgid: u32,
    origin_parent_tgid: u32,
    parent_comm: [u8; 16],
    origin_parent_comm: [u8; 16],
    origin_kind: u32,
    _origin_padding: u32,
    origin_cgroup_id: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct VfsFilePath {
    path: [u8; 256],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VfsActivityDelta {
    pub device: BlockDeviceId,
    pub inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    /// Task that actually executed the VFS operation (for example,
    /// fuse-overlayfs). The fields above are iodyne's attributed requester.
    pub executor_pid: u32,
    pub executor_tgid: u32,
    pub executor_comm: String,
    pub executor_cgroup_id: u64,
    /// Requester identity captured by delegated-filesystem hooks before
    /// userspace resolution. Zero values mean no delegated requester.
    pub origin_pid: u32,
    pub origin_tgid: u32,
    pub origin_comm: String,
    pub origin_cgroup_id: u64,
    pub attribution_kind: VfsAttributionKind,
    /// Immediate parent captured while the process was still alive.
    pub parent_tgid: u32,
    pub parent_comm: String,
    /// The operation was delegated through fuse-overlayfs. This survives a
    /// short-lived requester exiting before userspace can read its cgroup.
    pub container_owned: bool,
    pub basename: String,
    pub path: String,
    pub path_source: VfsPathSource,
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
unsafe impl aya::Pod for VfsEvent {}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
unsafe impl aya::Pod for VfsFilePath {}

pub struct EbpfLatencyCollector {
    status: EbpfStatus,
    vfs_status: EbpfStatus,
    vfs_path_status: EbpfStatus,
    vfs_fuse_status: EbpfStatus,
    vfs_fuse_writeback_status: EbpfStatus,
    vfs_overlay_status: EbpfStatus,
    cgroup_container_cache: HashMap<u64, bool>,
    previous: HashMap<HistogramKey, u64>,
    previous_vfs_drops: u64,
    pending_vfs_drops: u64,
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
            vfs_fuse_status: EbpfStatus::Unavailable("test fixture".into()),
            vfs_fuse_writeback_status: EbpfStatus::Unavailable("test fixture".into()),
            vfs_overlay_status: EbpfStatus::Unavailable("test fixture".into()),
            cgroup_container_cache: HashMap::new(),
            previous: HashMap::new(),
            previous_vfs_drops: 0,
            pending_vfs_drops: 0,
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
    /// completed-byte accounting. Diagnostics expose this separately so a
    /// host can distinguish kernel paths from the userspace fallback.
    pub fn vfs_path_status(&self) -> &EbpfStatus {
        &self.vfs_path_status
    }

    pub fn vfs_fuse_status(&self) -> &EbpfStatus {
        &self.vfs_fuse_status
    }

    pub fn vfs_fuse_writeback_status(&self) -> &EbpfStatus {
        &self.vfs_fuse_writeback_status
    }

    pub fn vfs_overlay_status(&self) -> &EbpfStatus {
        &self.vfs_overlay_status
    }

    pub fn vfs_source(&self) -> VfsActivitySource {
        if self.vfs_status.is_active() {
            VfsActivitySource::EbpfCompletedBytes
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

    /// Returns bounded per-file VFS completed-byte deltas since the previous
    /// sample. A VFS map failure disables only this capability.
    pub(crate) fn vfs_snapshot(&mut self) -> Vec<VfsActivityDelta> {
        if !self.vfs_status.is_active() {
            return Vec::new();
        }
        let current = match self.read_vfs_counts() {
            Ok(counts) => counts,
            Err(message) => {
                self.vfs_status = EbpfStatus::Unavailable(message);
                return Vec::new();
            }
        };
        if let Ok(total) = self.read_vfs_drop_count() {
            self.pending_vfs_drops = self
                .pending_vfs_drops
                .saturating_add(total.saturating_sub(self.previous_vfs_drops));
            self.previous_vfs_drops = total;
        }
        current
    }

    pub(crate) fn take_vfs_drops(&mut self) -> u64 {
        std::mem::take(&mut self.pending_vfs_drops)
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn load() -> Self {
        match load_linux() {
            Ok(latency_bpf) => {
                let (
                    vfs_bpf,
                    vfs_status,
                    vfs_path_status,
                    vfs_fuse_status,
                    vfs_fuse_writeback_status,
                    vfs_overlay_status,
                ) =
                    match load_vfs_linux() {
                        Ok((
                            bpf,
                            path_status,
                            fuse_status,
                            fuse_writeback_status,
                            overlay_status,
                        )) => (
                            Some(bpf),
                            EbpfStatus::Active,
                            path_status,
                            fuse_status,
                            fuse_writeback_status,
                            overlay_status,
                        ),
                        Err(error) => (
                            None,
                            independent_vfs_status(Err(error.clone())),
                            EbpfStatus::Unavailable(format!(
                                "VFS activity initialization failed before path attach: {error}"
                            )),
                            EbpfStatus::Unavailable(format!(
                                "VFS activity initialization failed before FUSE attach: {error}"
                            )),
                            EbpfStatus::Unavailable(format!(
                                "VFS activity initialization failed before FUSE writeback attach: {error}"
                            )),
                            EbpfStatus::Unavailable(format!(
                                "VFS activity initialization failed before OverlayFS attach: {error}"
                            )),
                        ),
                    };
                Self {
                    status: EbpfStatus::Active,
                    vfs_status,
                    vfs_path_status,
                    vfs_fuse_status,
                    vfs_fuse_writeback_status,
                    vfs_overlay_status,
                    cgroup_container_cache: HashMap::new(),
                    previous: HashMap::new(),
                    previous_vfs_drops: 0,
                    pending_vfs_drops: 0,
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
                vfs_fuse_status: EbpfStatus::Unavailable(format!(
                    "block probe initialization failed before FUSE attach: {error}"
                )),
                vfs_fuse_writeback_status: EbpfStatus::Unavailable(format!(
                    "block probe initialization failed before FUSE writeback attach: {error}"
                )),
                vfs_overlay_status: EbpfStatus::Unavailable(format!(
                    "block probe initialization failed before OverlayFS attach: {error}"
                )),
                cgroup_container_cache: HashMap::new(),
                previous: HashMap::new(),
                previous_vfs_drops: 0,
                pending_vfs_drops: 0,
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
            vfs_fuse_status: EbpfStatus::DisabledAtBuild,
            vfs_fuse_writeback_status: EbpfStatus::DisabledAtBuild,
            vfs_overlay_status: EbpfStatus::DisabledAtBuild,
            cgroup_container_cache: HashMap::new(),
            previous: HashMap::new(),
            previous_vfs_drops: 0,
            pending_vfs_drops: 0,
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn load() -> Self {
        Self {
            status: EbpfStatus::UnsupportedPlatform,
            vfs_status: EbpfStatus::UnsupportedPlatform,
            vfs_path_status: EbpfStatus::UnsupportedPlatform,
            vfs_fuse_status: EbpfStatus::UnsupportedPlatform,
            vfs_fuse_writeback_status: EbpfStatus::UnsupportedPlatform,
            vfs_overlay_status: EbpfStatus::UnsupportedPlatform,
            cgroup_container_cache: HashMap::new(),
            previous: HashMap::new(),
            previous_vfs_drops: 0,
            pending_vfs_drops: 0,
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
    fn read_vfs_counts(&mut self) -> Result<Vec<VfsActivityDelta>, String> {
        use aya::maps::{HashMap as AyaHashMap, MapError, RingBuf};

        let cgroup_container_cache = &mut self.cgroup_container_cache;
        let bpf = self
            .vfs_bpf
            .as_mut()
            .ok_or_else(|| "eBPF collector is not loaded".to_string())?;
        type ObservationKey = (VfsFileKey, u32, u32, u32);
        let mut deltas = HashMap::<ObservationKey, VfsActivityDelta>::new();
        let mut path_keys = HashMap::<ObservationKey, VfsFileKey>::new();
        let mut delegated_processes = HashMap::<u32, Option<(u32, String)>>::new();
        {
            let events = bpf
                .map_mut("VFS_EVENTS")
                .ok_or_else(|| "eBPF VFS event ring is missing".to_string())?;
            let mut events = RingBuf::try_from(events)
                .map_err(|error| format!("cannot access eBPF VFS event ring: {error}"))?;
            for _ in 0..MAX_VFS_EVENTS_PER_DRAIN {
                let Some(item) = events.next() else {
                    break;
                };
                let Some(event) = decode_vfs_event(&item) else {
                    continue;
                };
                let mut effective_key = event.key;
                let effective_cgroup_id = if event.origin_cgroup_id != 0 {
                    event.origin_cgroup_id
                } else {
                    event.cgroup_id
                };
                let cgroup_is_container = effective_cgroup_id != 0
                    && *cgroup_container_cache
                        .entry(effective_cgroup_id)
                        .or_insert_with(|| cgroup_id_is_container(effective_cgroup_id));
                let delegated_by_fuse_overlay = matches!(
                    event.origin_kind,
                    FUSE_ORIGIN_PROTOCOL | FUSE_ORIGIN_WRITEBACK | FUSE_ORIGIN_PID_ZERO
                ) && bpf_string(&event.comm) == "fuse-overlayfs";
                let (pid, comm, parent_tgid, parent_comm) =
                    if event.origin_pid == FUSE_ORIGIN_UNKNOWN {
                        (event.pid, "fuse-overlayfs".to_string(), 0, String::new())
                    } else if event.origin_pid != 0 {
                        // A protocol header PID is relative to the requester's
                        // PID namespace. Only consult host /proc after a BPF
                        // hook has supplied the corresponding host identity.
                        if event.origin_tgid != 0 {
                            let identity = delegated_processes
                                .entry(event.origin_pid)
                                .or_insert_with(|| delegated_process_identity(event.origin_pid));
                            if let Some((tgid, comm)) = identity {
                                effective_key.tgid = *tgid;
                                (
                                    event.origin_pid,
                                    comm.clone(),
                                    event.origin_parent_tgid,
                                    bpf_string(&event.origin_parent_comm),
                                )
                            } else {
                                effective_key.tgid = event.origin_tgid;
                                let cached_comm = bpf_string(&event.origin_comm);
                                let comm = if cached_comm.is_empty() {
                                    "process (exited)".to_string()
                                } else {
                                    cached_comm
                                };
                                (
                                    event.origin_pid,
                                    comm,
                                    event.origin_parent_tgid,
                                    bpf_string(&event.origin_parent_comm),
                                )
                            }
                        } else {
                            effective_key.tgid = event.origin_pid;
                            (
                                event.origin_pid,
                                format!("pid {} (unresolved)", event.origin_pid),
                                0,
                                String::new(),
                            )
                        }
                    } else {
                        (
                            event.pid,
                            bpf_string(&event.comm),
                            event.parent_tgid,
                            bpf_string(&event.parent_comm),
                        )
                    };
                if effective_key.tgid == std::process::id() {
                    continue;
                }
                let observation_key = (
                    effective_key,
                    event.key.tgid,
                    event.origin_tgid,
                    event.origin_kind,
                );
                path_keys.entry(observation_key).or_insert(event.key);
                let delta = deltas
                    .entry(observation_key)
                    .or_insert_with(|| VfsActivityDelta {
                        device: BlockDeviceId {
                            major: effective_key.major,
                            minor: effective_key.minor,
                        },
                        inode: effective_key.inode,
                        pid,
                        tgid: effective_key.tgid,
                        comm,
                        executor_pid: event.pid,
                        executor_tgid: event.key.tgid,
                        executor_comm: bpf_string(&event.comm),
                        executor_cgroup_id: event.cgroup_id,
                        origin_pid: event.origin_pid,
                        origin_tgid: event.origin_tgid,
                        origin_comm: bpf_string(&event.origin_comm),
                        origin_cgroup_id: event.origin_cgroup_id,
                        attribution_kind: attribution_kind(event.origin_kind),
                        parent_tgid,
                        parent_comm: parent_comm.clone(),
                        container_owned: delegated_by_fuse_overlay || cgroup_is_container,
                        basename: bpf_string(&event.basename),
                        path: String::new(),
                        path_source: VfsPathSource::Unresolved,
                        read_bytes: 0,
                        write_bytes: 0,
                        read_ops: 0,
                        write_ops: 0,
                    });
                delta.pid = pid;
                if parent_tgid != 0 {
                    delta.parent_tgid = parent_tgid;
                    delta.parent_comm = parent_comm;
                }
                delta.container_owned |= delegated_by_fuse_overlay || cgroup_is_container;
                if event.direction == 0 {
                    delta.read_bytes = delta.read_bytes.saturating_add(event.bytes);
                    delta.read_ops = delta.read_ops.saturating_add(1);
                } else if event.direction == 1 {
                    delta.write_bytes = delta.write_bytes.saturating_add(event.bytes);
                    delta.write_ops = delta.write_ops.saturating_add(1);
                }
            }
        }

        if self.vfs_path_status.is_active() && !deltas.is_empty() {
            let path_result = (|| -> Result<(), String> {
                let paths = bpf
                    .map_mut("VFS_PATHS")
                    .ok_or_else(|| "eBPF VFS path map is missing".to_string())?;
                let paths = AyaHashMap::<_, VfsFileKey, VfsFilePath>::try_from(paths)
                    .map_err(|error| format!("cannot access eBPF VFS path map: {error}"))?;
                for (key, delta) in &mut deltas {
                    let path_key = path_keys.get(key).unwrap_or(&key.0);
                    match paths.get(path_key, 0) {
                        Ok(path) => {
                            delta.path = bpf_string(&path.path);
                            if !delta.path.is_empty() {
                                delta.path_source = VfsPathSource::Ebpf;
                            }
                        }
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => {
                            return Err(format!("cannot read eBPF VFS path: {error}"));
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = path_result {
                self.vfs_path_status = EbpfStatus::Unavailable(error);
            }
        }

        Ok(deltas.into_values().collect())
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn read_vfs_drop_count(&mut self) -> Result<u64, String> {
        use aya::maps::Array;

        let bpf = self
            .vfs_bpf
            .as_mut()
            .ok_or_else(|| "eBPF collector is not loaded".to_string())?;
        let drops = bpf
            .map_mut("VFS_DROPS")
            .ok_or_else(|| "eBPF VFS drop counter is missing".to_string())?;
        let drops = Array::<_, u64>::try_from(drops)
            .map_err(|error| format!("cannot access eBPF VFS drop counter: {error}"))?;
        drops
            .get(&0, 0)
            .map_err(|error| format!("cannot read eBPF VFS drop counter: {error}"))
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn read_counts(&mut self) -> Result<HashMap<HistogramKey, u64>, String> {
        Ok(HashMap::new())
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn read_vfs_counts(&mut self) -> Result<Vec<VfsActivityDelta>, String> {
        Ok(Vec::new())
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn read_vfs_drop_count(&mut self) -> Result<u64, String> {
        Ok(0)
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
        ("iodyne_block_issue", "block_rq_issue"),
        ("iodyne_block_complete", "block_rq_complete"),
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
fn load_vfs_linux() -> Result<(aya::Bpf, EbpfStatus, EbpfStatus, EbpfStatus, EbpfStatus), String> {
    use aya::maps::Array;
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
    let self_tgid = bpf
        .map_mut("SELF_TGID")
        .ok_or_else(|| "eBPF self-TGID map is missing".to_string())?;
    let mut self_tgid = Array::<_, u32>::try_from(self_tgid)
        .map_err(|error| format!("cannot access eBPF self-TGID map: {error}"))?;
    self_tgid
        .set(0, std::process::id(), 0)
        .map_err(|error| format!("cannot configure eBPF self-TGID filter: {error}"))?;
    for (program_name, function_name) in [
        ("iodyne_vfs_read", "vfs_read"),
        ("iodyne_vfs_write", "vfs_write"),
        ("iodyne_fuse_read_complete", "vfs_read"),
        ("iodyne_vfs_write_complete", "vfs_write"),
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
    // This cleanup hook is opportunistic because kernels built without FUSE
    // do not expose fuse_dev_write. A worker's next /dev/fuse read also clears
    // stale attribution, so base VFS collection remains useful either way.
    let _ = attach_optional_kprobe(&mut bpf, "iodyne_fuse_reply", "fuse_dev_write");
    // Newer kernels expose the in-kernel request at this stable FUSE copy
    // boundary. Keep the userspace-buffer decoder above as a fallback when
    // this internal symbol is unavailable.
    let fuse_request_status =
        attach_optional_kprobe(&mut bpf, "iodyne_fuse_request", "fuse_copy_args");
    let fuse_status = match &fuse_request_status {
        Ok(()) => attach_optional_kprobe(
            &mut bpf,
            "iodyne_fuse_requester_identity",
            "request_wait_answer",
        ),
        Err(error) => Err(error.clone()),
    };
    let fuse_writeback_status = match &fuse_request_status {
        Ok(()) => attach_optional_kprobe(
            &mut bpf,
            "iodyne_fuse_logical_writer",
            "fuse_file_write_iter",
        ),
        Err(error) => Err(format!(
            "FUSE PID-0 writeback attribution requires requester correlation: {error}"
        )),
    };

    // OverlayFS is commonly a module, so these symbols may be absent even on
    // kernels that support it. Attach exits and physical backing hooks first;
    // an entry hook is enabled only when its cleanup and recorder are live.
    let overlay_status = (|| -> Result<(), String> {
        attach_optional_kprobe(&mut bpf, "iodyne_overlay_read_exit", "ovl_read_iter")?;
        attach_optional_kprobe(
            &mut bpf,
            "iodyne_overlay_backing_read_complete",
            "vfs_iter_read",
        )?;
        attach_optional_kprobe(&mut bpf, "iodyne_overlay_backing_read", "vfs_iter_read")?;
        attach_optional_kprobe(&mut bpf, "iodyne_overlay_read_enter", "ovl_read_iter")?;
        attach_optional_kprobe(&mut bpf, "iodyne_overlay_write_exit", "ovl_write_iter")?;
        attach_optional_kprobe(
            &mut bpf,
            "iodyne_overlay_backing_write_complete",
            "vfs_iter_write",
        )?;
        attach_optional_kprobe(&mut bpf, "iodyne_overlay_backing_write", "vfs_iter_write")?;
        attach_optional_kprobe(&mut bpf, "iodyne_overlay_write_enter", "ovl_write_iter")?;
        Ok(())
    })();
    // Path capture is a separate, newer capability. Count probes remain
    // attached when BTF lookup, verifier policy, or the helper allowlist
    // rejects this program.
    let path_status = attach_vfs_path_linux(&mut bpf);
    Ok((
        bpf,
        independent_vfs_status(path_status),
        independent_vfs_status(fuse_status),
        independent_vfs_status(fuse_writeback_status),
        independent_vfs_status(overlay_status),
    ))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn attach_optional_kprobe(
    bpf: &mut aya::Bpf,
    program_name: &str,
    function_name: &str,
) -> Result<(), String> {
    use aya::programs::KProbe;

    let Some(program) = bpf.program_mut(program_name) else {
        return Err(format!("eBPF program {program_name} is missing"));
    };
    let Ok(program): Result<&mut KProbe, _> = program.try_into() else {
        return Err(format!("invalid eBPF program {program_name}"));
    };
    program
        .load()
        .map_err(|error| format!("cannot load {program_name}: {error}"))?;
    program
        .attach(function_name, 0)
        .map_err(|error| format!("cannot attach {program_name} to {function_name}: {error}"))?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn attach_vfs_path_linux(bpf: &mut aya::Bpf) -> Result<(), String> {
    use aya::programs::FEntry;
    use aya::Btf;

    let btf = Btf::from_sys_fs().map_err(|error| format!("cannot read kernel BTF: {error}"))?;
    let program_name = "iodyne_vfs_path";
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

fn bpf_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn delegated_process_identity(pid: u32) -> Option<(u32, String)> {
    delegated_process_identity_at(pid, std::path::Path::new("/proc"))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn delegated_process_identity_at(pid: u32, proc_root: &std::path::Path) -> Option<(u32, String)> {
    let status = std::fs::read_to_string(proc_root.join(pid.to_string()).join("status")).ok()?;
    let tgid = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))?
        .trim()
        .parse::<u32>()
        .ok()?;
    let comm = std::fs::read_to_string(proc_root.join(tgid.to_string()).join("comm"))
        .ok()?
        .trim()
        .to_string();
    (!comm.is_empty()).then_some((tgid, comm))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn cgroup_id_is_container(cgroup_id: u64) -> bool {
    cgroup_id_is_container_at(cgroup_id, std::path::Path::new("/sys/fs/cgroup"))
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn cgroup_id_is_container_at(cgroup_id: u64, root: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    const MAX_CGROUP_DIRS: usize = 16_384;
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0;
    while let Some(path) = pending.pop() {
        visited += 1;
        if visited > MAX_CGROUP_DIRS {
            return false;
        }
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.ino() == cgroup_id {
            let relative = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
            return super::io::container_workload_label(&format!("0::/{relative}\n")).is_some();
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            continue;
        };
        pending.extend(entries.filter_map(Result::ok).filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_dir())
                .map(|_| entry.path())
        }));
    }
    false
}

fn decode_vfs_event(bytes: &[u8]) -> Option<VfsEvent> {
    if bytes.len() != std::mem::size_of::<VfsEvent>() {
        return None;
    }
    // Ring-buffer records are byte slices and do not promise Rust alignment.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<VfsEvent>()) })
}

fn attribution_kind(origin_kind: u32) -> VfsAttributionKind {
    match origin_kind {
        0 => VfsAttributionKind::Direct,
        FUSE_ORIGIN_PROTOCOL => VfsAttributionKind::FuseProtocol,
        FUSE_ORIGIN_WRITEBACK => VfsAttributionKind::FuseWriteback,
        FUSE_ORIGIN_PID_ZERO => VfsAttributionKind::FusePidZero,
        FUSE_ORIGIN_UNKNOWN => VfsAttributionKind::FuseUnresolved,
        value => VfsAttributionKind::Unknown(value),
    }
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

    fn vfs_event(bytes: u64, direction: u32) -> VfsEvent {
        let mut comm = [0; 16];
        comm[..4].copy_from_slice(b"test");
        let mut basename = [0; 64];
        basename[..8].copy_from_slice(b"data.log");
        VfsEvent {
            key: vfs_key(),
            bytes,
            pid: 1001,
            direction,
            origin_pid: 0,
            origin_tgid: 0,
            comm,
            origin_comm: [0; 16],
            basename,
            cgroup_id: 0,
            parent_tgid: 0,
            origin_parent_tgid: 0,
            parent_comm: [0; 16],
            origin_parent_comm: [0; 16],
            origin_kind: 0,
            _origin_padding: 0,
            origin_cgroup_id: 0,
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
    fn vfs_ring_record_decodes_without_alignment_assumptions() {
        let event = vfs_event(120, 0);
        assert_eq!(std::mem::size_of::<VfsEvent>(), 208);
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const VfsEvent).cast::<u8>(),
                std::mem::size_of::<VfsEvent>(),
            )
        };
        let decoded = decode_vfs_event(bytes).unwrap();
        assert_eq!(decoded.key, vfs_key());
        assert_eq!(decoded.bytes, 120);
        assert_eq!(decoded.pid, 1001);
        assert_eq!(bpf_string(&decoded.comm), "test");
        assert_eq!(bpf_string(&decoded.basename), "data.log");
        assert!(decode_vfs_event(&bytes[..bytes.len() - 1]).is_none());
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn delegated_process_identity_collapses_a_thread_to_its_process() {
        let root = std::env::temp_dir().join(format!("iodyne-fuse-fixture-{}", std::process::id()));
        std::fs::create_dir_all(root.join("101")).unwrap();
        std::fs::create_dir_all(root.join("100")).unwrap();
        std::fs::write(root.join("101/status"), "Name:\tworker\nTgid:\t100\n").unwrap();
        std::fs::write(root.join("100/comm"), "container-app\n").unwrap();

        assert_eq!(
            delegated_process_identity_at(101, &root),
            Some((100, "container-app".into()))
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn resolves_exited_container_ownership_from_cgroup_inode() {
        use std::os::unix::fs::MetadataExt;

        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let root =
            std::env::temp_dir().join(format!("iodyne-cgroup-id-fixture-{}", std::process::id()));
        let container = root
            .join("user.slice")
            .join(format!("libpod-{id}.scope"))
            .join("container");
        std::fs::create_dir_all(&container).unwrap();
        let cgroup_id = std::fs::metadata(&container).unwrap().ino();

        assert!(cgroup_id_is_container_at(cgroup_id, &root));

        std::fs::remove_dir_all(root).unwrap();
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
