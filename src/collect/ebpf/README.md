# Disk latency and VFS activity eBPF program

The checked-in x86 and arm64 objects are embedded when iodyne is built with
`--features ebpf`. Most eBPF bytecode is architecture-independent, but VFS
kprobes receive arguments through the architecture's `pt_regs` layout, so the
loader selects the matching object. The userspace loader is Aya; Aya applies
the ELF's BTF CO-RE relocations for the running Linux kernel.

Regenerate the object after changing the C source:

```sh
src/collect/ebpf/build-ebpf.sh
```

This build step requires a Clang installation with the BPF target. It is not a
normal Cargo, release, or `cargo publish` prerequisite because the generated
object is checked in. Keeping this separate avoids imposing Aya's nightly Rust
eBPF toolchain and `bpf-linker` on iodyne's Rust 1.75 build contract.

At runtime, iodyne requires Linux 5.11 or newer, BTF
(`/sys/kernel/btf/vmlinux`), the `block_rq_issue` and `block_rq_complete` raw
tracepoints, and permission to load tracing BPF programs. The 5.11 floor is an
ABI requirement, not merely a feature estimate: the probe expects the modern
raw tracepoint prototypes where request is argument 0 and completion bytes are
argument 2. Older kernels used a different `block_rq_issue` prototype, so the
loader rejects them rather than risk silently interpreting a request queue as
a request. A vendor kernel that removes the tracepoints or required BTF fields
fails probe load/attach and iodyne falls back to aggregate await.

Root normally has load permission; kernel lockdown, containers, or LSM policy
can still deny it. On modern kernels a non-root helper could instead be granted
`CAP_BPF` and `CAP_PERFMON`, but iodyne does not prescribe or install
capabilities.

The program records issue timestamps in a bounded LRU map and increments a
bounded per-CPU logarithmic histogram on final completion. Partial completions
leave the request timestamp in place; latency is measured from its issue to the
final completion. It never streams individual requests to userspace. The
current CO-RE field paths are `request.q.disk`, `request.cmd_flags`, and
`request.__data_len`; kernels whose BTF lacks them reject the load, and
iodyne falls back to aggregate await statistics.

Separate VFS objects contain `vfs_read`, `vfs_write`, `vfs_iter_read`, and
`vfs_iter_write` kprobes. Their
map creation, load, and attach status is independent: a kernel without the ring
buffer map type or either VFS symbol can still provide block latency. Each
successful operation emits its completed byte count as a compact record to a
1 MiB ring buffer; userspace drains and groups a bounded number of received
records once per display interval. A full ring drops VFS attribution rather
than delaying the filesystem operation, and sustained producers cannot
monopolize the UI thread.

Classic `/dev/fuse` requests are correlated across the userspace-filesystem
boundary. When the kernel exposes `fuse_copy_args`, a probe reads the requester
PID directly from the selected in-kernel `fuse_req`; a `/dev/fuse` read-return
probe provides a compatibility fallback. Regular-file operations performed by
that daemon worker before its FUSE reply are attributed to the requester, whose
thread ID is resolved to a host process in userspace.

Writeback-cache requests can carry protocol PID zero because the task that
dirtied the page is no longer current when FUSE submits the write. A probe on
`fuse_file_write_iter` remembers the logical writer by FUSE mount and node ID;
the later request uses that identity only when it is at most 60 seconds old and
unambiguous. A different process writing the same node suppresses attribution
for 60 seconds rather than guessing. FUSE-over-io_uring, passthrough, and
requests that cannot be joined to a recent logical writer remain attributed to
the FUSE daemon. `--diag` reports the direct requester hook and PID-zero
writeback hook separately.

Kernel OverlayFS is handled without a delegation lookup because the original
container task remains current. Its nested `vfs_iter_read` and
`vfs_iter_write` calls expose the real upper/lower regular file and its
physical filesystem device. Direct iter I/O outside OverlayFS is also counted,
covering vectored callers that bypass scalar `vfs_read`/`vfs_write`. This does
not depend on optional internal OverlayFS symbols. `--diag` reports backing
attribution active whenever the generic iter probes attach.

The probe admits only regular files on filesystems with a nonzero block-device
major. Device nodes, PTYs, pipes, sockets, and anonymous pseudo-filesystems are
excluded before they can consume ring capacity or presentation rows.

After both count kprobes attach, `security_file_permission` is attached
independently as an fentry program and uses `bpf_d_path` to capture the first
observed path while the kernel `struct path` is still valid. Paths are bounded
to 256 bytes in a same-key LRU map. A kernel that rejects the fentry program or
helper still retains VFS counters. The path map is in the same ELF object, so
an earlier object or map-creation failure disables the complete VFS collector
(but not the separately loaded block-latency collector).

An empty map value records a failed or overlong-path attempt so the helper is
not retried for every operation. Userspace prefers an event-time path, then
scans at most 256 descriptors for each unresolved candidate process, then shows
basename and inode. It only polls paths for keys received from the ring during
the current interval; it never installs recursive watches or walks filesystem
trees.

VFS byte counts are successful return values from the probed VFS calls, not
caller buffer capacities and not physical disk bytes. Page-cache hits are
included; buffered writeback is attributed to the writing process at the
original VFS call rather than to a later kernel worker. mmap I/O, metadata I/O,
and direct file-operation paths that bypass both scalar and iter VFS helpers
(including some io_uring operations) remain outside this collector. Overlong
paths and kernels that reject event-time path capture use the `/proc` fallback;
when that also cannot resolve a file, iodyne retains the bounded basename and
inode identity.

For displayed host processes, userspace also reads the bounded
`/proc/<pid>/cgroup` record and recognizes Docker, Podman/libpod, containerd,
and CRI-O scope conventions. It adds a runtime plus shortened container ID to
the process label without connecting to a runtime socket or requiring runtime
metadata files.
