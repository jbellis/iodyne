# Disk latency and VFS activity eBPF program

The checked-in x86 and arm64 objects are embedded when DiskWatch is built with
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
eBPF toolchain and `bpf-linker` on DiskWatch's Rust 1.75 build contract.

At runtime, DiskWatch requires Linux 5.11 or newer, BTF
(`/sys/kernel/btf/vmlinux`), the `block_rq_issue` and `block_rq_complete` raw
tracepoints, and permission to load tracing BPF programs. The 5.11 floor is an
ABI requirement, not merely a feature estimate: the probe expects the modern
raw tracepoint prototypes where request is argument 0 and completion bytes are
argument 2. Older kernels used a different `block_rq_issue` prototype, so the
loader rejects them rather than risk silently interpreting a request queue as
a request. A vendor kernel that removes the tracepoints or required BTF fields
fails probe load/attach and DiskWatch falls back to aggregate await.

Root normally has load permission; kernel lockdown, containers, or LSM policy
can still deny it. On modern kernels a non-root helper could instead be granted
`CAP_BPF` and `CAP_PERFMON`, but DiskWatch does not prescribe or install
capabilities.

The program records issue timestamps in a bounded LRU map and increments a
bounded per-CPU logarithmic histogram on final completion. Partial completions
leave the request timestamp in place; latency is measured from its issue to the
final completion. It never streams individual requests to userspace. The
current CO-RE field paths are `request.q.disk`, `request.cmd_flags`, and
`request.__data_len`; kernels whose BTF lacks them reject the load, and
DiskWatch falls back to aggregate await statistics.

Separate VFS objects contain optional `vfs_read` and `vfs_write` kprobes. Their
map creation, load, and attach status is independent: a kernel without the LRU
map type or either VFS symbol can still provide block latency. File activity is
accumulated in an 8192-entry LRU map keyed by filesystem device, inode, and
process TGID. Atomic counters keep updates safe when several threads in a
process access the same file.

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
basename and inode. It only polls paths for active count keys plus one race
retry; it never installs recursive watches or walks filesystem trees.

VFS byte counts are the `count` requested at function entry, not bytes returned
to the caller and not physical disk bytes. Page-cache hits are included;
buffered writeback is attributed to the writing process at the original VFS
call rather than to a later kernel worker. mmap I/O, direct paths that bypass
`vfs_read`/`vfs_write` (including some io_uring operations), metadata I/O, and
files whose operations bypass these hooks may be absent. Overlong paths and
kernels that reject event-time path capture use the `/proc` fallback; when that
also cannot resolve a file, DiskWatch retains the bounded basename and inode
identity.
