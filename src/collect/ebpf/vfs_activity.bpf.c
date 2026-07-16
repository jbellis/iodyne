// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Optional VFS requested-byte attribution, loaded independently of latency.

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define MAX_VFS_FILES 8192
#define MAX_VFS_AGG_ENTRIES 8192
#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 64
#define FILE_PATH_LEN 256
#define S_IFMT 00170000
#define S_IFREG 0100000
#define S_IFCHR 0020000
#define FUSE_DEVICE_MAJOR 10
#define FUSE_DEVICE_MINOR 229
#define FUSE_ORIGIN_UNKNOWN 0xffffffffU
#define FUSE_ORIGIN_PROTOCOL 1
#define FUSE_ORIGIN_WRITEBACK 2
#define FUSE_ORIGIN_PID_ZERO 3
#define FUSE_WRITE 16
#define FUSE_WRITER_MAX_AGE_NS (60ULL * 1000 * 1000 * 1000)

typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct super_block {
    __u32 s_dev;
    void *s_fs_info;
} __attribute__((preserve_access_index));
struct inode {
    struct super_block *i_sb;
    unsigned long i_ino;
    __u16 i_mode;
    __u32 i_rdev;
} __attribute__((preserve_access_index));
struct qstr {
    const unsigned char *name;
} __attribute__((preserve_access_index));
struct dentry {
    struct qstr d_name;
} __attribute__((preserve_access_index));
struct path {
    struct dentry *dentry;
} __attribute__((preserve_access_index));
struct file {
    struct path f_path;
    struct inode *f_inode;
} __attribute__((preserve_access_index));
struct kiocb {
    struct file *ki_filp;
} __attribute__((preserve_access_index));
struct task_struct {
    int tgid;
    char comm[TASK_COMM_LEN];
    struct task_struct *real_parent;
} __attribute__((preserve_access_index));
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long di;
    unsigned long si;
    unsigned long dx;
    unsigned long ax;
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long regs[31];
} __attribute__((preserve_access_index));
#else
#error unsupported target architecture
#endif

struct vfs_file_key {
    __u32 major;
    __u32 minor;
    __u64 inode;
    __u32 tgid;
    __u32 _padding;
};
struct vfs_agg_key {
    __u32 major;
    __u32 minor;
    __u64 inode;
    __u32 tgid;
    __u32 origin_pid;
    __u32 origin_kind;
    __u32 _padding;
};
struct vfs_agg_value {
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_ops;
    __u64 write_ops;
    __u32 pid;
    __u32 origin_tgid;
    __u64 cgroup_id;
    __u64 origin_cgroup_id;
    __u32 parent_tgid;
    __u32 origin_parent_tgid;
    char comm[TASK_COMM_LEN];
    char origin_comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char origin_parent_comm[TASK_COMM_LEN];
    char basename[FILE_NAME_LEN];
};
struct fuse_in_header {
    __u32 len;
    __u32 opcode;
    __u64 unique;
    __u64 nodeid;
    __u32 uid;
    __u32 gid;
    __u32 pid;
    __u32 padding;
};
struct fuse_req {
    // FUSE request layout is private to the module, whose split BTF Aya 0.12
    // cannot use for CO-RE. These fields have retained their offsets from the
    // oldest supported 5.14 vendor kernel through current kernels.
    char _before_in[56];
    struct {
        struct fuse_in_header h;
    } in;
    char _before_fm[48];
    void *fm;
};
struct fuse_copy_state {
    int write;
    __u32 _padding;
    struct fuse_req *req;
};
struct vfs_file_path {
    char path[FILE_PATH_LEN];
};
struct pending_vfs_io {
    __u64 file;
    __u32 direction;
    __u32 _padding;
};
struct requester_identity {
    __u32 pid;
    __u32 tgid;
    __u32 parent_tgid;
    __u32 _padding;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
};
struct active_fuse_request {
    __u32 origin_pid;
    __u32 kind;
    struct requester_identity identity;
};
struct fuse_writer_key {
    __u64 mount;
    __u64 nodeid;
};
struct fuse_writer {
    struct requester_identity identity;
    __u64 last_seen_ns;
    __u64 ambiguous_until_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VFS_AGG_ENTRIES);
    __type(key, struct vfs_agg_key);
    __type(value, struct vfs_agg_value);
} VFS_AGG SEC(".maps");

// Aggregation-table pressure must be observable: losing attribution is
// acceptable, silently presenting an incomplete sample as complete is not.
// Counts operations that could not be recorded because the table was full.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} VFS_DROPS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} SELF_TGID SEC(".maps");

// A classic /dev/fuse read returns one request. Remember its userspace
// destination until the kretprobe can read the populated fuse_in_header.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} PENDING_FUSE_READS SEC(".maps");

// libfuse workers normally receive and service a request synchronously on one
// thread. While that thread is active, backing-file VFS calls are delegated by
// the request PID rather than initiated by the daemon itself.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct active_fuse_request);
} ACTIVE_FUSE_REQUESTS SEC(".maps");

// Writeback-cache requests carry protocol PID zero. Remember the process that
// dirtied each logical FUSE node while it is still current, scoped by mount so
// independent containers cannot collide. Conflicting writers stay ambiguous
// for one bounded writeback window rather than receiving invented attribution.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct fuse_writer_key);
    __type(value, struct fuse_writer);
} FUSE_LOGICAL_WRITERS SEC(".maps");

// FUSE supplies only a PID with the later daemon request. Cache the name and
// process group while the requester is current so short-lived commands remain
// identifiable after they exit.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct requester_identity);
} FUSE_REQUESTER_IDENTITIES SEC(".maps");

// The file remains valid until the VFS call returns. Retain it so the return
// probe can charge bytes actually transferred instead of buffer capacity.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_vfs_io);
} PENDING_VFS_IO SEC(".maps");

// Iter-based calls can nest below a scalar operation (notably through
// OverlayFS), so they need independent pending state. They also cover direct
// vfs_iter_read/write callers such as readv/writev that never pass through
// vfs_read/write.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_vfs_io);
} PENDING_ITER_IO SEC(".maps");

// Kept separate from counters so first-path arbitration is an atomic
// BPF_NOEXIST insertion and userspace never observes a partially-written path.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_VFS_FILES);
    __type(key, struct vfs_file_key);
    __type(value, struct vfs_file_path);
} VFS_PATHS SEC(".maps");

static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static void *(*bpf_get_current_task)(void) = (void *)35;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size,
                                         const void *unsafe_ptr) = (void *)115;
static long (*bpf_probe_read_user)(void *dst, __u32 size,
                                   const void *unsafe_ptr) = (void *)112;
static long (*bpf_d_path)(struct path *path, char *buf, __u32 size) =
    (void *)147;

static __inline __attribute__((always_inline)) void current_parent_identity(
    __u32 *tgid, char comm[TASK_COMM_LEN]) {
    struct task_struct *task = bpf_get_current_task();
    struct task_struct *parent = 0;
    int parent_tgid = 0;
    if (!task ||
        bpf_probe_read_kernel(
            &parent, sizeof(parent),
            __builtin_preserve_access_index(&task->real_parent)) ||
        !parent ||
        bpf_probe_read_kernel(
            &parent_tgid, sizeof(parent_tgid),
            __builtin_preserve_access_index(&parent->tgid)) ||
        parent_tgid <= 1)
        return;
    *tgid = (__u32)parent_tgid;
    bpf_probe_read_kernel(comm, TASK_COMM_LEN,
                          __builtin_preserve_access_index(&parent->comm));
}

static __inline __attribute__((always_inline)) int vfs_key_for_file(
    struct file *file, __u64 pid_tgid, struct vfs_file_key *key) {
    struct inode *inode;
    if (!file ||
        bpf_probe_read_kernel(&inode, sizeof(inode),
                              __builtin_preserve_access_index(&file->f_inode)) ||
        !inode)
        return -1;
    struct super_block *sb;
    if (bpf_probe_read_kernel(&sb, sizeof(sb),
                              __builtin_preserve_access_index(&inode->i_sb)) ||
        !sb)
        return -1;
    __u32 dev;
    unsigned long inode_number;
    __u16 mode;
    if (bpf_probe_read_kernel(&dev, sizeof(dev),
                              __builtin_preserve_access_index(&sb->s_dev)) ||
        bpf_probe_read_kernel(&inode_number, sizeof(inode_number),
                              __builtin_preserve_access_index(&inode->i_ino)) ||
        bpf_probe_read_kernel(&mode, sizeof(mode),
                              __builtin_preserve_access_index(&inode->i_mode)))
        return -1;

    // Keep the storage view about storage: reject device nodes, PTYs, pipes,
    // sockets, and regular-looking files on anonymous/pseudo filesystems.
    if ((mode & S_IFMT) != S_IFREG || (dev >> 20) == 0)
        return -1;

    key->major = dev >> 20;
    key->minor = dev & ((1U << 20) - 1);
    key->inode = (__u64)inode_number;
    key->tgid = (__u32)(pid_tgid >> 32);
    key->_padding = 0;
    return 0;
}

static __inline __attribute__((always_inline)) void vfs_agg_metadata(
    struct file *file, __u64 pid_tgid, struct vfs_agg_value *value) {
    value->pid = (__u32)pid_tgid;
    bpf_get_current_comm(value->comm, sizeof(value->comm));
    current_parent_identity(&value->parent_tgid, value->parent_comm);
    struct dentry *dentry;
    if (!bpf_probe_read_kernel(
            &dentry, sizeof(dentry),
            __builtin_preserve_access_index(&file->f_path.dentry)) &&
        dentry) {
        const unsigned char *name;
        if (!bpf_probe_read_kernel(
                &name, sizeof(name),
                __builtin_preserve_access_index(&dentry->d_name.name)) &&
            name)
            bpf_probe_read_kernel_str(value->basename,
                                      sizeof(value->basename), name);
    }
}

static __inline __attribute__((always_inline)) void vfs_agg_add(
    struct vfs_agg_value *value, __u64 count, __u32 direction) {
    if (direction == 0) {
        __sync_fetch_and_add(&value->read_bytes, count);
        __sync_fetch_and_add(&value->read_ops, 1);
    } else if (direction == 1) {
        __sync_fetch_and_add(&value->write_bytes, count);
        __sync_fetch_and_add(&value->write_ops, 1);
    }
}

static __inline __attribute__((always_inline)) struct file *vfs_file_arg(
    struct pt_regs *ctx) {
    struct file *file = 0;
#if defined(__TARGET_ARCH_x86)
    bpf_probe_read_kernel(&file, sizeof(file),
                          __builtin_preserve_access_index(&ctx->di));
#elif defined(__TARGET_ARCH_arm64)
    bpf_probe_read_kernel(&file, sizeof(file),
                          __builtin_preserve_access_index(&ctx->regs[0]));
#endif
    return file;
}

static __inline __attribute__((always_inline)) void *first_pointer_arg(
    struct pt_regs *ctx) {
    void *pointer = 0;
#if defined(__TARGET_ARCH_x86)
    bpf_probe_read_kernel(&pointer, sizeof(pointer),
                          __builtin_preserve_access_index(&ctx->di));
#elif defined(__TARGET_ARCH_arm64)
    bpf_probe_read_kernel(&pointer, sizeof(pointer),
                          __builtin_preserve_access_index(&ctx->regs[0]));
#endif
    return pointer;
}

static __inline __attribute__((always_inline)) __u64 vfs_buffer_arg(
    struct pt_regs *ctx) {
    __u64 buffer = 0;
#if defined(__TARGET_ARCH_x86)
    bpf_probe_read_kernel(&buffer, sizeof(buffer),
                          __builtin_preserve_access_index(&ctx->si));
#elif defined(__TARGET_ARCH_arm64)
    bpf_probe_read_kernel(&buffer, sizeof(buffer),
                          __builtin_preserve_access_index(&ctx->regs[1]));
#endif
    return buffer;
}

static __inline __attribute__((always_inline)) long vfs_return_value(
    struct pt_regs *ctx) {
    long value = 0;
#if defined(__TARGET_ARCH_x86)
    bpf_probe_read_kernel(&value, sizeof(value),
                          __builtin_preserve_access_index(&ctx->ax));
#elif defined(__TARGET_ARCH_arm64)
    bpf_probe_read_kernel(&value, sizeof(value),
                          __builtin_preserve_access_index(&ctx->regs[0]));
#endif
    return value;
}

static __inline __attribute__((always_inline)) int is_fuse_device(
    struct file *file) {
    struct inode *inode;
    if (!file ||
        bpf_probe_read_kernel(&inode, sizeof(inode),
                              __builtin_preserve_access_index(&file->f_inode)) ||
        !inode)
        return 0;
    __u16 mode;
    __u32 rdev;
    if (bpf_probe_read_kernel(&mode, sizeof(mode),
                              __builtin_preserve_access_index(&inode->i_mode)) ||
        bpf_probe_read_kernel(&rdev, sizeof(rdev),
                              __builtin_preserve_access_index(&inode->i_rdev)))
        return 0;
    return (mode & S_IFMT) == S_IFCHR && (rdev >> 20) == FUSE_DEVICE_MAJOR &&
           (rdev & ((1U << 20) - 1)) == FUSE_DEVICE_MINOR;
}

static __inline __attribute__((always_inline)) void remember_fuse_identity(
    __u32 key, __u64 pid_tgid) {
    if (!key)
        return;
    struct requester_identity identity = {
        .pid = (__u32)pid_tgid,
        .tgid = (__u32)(pid_tgid >> 32),
        .cgroup_id = bpf_get_current_cgroup_id(),
    };
    bpf_get_current_comm(identity.comm, sizeof(identity.comm));
    current_parent_identity(&identity.parent_tgid, identity.parent_comm);
    bpf_map_update_elem(&FUSE_REQUESTER_IDENTITIES, &key, &identity, 0);
}

static __inline __attribute__((always_inline)) void current_identity(
    __u64 pid_tgid, struct requester_identity *identity) {
    identity->pid = (__u32)pid_tgid;
    identity->tgid = (__u32)(pid_tgid >> 32);
    identity->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(identity->comm, sizeof(identity->comm));
    current_parent_identity(&identity->parent_tgid, identity->parent_comm);
}

static __inline __attribute__((always_inline)) int fuse_writer_key_for_file(
    struct file *file, struct fuse_writer_key *key) {
    struct inode *inode = 0;
    struct super_block *sb = 0;
    void *fm = 0;
    __u64 nodeid = 0;
    if (!file ||
        bpf_probe_read_kernel(&inode, sizeof(inode),
                              __builtin_preserve_access_index(&file->f_inode)) ||
        !inode ||
        bpf_probe_read_kernel(&sb, sizeof(sb),
                              __builtin_preserve_access_index(&inode->i_sb)) ||
        !sb ||
        bpf_probe_read_kernel(&fm, sizeof(fm),
                              __builtin_preserve_access_index(&sb->s_fs_info)) ||
        !fm ||
        bpf_probe_read_kernel(
            &nodeid, sizeof(nodeid),
            (void *)inode +
                __builtin_preserve_type_info(*(struct inode *)0, 1)) ||
        !nodeid)
        return -1;
    key->mount = (__u64)fm;
    key->nodeid = nodeid;
    return 0;
}

static __inline __attribute__((always_inline)) void remember_fuse_writer(
    struct file *file, __u64 pid_tgid) {
    struct fuse_writer_key key = {};
    if (fuse_writer_key_for_file(file, &key))
        return;
    __u64 now = bpf_ktime_get_ns();
    struct fuse_writer next = {
        .last_seen_ns = now,
    };
    current_identity(pid_tgid, &next.identity);
    struct fuse_writer *previous =
        bpf_map_lookup_elem(&FUSE_LOGICAL_WRITERS, &key);
    if (previous && now - previous->last_seen_ns <= FUSE_WRITER_MAX_AGE_NS) {
        if (previous->identity.tgid != next.identity.tgid)
            next.ambiguous_until_ns = now + FUSE_WRITER_MAX_AGE_NS;
        else
            next.ambiguous_until_ns = previous->ambiguous_until_ns;
    }
    bpf_map_update_elem(&FUSE_LOGICAL_WRITERS, &key, &next, 0);
}

static __inline __attribute__((always_inline)) void begin_fuse_request(
    __u64 daemon_pid_tgid, struct fuse_req *req, struct fuse_in_header *header) {
    struct active_fuse_request active = {};
    if (header->pid) {
        active.origin_pid = header->pid;
        active.kind = FUSE_ORIGIN_PROTOCOL;
    } else {
        active.origin_pid = FUSE_ORIGIN_UNKNOWN;
        active.kind = FUSE_ORIGIN_PID_ZERO;
        if (header->opcode == FUSE_WRITE && header->nodeid && req) {
            void *fm = 0;
            if (!bpf_probe_read_kernel(&fm, sizeof(fm), &req->fm) &&
                fm) {
                struct fuse_writer_key key = {
                    .mount = (__u64)fm,
                    .nodeid = header->nodeid,
                };
                struct fuse_writer *writer =
                    bpf_map_lookup_elem(&FUSE_LOGICAL_WRITERS, &key);
                __u64 now = bpf_ktime_get_ns();
                if (writer && now - writer->last_seen_ns <=
                                  FUSE_WRITER_MAX_AGE_NS &&
                    writer->ambiguous_until_ns <= now) {
                    active.origin_pid = writer->identity.pid;
                    active.kind = FUSE_ORIGIN_WRITEBACK;
                    active.identity = writer->identity;
                }
            }
        }
    }
    bpf_map_update_elem(&ACTIVE_FUSE_REQUESTS, &daemon_pid_tgid, &active, 0);
}

static __inline __attribute__((always_inline)) void begin_fuse_read(
    struct pt_regs *ctx, struct file *file, __u64 pid_tgid) {
    if (!is_fuse_device(file))
        return;
    // The previous request is no longer active by the time this worker asks
    // for another one, even if its reply path was not observable.
    bpf_map_delete_elem(&ACTIVE_FUSE_REQUESTS, &pid_tgid);
    __u64 buffer = vfs_buffer_arg(ctx);
    if (buffer)
        bpf_map_update_elem(&PENDING_FUSE_READS, &pid_tgid, &buffer, 0);
}

static __inline __attribute__((always_inline)) void finish_fuse_reply(
    __u64 pid_tgid) {
    bpf_map_delete_elem(&ACTIVE_FUSE_REQUESTS, &pid_tgid);
}

static __inline __attribute__((always_inline)) struct file *first_file_arg(
    struct pt_regs *ctx) {
    return vfs_file_arg(ctx);
}

static __inline __attribute__((always_inline)) int record_vfs_file(
    struct file *file, __u64 count, __u32 direction) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    __u32 *self_tgid = bpf_map_lookup_elem(&SELF_TGID, &zero);
    if (self_tgid && *self_tgid == (__u32)(pid_tgid >> 32))
        return 0;
    struct vfs_file_key key = {};
    if (vfs_key_for_file(file, pid_tgid, &key))
        return 0;

    __u32 origin_pid = 0;
    __u32 origin_kind = 0;
    struct requester_identity *identity = 0;
    struct active_fuse_request *active =
        bpf_map_lookup_elem(&ACTIVE_FUSE_REQUESTS, &pid_tgid);
    if (active) {
        origin_pid = active->origin_pid;
        origin_kind = active->kind;
        if (active->identity.tgid)
            identity = &active->identity;
        else if (active->origin_pid != FUSE_ORIGIN_UNKNOWN)
            identity = bpf_map_lookup_elem(&FUSE_REQUESTER_IDENTITIES,
                                           &active->origin_pid);
        if (identity)
            origin_pid = identity->pid;
    }

    struct vfs_agg_key agg_key = {
        .major = key.major,
        .minor = key.minor,
        .inode = key.inode,
        .tgid = key.tgid,
        .origin_pid = origin_pid,
        .origin_kind = origin_kind,
        ._padding = 0,
    };
    struct vfs_agg_value *value = bpf_map_lookup_elem(&VFS_AGG, &agg_key);
    if (value) {
        vfs_agg_add(value, count, direction);
        return 0;
    }

    struct vfs_agg_value next = {};
    if (direction == 0) {
        next.read_bytes = count;
        next.read_ops = 1;
    } else if (direction == 1) {
        next.write_bytes = count;
        next.write_ops = 1;
    }
    next.cgroup_id = bpf_get_current_cgroup_id();
    if (identity) {
        next.origin_tgid = identity->tgid;
        next.origin_parent_tgid = identity->parent_tgid;
        next.origin_cgroup_id = identity->cgroup_id;
        __builtin_memcpy(next.origin_comm, identity->comm,
                         sizeof(next.origin_comm));
        __builtin_memcpy(next.origin_parent_comm, identity->parent_comm,
                         sizeof(next.origin_parent_comm));
    }
    vfs_agg_metadata(file, pid_tgid, &next);

    if (bpf_map_update_elem(&VFS_AGG, &agg_key, &next, BPF_NOEXIST)) {
        value = bpf_map_lookup_elem(&VFS_AGG, &agg_key);
        if (value) {
            vfs_agg_add(value, count, direction);
            return 0;
        }
        __u64 *drops = bpf_map_lookup_elem(&VFS_DROPS, &zero);
        if (drops)
            __sync_fetch_and_add(drops, 1);
    }
    return 0;
}

static __inline __attribute__((always_inline)) void begin_pending_io(
    void *map, struct file *file, __u32 direction) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_vfs_io pending = {
        .file = (__u64)file,
        .direction = direction,
    };
    bpf_map_update_elem(map, &pid_tgid, &pending, 0);
}

static __inline __attribute__((always_inline)) int complete_pending_io(
    void *map, struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_vfs_io *stored = bpf_map_lookup_elem(map, &pid_tgid);
    if (!stored)
        return 0;
    struct pending_vfs_io pending = *stored;
    bpf_map_delete_elem(map, &pid_tgid);
    long completed = vfs_return_value(ctx);
    if (completed <= 0)
        return 0;
    return record_vfs_file((struct file *)pending.file, (__u64)completed,
                           pending.direction);
}

SEC("kprobe/vfs_read")
int iodyne_vfs_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct file *file = vfs_file_arg(ctx);
    begin_fuse_read(ctx, file, pid_tgid);
    begin_pending_io(&PENDING_VFS_IO, file, 0);
    return 0;
}
SEC("kprobe/vfs_write")
int iodyne_vfs_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct file *file = vfs_file_arg(ctx);
    if (is_fuse_device(file))
        finish_fuse_reply(pid_tgid);
    begin_pending_io(&PENDING_VFS_IO, file, 1);
    return 0;
}

SEC("kretprobe/vfs_read")
int iodyne_fuse_read_complete(struct pt_regs *ctx) {
    complete_pending_io(&PENDING_VFS_IO, ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *buffer = bpf_map_lookup_elem(&PENDING_FUSE_READS, &pid_tgid);
    if (!buffer)
        return 0;
    __u64 user_buffer = *buffer;
    bpf_map_delete_elem(&PENDING_FUSE_READS, &pid_tgid);
    if (vfs_return_value(ctx) < (long)sizeof(struct fuse_in_header))
        return 0;
    struct fuse_in_header header = {};
    if (bpf_probe_read_user(&header, sizeof(header), (void *)user_buffer) ||
        header.len < sizeof(header) || !header.unique)
        return 0;
    begin_fuse_request(pid_tgid, 0, &header);
    return 0;
}

SEC("kretprobe/vfs_write")
int iodyne_vfs_write_complete(struct pt_regs *ctx) {
    return complete_pending_io(&PENDING_VFS_IO, ctx);
}

// fuse_copy_args runs after the kernel has selected a request and before it is
// copied to the userspace filesystem daemon. Reading the kernel request here
// avoids depending on the daemon's read buffer layout or syscall wrapper.
SEC("kprobe/fuse_copy_args")
int iodyne_fuse_request(struct pt_regs *ctx) {
    struct fuse_copy_state *cs = first_pointer_arg(ctx);
    if (!cs)
        return 0;
    int write = 0;
    struct fuse_req *req = 0;
    if (bpf_probe_read_kernel(&write, sizeof(write), &cs->write) ||
        !write ||
        bpf_probe_read_kernel(&req, sizeof(req), &cs->req) ||
        !req)
        return 0;
    struct fuse_in_header header = {};
    if (bpf_probe_read_kernel(&header, sizeof(header), &req->in.h))
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    begin_fuse_request(pid_tgid, req, &header);
    return 0;
}

// The request header is populated before synchronous FUSE requests wait for
// their answer. Current is still the requester here, so the header PID can be
// mapped to the real host process even across PID namespaces.
SEC("kprobe/request_wait_answer")
int iodyne_fuse_requester_identity(struct pt_regs *ctx) {
    struct fuse_req *req = first_pointer_arg(ctx);
    if (!req)
        return 0;
    __u32 origin_pid = 0;
    if (bpf_probe_read_kernel(&origin_pid, sizeof(origin_pid), &req->in.h.pid) ||
        !origin_pid)
        return 0;
    remember_fuse_identity(origin_pid, bpf_get_current_pid_tgid());
    return 0;
}

// Capture the writer before writeback-cache decouples dirtying the logical
// FUSE inode from the later PID-zero request serviced by the daemon.
SEC("kprobe/fuse_file_write_iter")
int iodyne_fuse_logical_writer(struct pt_regs *ctx) {
    struct kiocb *iocb = first_pointer_arg(ctx);
    struct file *file = 0;
    if (!iocb ||
        bpf_probe_read_kernel(
            &file, sizeof(file),
            __builtin_preserve_access_index(&iocb->ki_filp)) ||
        !file)
        return 0;
    remember_fuse_writer(file, bpf_get_current_pid_tgid());
    return 0;
}

// libfuse commonly replies with writev, which bypasses vfs_write but still
// reaches the FUSE device's write_iter implementation.
SEC("kprobe/fuse_dev_write")
int iodyne_fuse_reply(struct pt_regs *ctx) {
    finish_fuse_reply(bpf_get_current_pid_tgid());
    return 0;
}

SEC("kprobe/vfs_iter_read")
int iodyne_vfs_iter_read(struct pt_regs *ctx) {
    begin_pending_io(&PENDING_ITER_IO, first_file_arg(ctx), 0);
    return 0;
}
SEC("kprobe/vfs_iter_write")
int iodyne_vfs_iter_write(struct pt_regs *ctx) {
    begin_pending_io(&PENDING_ITER_IO, first_file_arg(ctx), 1);
    return 0;
}
SEC("kretprobe/vfs_iter_read")
int iodyne_vfs_iter_read_complete(struct pt_regs *ctx) {
    return complete_pending_io(&PENDING_ITER_IO, ctx);
}
SEC("kretprobe/vfs_iter_write")
int iodyne_vfs_iter_write_complete(struct pt_regs *ctx) {
    return complete_pending_io(&PENDING_ITER_IO, ctx);
}

// bpf_d_path is restricted to a small verifier allowlist that includes
// security_file_permission fentry programs. This hook runs while f_path is
// valid, after the VFS entry probe has created the corresponding count key.
SEC("fentry/security_file_permission")
int iodyne_vfs_path(__u64 *ctx) {
    struct file *file = (struct file *)ctx[0];
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    __u32 *self_tgid = bpf_map_lookup_elem(&SELF_TGID, &zero);
    if (self_tgid && *self_tgid == (__u32)(pid_tgid >> 32))
        return 0;
    struct vfs_file_key key = {};
    if (vfs_key_for_file(file, pid_tgid, &key))
        return 0;
    struct vfs_file_path captured = {};
    // Publish an empty sentinel first. Only the insertion winner attempts the
    // relatively expensive helper; failure and overlong paths remain a stable
    // unresolved sentinel instead of retrying on every operation.
    if (bpf_map_update_elem(&VFS_PATHS, &key, &captured, BPF_NOEXIST))
        return 0;
    if (bpf_d_path(&file->f_path, captured.path, sizeof(captured.path)) < 0)
        return 0;
    bpf_map_update_elem(&VFS_PATHS, &key, &captured, BPF_EXIST);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
