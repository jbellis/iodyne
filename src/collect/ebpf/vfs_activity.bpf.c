// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Optional VFS requested-byte attribution, loaded independently of latency.

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_NOEXIST 1
#define MAX_VFS_FILES 8192
#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 64

typedef unsigned int __u32;
typedef unsigned long long __u64;

struct super_block {
    __u32 s_dev;
} __attribute__((preserve_access_index));
struct inode {
    struct super_block *i_sb;
    unsigned long i_ino;
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

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long di;
    unsigned long si;
    unsigned long dx;
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
struct vfs_file_value {
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_ops;
    __u64 write_ops;
    __u32 pid;
    __u32 _padding;
    char comm[TASK_COMM_LEN];
    char basename[FILE_NAME_LEN];
};

// Values are updated atomically because threads in one process can execute on
// different CPUs while sharing the same (filesystem, inode, TGID) key.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_VFS_FILES);
    __type(key, struct vfs_file_key);
    __type(value, struct vfs_file_value);
} VFS_FILES SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size,
                                         const void *unsafe_ptr) = (void *)115;

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

static __inline __attribute__((always_inline)) __u64 vfs_count_arg(
    struct pt_regs *ctx) {
    __u64 count = 0;
#if defined(__TARGET_ARCH_x86)
    bpf_probe_read_kernel(&count, sizeof(count),
                          __builtin_preserve_access_index(&ctx->dx));
#elif defined(__TARGET_ARCH_arm64)
    bpf_probe_read_kernel(&count, sizeof(count),
                          __builtin_preserve_access_index(&ctx->regs[2]));
#endif
    return count;
}

static __inline __attribute__((always_inline)) int record_vfs(
    struct pt_regs *ctx, __u32 direction) {
    struct file *file = vfs_file_arg(ctx);
    if (!file)
        return 0;
    struct inode *inode;
    if (bpf_probe_read_kernel(&inode, sizeof(inode),
                              __builtin_preserve_access_index(&file->f_inode)) ||
        !inode)
        return 0;
    struct super_block *sb;
    if (bpf_probe_read_kernel(&sb, sizeof(sb),
                              __builtin_preserve_access_index(&inode->i_sb)) ||
        !sb)
        return 0;
    __u32 dev;
    unsigned long inode_number;
    if (bpf_probe_read_kernel(&dev, sizeof(dev),
                              __builtin_preserve_access_index(&sb->s_dev)) ||
        bpf_probe_read_kernel(&inode_number, sizeof(inode_number),
                              __builtin_preserve_access_index(&inode->i_ino)))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct vfs_file_key key = {
        .major = dev >> 20,
        .minor = dev & ((1U << 20) - 1),
        .inode = (__u64)inode_number,
        .tgid = (__u32)(pid_tgid >> 32),
    };
    struct vfs_file_value *value = bpf_map_lookup_elem(&VFS_FILES, &key);
    if (!value) {
        struct vfs_file_value initial = {.pid = (__u32)pid_tgid};
        bpf_get_current_comm(initial.comm, sizeof(initial.comm));
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
                bpf_probe_read_kernel_str(initial.basename,
                                          sizeof(initial.basename), name);
        }
        bpf_map_update_elem(&VFS_FILES, &key, &initial, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&VFS_FILES, &key);
    }
    if (!value)
        return 0;

    // The thread handling the latest operation can have a descriptor table
    // that is not visible through the thread-group leader. Keep its PID so
    // userspace can try /proc/<pid>/fd before falling back to the TGID.
    value->pid = (__u32)pid_tgid;

    __u64 count = vfs_count_arg(ctx);
    if (direction == 0) {
        __sync_fetch_and_add(&value->read_bytes, count);
        __sync_fetch_and_add(&value->read_ops, 1);
    } else {
        __sync_fetch_and_add(&value->write_bytes, count);
        __sync_fetch_and_add(&value->write_ops, 1);
    }
    return 0;
}

SEC("kprobe/vfs_read")
int diskwatch_vfs_read(struct pt_regs *ctx) {
    return record_vfs(ctx, 0);
}
SEC("kprobe/vfs_write")
int diskwatch_vfs_write(struct pt_regs *ctx) {
    return record_vfs(ctx, 1);
}

char LICENSE[] SEC("license") = "GPL";
