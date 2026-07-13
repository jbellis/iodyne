// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Optional VFS requested-byte attribution, loaded independently of latency.

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define MAX_VFS_FILES 8192
#define VFS_RING_BYTES (1024 * 1024)
#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 64
#define FILE_PATH_LEN 256

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
struct vfs_event {
    struct vfs_file_key key;
    __u64 bytes;
    __u32 pid;
    __u32 direction;
    char comm[TASK_COMM_LEN];
    char basename[FILE_NAME_LEN];
};
struct vfs_file_path {
    char path[FILE_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, VFS_RING_BYTES);
} VFS_EVENTS SEC(".maps");

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
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size,
                                         const void *unsafe_ptr) = (void *)115;
static long (*bpf_d_path)(struct path *path, char *buf, __u32 size) =
    (void *)147;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size,
                                  __u64 flags) = (void *)130;

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
    if (bpf_probe_read_kernel(&dev, sizeof(dev),
                              __builtin_preserve_access_index(&sb->s_dev)) ||
        bpf_probe_read_kernel(&inode_number, sizeof(inode_number),
                              __builtin_preserve_access_index(&inode->i_ino)))
        return -1;

    key->major = dev >> 20;
    key->minor = dev & ((1U << 20) - 1);
    key->inode = (__u64)inode_number;
    key->tgid = (__u32)(pid_tgid >> 32);
    key->_padding = 0;
    return 0;
}

static __inline __attribute__((always_inline)) void vfs_event_metadata(
    struct file *file, __u64 pid_tgid, struct vfs_event *event) {
    event->pid = (__u32)pid_tgid;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
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
            bpf_probe_read_kernel_str(event->basename,
                                      sizeof(event->basename), name);
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
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct vfs_file_key key = {};
    if (vfs_key_for_file(file, pid_tgid, &key))
        return 0;
    struct vfs_event event = {};
    event.key = key;
    event.bytes = vfs_count_arg(ctx);
    event.direction = direction;
    vfs_event_metadata(file, pid_tgid, &event);
    // A full ring drops attribution rather than delaying the filesystem call.
    bpf_ringbuf_output(&VFS_EVENTS, &event, sizeof(event), 0);
    return 0;
}

SEC("kprobe/vfs_read")
int iodyne_vfs_read(struct pt_regs *ctx) {
    return record_vfs(ctx, 0);
}
SEC("kprobe/vfs_write")
int iodyne_vfs_write(struct pt_regs *ctx) {
    return record_vfs(ctx, 1);
}

// bpf_d_path is restricted to a small verifier allowlist that includes
// security_file_permission fentry programs. This hook runs while f_path is
// valid, after the VFS entry probe has created the corresponding count key.
SEC("fentry/security_file_permission")
int iodyne_vfs_path(__u64 *ctx) {
    struct file *file = (struct file *)ctx[0];
    __u64 pid_tgid = bpf_get_current_pid_tgid();
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
