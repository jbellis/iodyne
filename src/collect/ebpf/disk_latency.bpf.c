// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Built with build-ebpf.sh. Keep this file freestanding: release builds load
// the checked-in ELF and do not require kernel headers, clang, or libbpf.

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define MAX_IN_FLIGHT 65536
#define MAX_HISTOGRAM_KEYS 16384
#define LATENCY_BUCKETS 32
#define REQ_OP_MASK 0xff
#define REQ_OP_READ 0
#define REQ_OP_WRITE 1

typedef unsigned int __u32;
typedef unsigned long long __u64;

// These deliberately partial declarations are relocated by kernel BTF. Only
// the named fields below form the runtime kernel ABI used by this program.
struct gendisk {
    int major;
    int first_minor;
} __attribute__((preserve_access_index));

struct request_queue {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request {
    struct request_queue *q;
    __u32 cmd_flags;
    __u32 __data_len;
} __attribute__((preserve_access_index));

struct bpf_raw_tracepoint_args {
    __u64 args[0];
};

struct start_value {
    __u64 started_ns;
    __u32 major;
    __u32 minor;
    __u32 direction;
    __u32 _padding;
};

struct histogram_key {
    __u32 major;
    __u32 minor;
    __u32 direction;
    __u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IN_FLIGHT);
    __type(key, __u64);
    __type(value, struct start_value);
} STARTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_HISTOGRAM_KEYS);
    __type(key, struct histogram_key);
    __type(value, __u64);
} HISTOGRAMS SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) = (void *)113;

static __inline __attribute__((always_inline)) __u32 latency_bucket(__u64 us) {
    if (us < 2)
        return 0;
    __u32 bucket = 63 - __builtin_clzll(us);
    if (bucket >= LATENCY_BUCKETS)
        bucket = LATENCY_BUCKETS - 1;
    return bucket;
}

SEC("raw_tracepoint/block_rq_issue")
int diskwatch_block_issue(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq = (struct request *)ctx->args[0];
    if (!rq)
        return 0;

    __u32 operation;
    if (bpf_probe_read_kernel(
            &operation, sizeof(operation),
            __builtin_preserve_access_index(&rq->cmd_flags)))
        return 0;
    operation &= REQ_OP_MASK;
    __u32 direction;
    if (operation == REQ_OP_READ)
        direction = 0;
    else if (operation == REQ_OP_WRITE)
        direction = 1;
    else
        return 0;

    struct request_queue *queue;
    if (bpf_probe_read_kernel(
            &queue, sizeof(queue),
            __builtin_preserve_access_index(&rq->q)))
        return 0;
    if (!queue)
        return 0;
    struct gendisk *disk;
    if (bpf_probe_read_kernel(
            &disk, sizeof(disk),
            __builtin_preserve_access_index(&queue->disk)))
        return 0;
    if (!disk)
        return 0;

    int major;
    int first_minor;
    if (bpf_probe_read_kernel(
            &major, sizeof(major),
            __builtin_preserve_access_index(&disk->major)) ||
        bpf_probe_read_kernel(
            &first_minor, sizeof(first_minor),
            __builtin_preserve_access_index(&disk->first_minor)))
        return 0;

    struct start_value start = {
        .started_ns = bpf_ktime_get_ns(),
        .major = (__u32)major,
        .minor = (__u32)first_minor,
        .direction = direction,
    };
    __u64 request_key = (__u64)rq;
    bpf_map_update_elem(&STARTS, &request_key, &start, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/block_rq_complete")
int diskwatch_block_complete(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq = (struct request *)ctx->args[0];
    __u64 request_key = (__u64)rq;
    struct start_value *start = bpf_map_lookup_elem(&STARTS, &request_key);
    if (!start)
        return 0;

    // Linux 5.11+ block_rq_complete passes the number of bytes completed as
    // raw argument 2. blk_update_request emits the tracepoint before reducing
    // rq->__data_len, so a smaller completion is partial and the same request
    // must remain in STARTS until its final completion.
    __u32 remaining;
    if (bpf_probe_read_kernel(
            &remaining, sizeof(remaining),
            __builtin_preserve_access_index(&rq->__data_len)))
        return 0;
    __u32 completed = (__u32)ctx->args[2];
    if (completed < remaining)
        return 0;

    struct histogram_key key = {
        .major = start->major,
        .minor = start->minor,
        .direction = start->direction,
        .bucket = latency_bucket((bpf_ktime_get_ns() - start->started_ns) / 1000),
    };
    __u64 one = 1;
    __u64 zero = 0;
    __u64 *count = bpf_map_lookup_elem(&HISTOGRAMS, &key);
    if (!count) {
        // BPF_NOEXIST ensures concurrent first observations cannot replace a
        // value another CPU just created. Look up again after either success
        // or EEXIST, then increment this CPU's private counter.
        bpf_map_update_elem(&HISTOGRAMS, &key, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&HISTOGRAMS, &key);
    }
    if (count)
        *count += one;
    bpf_map_delete_elem(&STARTS, &request_key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
