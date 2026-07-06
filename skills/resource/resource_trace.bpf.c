#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(max_entries, 4);
    __uint(value_size, sizeof(u64));
} res_counters SEC(".maps");
/*
 * res_counters idx:
 *   0 = page allocations
 *   1 = block I/O issues
 *   2 = page allocation failures
 *   3 = block I/O completions
 */

SEC("kprobe/__alloc_pages_nodemask")
int trace_page_alloc(struct pt_regs *ctx)
{
    u32 zero = 0;
    u64 *cnt = bpf_map_lookup_elem(&res_counters, &zero);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    return 0;
}

SEC("kprobe/block_rq_issue")
int trace_block_issue(struct pt_regs *ctx)
{
    u32 idx = 1;
    u64 *cnt = bpf_map_lookup_elem(&res_counters, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    return 0;
}
