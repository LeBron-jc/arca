#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct net_event {
    u32 pid;
    u64 bytes;
    u64 timestamp;
    char comm[16];
    u8 is_tx;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} net_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} block_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1);
} blocked_counter SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *blocked = bpf_map_lookup_elem(&block_list, &pid);
    if (blocked && *blocked) {
        u32 zero = 0;
        u64 *cnt = bpf_map_lookup_elem(&blocked_counter, &zero);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        /* DO NOT return -1 from kprobe — causes kernel instability.
         * Blocking is handled in userspace via SIGTERM. */
    }

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;

    size_t size = (size_t)PT_REGS_PARM3(ctx);
    e->pid       = pid;
    e->bytes     = size;
    e->timestamp = bpf_ktime_get_ns();
    e->is_tx     = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int trace_tcp_recv(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;

    int copied = (int)PT_REGS_PARM2(ctx);
    e->pid       = pid;
    e->bytes     = copied > 0 ? (u64)copied : 0;
    e->timestamp = bpf_ktime_get_ns();
    e->is_tx     = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
