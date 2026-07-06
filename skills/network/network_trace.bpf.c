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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(max_entries, 4);
    __uint(value_size, sizeof(u64));
} net_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} killed_pids SEC(".maps");
/*
 * net_counters idx:
 *   0 = tcp_connect events
 *   1 = tcp_retransmits
 *   2 = total tcp_sendmsg calls
 *   3 = total tcp_recv calls
 */

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *blocked = bpf_map_lookup_elem(&block_list, &pid);
    if (blocked && *blocked) {
        u32 zero = 0;
        u64 *cnt = bpf_map_lookup_elem(&blocked_counter, &zero);
        if (cnt) __sync_fetch_and_add(cnt, 1);

        /* terminate the abusive process from kernel space — atomic, no race */
        u8 *already = bpf_map_lookup_elem(&killed_pids, &pid);
        if (!already) {
            u8 one = 1;
            bpf_map_update_elem(&killed_pids, &pid, &one, BPF_ANY);
            bpf_send_signal(9); /* SIGKILL */
        }
        return 0;
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

SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    u32 zero = 0;
    u64 *cnt = bpf_map_lookup_elem(&net_counters, &zero);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid; e->bytes = 0; e->timestamp = bpf_ktime_get_ns(); e->is_tx = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int trace_tcp_retransmit(struct pt_regs *ctx)
{
    u32 idx = 1;
    u64 *cnt = bpf_map_lookup_elem(&net_counters, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid; e->bytes = 0; e->timestamp = bpf_ktime_get_ns(); e->is_tx = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
