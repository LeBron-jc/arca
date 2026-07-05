#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

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

struct net_flow_event {
    u32 pid;
    u32 len;
    u64 timestamp;
    char comm[16];
    u8 is_tx; /* 1 = transmit, 0 = receive */
};

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *blocked = bpf_map_lookup_elem(&block_list, &pid);
    if (blocked && *blocked)
        return 0;

    struct net_flow_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->len = 0;
    e->timestamp = bpf_ktime_get_ns();
    e->is_tx = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int trace_tcp_recv(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct net_flow_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->len = 0;
    e->timestamp = bpf_ktime_get_ns();
    e->is_tx = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
