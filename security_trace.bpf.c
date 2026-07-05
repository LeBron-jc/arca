#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct exec_event {
    u32 pid;
    u64 timestamp;
    char comm[16];
    char filename[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} sec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} alert_counter SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int kprobe_exec(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct exec_event *e;

    e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    char *filename = (char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);

    /* alert on tmp/dev_shm execution */
    if (e->filename[0] == '/' && e->filename[1] == 't' &&
        e->filename[2] == 'm' && e->filename[3] == 'p') {
        u32 zero = 0;
        u64 *cnt = bpf_map_lookup_elem(&alert_counter, &zero);
        if (cnt) __sync_fetch_and_add(cnt, 1);
    }

    return 0;
}
