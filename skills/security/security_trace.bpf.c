#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct exec_event { u32 pid; u32 old_pid; u64 timestamp; char comm[16]; char filename[64]; };

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} sec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32); __type(value, u64);
} alert_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32); __type(value, u64);
} exit_counter SEC(".maps");

struct sched_exec_args {
    unsigned short common_type; unsigned char common_flags, common_preempt_count;
    int common_pid; char filename[16]; int pid, old_pid;
};

struct sched_exit_args {
    unsigned short common_type; unsigned char common_flags, common_preempt_count;
    int common_pid; char comm[16]; pid_t pid; int prio;
};

struct mount_args {
    unsigned short common_type; unsigned char common_flags, common_preempt_count;
    int common_pid; unsigned long long __syscall_nr;
    char *source, *target, *filesystemtype; unsigned long mountflags; void *data;
};

SEC("tp/sched/sched_process_exec")
int trace_exec(struct sched_exec_args *ctx)
{
    u32 zero = 0; u64 *cnt = bpf_map_lookup_elem(&alert_counter, &zero);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    u32 pid = ctx->pid; if (!pid) return 0;

    /* ---- REAL CONTROL: prevent /tmp/ and /dev/shm/ execution ---- */
    char fname[16]; __builtin_memset(fname, 0, sizeof(fname));
    bpf_probe_read_kernel_str(fname, sizeof(fname), ctx->filename);
    if ((fname[0]=='/' && fname[1]=='t' && fname[2]=='m' && fname[3]=='p' && fname[4]=='/') ||
        (fname[0]=='/' && fname[1]=='d' && fname[2]=='e' && fname[3]=='v')) {
        bpf_send_signal(9); /* SIGKILL */
        return 0;
    }

    struct exec_event *e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid=pid; e->old_pid=ctx->old_pid; e->timestamp=bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->filename,0,sizeof(e->filename));
    bpf_probe_read_kernel_str(e->filename,16,ctx->filename);
    bpf_ringbuf_submit(e,0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_exit(struct sched_exit_args *ctx)
{
    u32 zero = 0; u64 *cnt = bpf_map_lookup_elem(&exit_counter, &zero);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    u32 pid = ctx->pid; if (!pid) return 0;

    struct exec_event *e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid=pid; e->old_pid=-1; e->timestamp=bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e,0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mount")
int trace_mount(struct mount_args *ctx)
{
    u32 zero = 0; u64 *cnt = bpf_map_lookup_elem(&alert_counter, &zero);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct exec_event *e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid=pid; e->old_pid=-2; e->timestamp=bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->target);
    bpf_ringbuf_submit(e,0);
    return 0;
}
