#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "arca.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned int);
    __type(value, enum arca_task_class);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_class_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct arca_stats_key);
    __type(value, struct arca_stats_val);
} task_stats SEC(".maps");

struct sched_switch_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};

struct sched_wakeup_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char comm[16];
    pid_t pid;
    int prio;
    int target_cpu;
};

static void track_start(u32 pid, u64 tgid, u32 cpu, const char *comm)
{
    struct arca_stats_key key = { .pid = pid, .tgid = tgid };
    struct arca_stats_val *val;
    u64 now = bpf_ktime_get_ns();

    val = bpf_map_lookup_elem(&task_stats, &key);
    if (!val) {
        struct arca_stats_val new_val = {};
        new_val.last_run_start_ns = now;
        new_val.last_cpu = cpu;
        new_val.switch_count = 1;
        if (comm) bpf_probe_read_kernel_str(new_val.comm, sizeof(new_val.comm), comm);
        bpf_map_update_elem(&task_stats, &key, &new_val, BPF_ANY);
    } else {
        val->last_run_start_ns = now;
        if (val->last_cpu != cpu && val->last_cpu != 0)
            val->cpu_migrations++;
        val->last_cpu = cpu;
        val->switch_count++;
        /* update comm if changed */
        if (comm && val->comm[0] == 0)
            bpf_probe_read_kernel_str(val->comm, sizeof(val->comm), comm);
    }
}

static void track_wakeup(u32 pid, u64 tgid, const char *comm)
{
    struct arca_stats_key key = { .pid = pid, .tgid = tgid };
    struct arca_stats_val *val;
    u64 now = bpf_ktime_get_ns();

    val = bpf_map_lookup_elem(&task_stats, &key);
    if (!val) {
        struct arca_stats_val new_val = {};
        new_val.last_wake_ns = now;
        new_val.wakeup_count = 1;
        if (comm) bpf_probe_read_kernel_str(new_val.comm, sizeof(new_val.comm), comm);
        bpf_map_update_elem(&task_stats, &key, &new_val, BPF_ANY);
    } else {
        /* measure wait time since last wake */
        if (val->last_wake_ns && now > val->last_wake_ns) {
            u64 wait_ns = now - val->last_wake_ns;
            if (wait_ns < 60000000000ULL)
                val->total_wait_ns += wait_ns;
        }
        val->last_wake_ns = now;
        __sync_fetch_and_add(&val->wakeup_count, 1);
        if (comm && val->comm[0] == 0)
            bpf_probe_read_kernel_str(val->comm, sizeof(val->comm), comm);
    }
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;

    /* prev task stopped */
    if (prev_pid) {
        struct arca_stats_key key = { .pid = prev_pid };
        struct arca_stats_val *val = bpf_map_lookup_elem(&task_stats, &key);
        u64 run_ns = 0;
        if (val && val->last_run_start_ns) {
            u64 now = bpf_ktime_get_ns();
            run_ns = now - val->last_run_start_ns;
            if (run_ns < 60000000000ULL) {
                val->total_run_ns += run_ns;
                val->last_run_start_ns = 0;
            }
        }
        /* emit event with runtime info */
        struct arca_task_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            __builtin_memset(e, 0, sizeof(*e));
            e->event_type = ARCA_EVENT_SWITCH;
            e->timestamp  = bpf_ktime_get_ns();
            e->cpu        = cpu;
            e->prev_pid   = prev_pid;
            e->next_pid   = next_pid;
            e->pid        = next_pid;
            e->run_time_ns = run_ns;
            bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), ctx->next_comm);
            bpf_ringbuf_submit(e, 0);
        }
    }

    /* next task started */
    if (next_pid) {
        track_start(next_pid, 0, cpu, ctx->next_comm);
    }

    return 0;
}

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct sched_wakeup_args *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();

    if (!ctx->pid) return 0;

    track_wakeup(ctx->pid, 0, ctx->comm);

    /* emit event */
    struct arca_task_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->event_type = ARCA_EVENT_WAKEUP;
        e->timestamp  = bpf_ktime_get_ns();
        e->cpu        = cpu;
        e->wakee_pid  = ctx->pid;
        e->pid        = ctx->pid;
        bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), ctx->comm);
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
