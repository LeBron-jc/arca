#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "arca.h"

char _license[] SEC("license") = "GPL";

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

static void ensure_stats(u32 pid, u64 tgid)
{
    struct arca_stats_key key = { .pid = pid, .tgid = tgid };
    if (!bpf_map_lookup_elem(&task_stats, &key)) {
        struct arca_stats_val new_val = {};
        bpf_map_update_elem(&task_stats, &key, &new_val, BPF_ANY);
    }
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;
    long prev_state = ctx->prev_state;
    u32 cpu = bpf_get_smp_processor_id();

    if (prev_pid) {
        struct arca_stats_key key = { .pid = prev_pid };
        struct arca_stats_val *val = bpf_map_lookup_elem(&task_stats, &key);

        if (val && val->last_run_start_ns) {
            u64 now = bpf_ktime_get_ns();
            u64 elapsed = now - val->last_run_start_ns;
            if (elapsed < 60000000000ULL) {
                val->total_run_ns += elapsed;
            }
            val->last_run_start_ns = 0;
        }

        if (val) {
            val->switch_count++;
            if (val->last_cpu != cpu && val->last_cpu != 0)
                val->cpu_migrations++;
            val->last_cpu = cpu;

            if (prev_state & TASK_UNINTERRUPTIBLE)
                val->d_state_count++;
            else if (prev_state & TASK_INTERRUPTIBLE)
                val->io_wait_count++;
            else if (prev_state == TASK_RUNNING)
                val->preempt_count++;
        }
    }

    if (next_pid) {
        ensure_stats(next_pid, 0);

        struct arca_stats_key key = { .pid = next_pid };
        struct arca_stats_val *val = bpf_map_lookup_elem(&task_stats, &key);
        u64 now = bpf_ktime_get_ns();

        if (val) {
            val->last_run_start_ns = now;
            if (val->comm[0] == 0)
                bpf_probe_read_kernel_str(val->comm, sizeof(val->comm), ctx->next_comm);
        }
    }

    return 0;
}

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct sched_wakeup_args *ctx)
{
    u32 pid = ctx->pid;
    if (!pid) return 0;

    ensure_stats(pid, 0);

    struct arca_stats_key key = { .pid = pid };
    struct arca_stats_val *val = bpf_map_lookup_elem(&task_stats, &key);
    u64 now = bpf_ktime_get_ns();

    if (val) {
        if (val->last_wake_ns && now > val->last_wake_ns) {
            u64 wait_ns = now - val->last_wake_ns;
            if (wait_ns < 60000000000ULL)
                val->total_wait_ns += wait_ns;
        }
        val->last_wake_ns = now;
        __sync_fetch_and_add(&val->wakeup_count, 1);
        if (val->comm[0] == 0)
            bpf_probe_read_kernel_str(val->comm, sizeof(val->comm), ctx->comm);
    }

    return 0;
}
