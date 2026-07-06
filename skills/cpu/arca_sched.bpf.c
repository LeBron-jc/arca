#include <scx/common.bpf.h>
#include "arca.h"
#include "arca_sched.h"

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, int);
} task_class_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 4);
} stats SEC(".maps");

static void stat_inc(u32 idx) {
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p) (*cnt_p)++;
}

static u64 vtime_now;

#define DFL_SLICE (SCX_SLICE_DFL)  /* 5ms */

/*
 * select_cpu: high-priority tasks bypass the queue
 */
s32 BPF_STRUCT_OPS(arca_select_cpu, struct task_struct *p,
                   s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;
    u32 pid = p->pid;
    int *prio = bpf_map_lookup_elem(&task_class_map, &pid);

    if (prio && *prio >= PRIORITY_HIGH) {
        s32 idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
        cpu = (idle_cpu >= 0) ? idle_cpu :
              scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, DFL_SLICE / 5, 0);
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
        stat_inc(0);
        return cpu;
    }

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (is_idle)
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, DFL_SLICE, 0);
    return cpu;
}

/*
 * enqueue: adjust vtime by priority — higher = earlier in queue
 */
void BPF_STRUCT_OPS(arca_enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = p->pid;
    int *prio = bpf_map_lookup_elem(&task_class_map, &pid);
    int priority = prio ? *prio : 0;

    if (p->scx.dsq_vtime == 0)
        p->scx.dsq_vtime = vtime_now;

    u64 vtime = p->scx.dsq_vtime;
    u64 slice = DFL_SLICE;

    /* priority → vtime offset: +100 = 10x slice boost (runs 10x more often) */
    if (priority > 0) {
        vtime -= (u64)priority * slice / 10;
        slice = DFL_SLICE / 2;  /* high priority = shorter slice = better responsiveness */
        stat_inc(0);
    } else if (priority < PRIORITY_LOW) {
        vtime += (u64)(-priority) * slice / 10;
        slice = DFL_SLICE * 4;  /* low priority = longer slice = fewer context switches */
        stat_inc(1);
    } else {
        stat_inc(2);
    }

    if (time_before(vtime, vtime_now - slice * 100))
        vtime = vtime_now - slice * 100;

    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}

void BPF_STRUCT_OPS(arca_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(arca_running, struct task_struct *p)
{
    if (time_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(arca_stopping, struct task_struct *p, bool runnable)
{
    u64 used = DFL_SLICE - p->scx.slice;
    p->scx.dsq_vtime += used * 100 / p->scx.weight;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(arca_init)
{
    scx_bpf_create_dsq(SHARED_DSQ, -1);
    return 0;
}

void BPF_STRUCT_OPS(arca_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(arca_ops,
               .select_cpu = (void *)arca_select_cpu,
               .enqueue    = (void *)arca_enqueue,
               .dispatch   = (void *)arca_dispatch,
               .running    = (void *)arca_running,
               .stopping   = (void *)arca_stopping,
               .init       = (void *)arca_init,
               .exit       = (void *)arca_exit,
               .name       = "arca");
