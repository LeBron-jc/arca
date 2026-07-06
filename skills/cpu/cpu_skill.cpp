#include <cstdio>
#include <cstring>
#include <cmath>
#include <sstream>
#include <unistd.h>
#include "cpu_skill.h"

namespace arca {

int CPUSchedSkill::init()
{
    std::string bpfo = cfg_.get_str("cpu.bpf_object", "skills/cpu/arca_trace.bpf.o");
    trace_obj_ = bpf_object__open(bpfo.c_str());
    if (!trace_obj_) { set_status("open trace BPF failed"); return -1; }
    if (bpf_object__load(trace_obj_)) { set_status("load trace BPF failed"); return -1; }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, trace_obj_)
        if (bpf_program__attach(prog) == NULL)
            fprintf(stderr, "[CPU] Warning: attach failed for %s\n", bpf_program__name(prog));

    struct bpf_map *cm = bpf_object__find_map_by_name(trace_obj_, "task_class_map");
    if (!cm) { set_status("class_map not found"); return -1; }
    class_map_fd_ = bpf_map__fd(cm);

    struct bpf_map *sm = bpf_object__find_map_by_name(trace_obj_, "task_stats");
    if (!sm) { set_status("stats_map not found"); return -1; }
    stats_map_fd_ = bpf_map__fd(sm);

    return 0;
}

int CPUSchedSkill::start()
{
    running_ = true;
    scx_state_ = arca_scx_open_load_attach("/sys/fs/bpf/task_class_map");
    if (!scx_state_) { set_status("SCX attach failed"); return -1; }
    return 0;
}

int CPUSchedSkill::stop()
{
    running_ = false;
    if (scx_state_) { arca_scx_destroy(scx_state_); scx_state_ = nullptr; }
    if (trace_obj_) { bpf_object__close(trace_obj_); trace_obj_ = nullptr; }
    return 0;
}

int CPUSchedSkill::collect()
{
    return 0; /* BPF writes directly to task_stats map, no ringbuffer needed */
}

void CPUSchedSkill::compute_features()
{
    time_t now = time(NULL);
    double dt = difftime(now, last_snapshot_ts_);
    if (dt < 0.5) return;

    struct arca_stats_key prev_key = {}, key = {};

    while (bpf_map_get_next_key(stats_map_fd_, &prev_key, &key) == 0) {
        struct arca_stats_val val;
        if (bpf_map_lookup_elem(stats_map_fd_, &key, &val) != 0) { prev_key = key; continue; }

        uint32_t pid = key.pid;
        auto &feat = features_[pid];
        auto &snap = snapshots_[pid];

        uint64_t delta_run = val.total_run_ns - snap.prev_run_ns;
        uint64_t delta_wait = val.total_wait_ns - snap.prev_wait_ns;
        uint32_t delta_wake = val.wakeup_count - snap.prev_wakeup;
        uint32_t delta_switch = val.switch_count - snap.prev_switch;
        uint32_t delta_migrate = val.cpu_migrations - snap.prev_migration;
        uint32_t delta_io_wait = val.io_wait_count - snap.prev_io_wait;
        uint32_t delta_d_state = val.d_state_count - snap.prev_d_state;
        uint64_t delta_blocked = val.blocked_ns - snap.prev_blocked_ns;
        uint64_t delta_queue   = val.wait_ns - snap.prev_queue_ns;

        feat.avg_run_ns     = (feat.avg_run_ns * 7 + delta_run / (delta_switch ? delta_switch : 1)) / 8;
        feat.avg_wait_ns    = (feat.avg_wait_ns * 7 + delta_wait / (delta_wake ? delta_wake : 1)) / 8;
        feat.avg_blocked_ns = (feat.avg_blocked_ns * 7 + delta_blocked / (delta_d_state + delta_io_wait ? delta_d_state + delta_io_wait : 1)) / 8;
        feat.avg_queue_ns   = (feat.avg_queue_ns * 7 + delta_queue / (delta_switch ? delta_switch : 1)) / 8;
        feat.wakeup_rate    = delta_wake;
        feat.switch_rate    = delta_switch;
        feat.migration_rate = delta_migrate;
        feat.io_wait_count  = delta_io_wait;
        feat.d_state_count  = delta_d_state;
        feat.is_kthread     = val.is_kthread;
        feat.nice           = val.nice;
        feat.parent_pid     = val.parent_pid;
        memcpy(feat.comm, val.comm, 16);

        snap.prev_run_ns     = val.total_run_ns;
        snap.prev_wait_ns    = val.total_wait_ns;
        snap.prev_wakeup     = val.wakeup_count;
        snap.prev_switch     = val.switch_count;
        snap.prev_migration  = val.cpu_migrations;
        snap.prev_io_wait    = val.io_wait_count;
        snap.prev_d_state    = val.d_state_count;
        snap.prev_blocked_ns = val.blocked_ns;
        snap.prev_queue_ns   = val.wait_ns;

        prev_key = key;
    }

    event_count_ = snapshots_.size();
    last_snapshot_ts_ = now;
}

int CPUSchedSkill::policy()
{
    compute_features();

    /* write collected features to SharedStore for LLM consumption */
    if (store_) {
        store_->put_int("cpu.tasks", (int)snapshots_.size());

        std::ostringstream top;
        int n = 0;
        for (auto &kv : snapshots_) {
            if (++n > 10) break;
            auto fit = features_.find(kv.first);
            top << "pid=" << kv.first;
            if (fit != features_.end()) {
                top << " avg_run_ms=" << (fit->second.avg_run_ns / 1000000.0)
                    << " avg_blocked_ms=" << (fit->second.avg_blocked_ns / 1000000.0)
                    << " avg_queue_ms=" << (fit->second.avg_queue_ns / 1000000.0)
                    << " wakeup_rate=" << fit->second.wakeup_rate
                    << " io_wait=" << fit->second.io_wait_count
                    << " d_state=" << fit->second.d_state_count
                    << " nice=" << fit->second.nice
                    << " parent=" << fit->second.parent_pid
                    << " comm=" << fit->second.comm;
            }
            top << "\n";
        }
        store_->put("cpu.top_tasks", top.str());
    }

    /* prune stale entries */
    for (auto it = features_.begin(); it != features_.end(); ) {
        struct arca_stats_key k = { .pid = it->first };
        if (bpf_map_lookup_elem(stats_map_fd_, &k, NULL) != 0)
            it = features_.erase(it);
        else ++it;
    }

    return 0;
}

int CPUSchedSkill::act() { return 0; }

std::vector<SkillMetrics> CPUSchedSkill::metrics()
{
    return {
        {"tasks", (double)snapshots_.size(), "cnt", "Tracked tasks"},
    };
}

} // namespace arca
