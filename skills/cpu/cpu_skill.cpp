#include <cstdio>
#include <cstring>
#include <cmath>
#include <sstream>
#include <unistd.h>
#include "cpu_skill.h"

namespace arca {

int CPUSchedSkill::handle_event_cb(void *ctx, void *data, size_t sz)
{
    auto *skill = static_cast<CPUSchedSkill *>(ctx);
    auto *e = static_cast<arca_task_event *>(data);
    if (sz < sizeof(arca_task_event)) return 0;

    skill->event_count_++;

    uint32_t tid = e->pid;
    if (tid == 0) return 0;

    auto &feat = skill->features_[tid];
    feat.avg_run_ns = (feat.avg_run_ns * 3 + e->run_time_ns) / 4;

    return 0;
}

int CPUSchedSkill::init()
{
    std::string bpfo = cfg_.get_str("cpu.bpf_object", "skills/cpu/arca_trace.bpf.o");
    trace_obj_ = bpf_object__open(bpfo.c_str());
    if (!trace_obj_) { fprintf(stderr, "CPU: open trace BPF failed\n"); return -1; }
    if (bpf_object__load(trace_obj_)) { fprintf(stderr, "CPU: load trace BPF failed\n"); return -1; }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, trace_obj_)
        bpf_program__attach(prog);

    struct bpf_map *events_map = bpf_object__find_map_by_name(trace_obj_, "events");
    if (!events_map) return -1;
    rb_ = ring_buffer__new(bpf_map__fd(events_map), handle_event_cb, this, NULL);
    if (!rb_) return -1;

    struct bpf_map *cm = bpf_object__find_map_by_name(trace_obj_, "task_class_map");
    if (!cm) return -1;
    class_map_fd_ = bpf_map__fd(cm);

    struct bpf_map *sm = bpf_object__find_map_by_name(trace_obj_, "task_stats");
    if (!sm) return -1;
    stats_map_fd_ = bpf_map__fd(sm);

    return 0;
}

int CPUSchedSkill::start()
{
    running_ = true;
    scx_state_ = arca_scx_open_load_attach("/sys/fs/bpf/task_class_map");
    if (!scx_state_) { fprintf(stderr, "CPU: SCX attach failed\n"); return -1; }
    return 0;
}

int CPUSchedSkill::stop()
{
    running_ = false;
    if (scx_state_) { arca_scx_destroy(scx_state_); scx_state_ = nullptr; }
    if (rb_) { ring_buffer__free(rb_); rb_ = nullptr; }
    if (trace_obj_) { bpf_object__close(trace_obj_); trace_obj_ = nullptr; }
    return 0;
}

int CPUSchedSkill::collect()
{
    ring_buffer__poll(rb_, 0);
    return 0;
}

void CPUSchedSkill::compute_features()
{
    time_t now = time(NULL);
    double dt = difftime(now, last_snapshot_ts_);
    if (dt < 0.5) return;

    /* iterate over BPF stats map and pull latest values */
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

        feat.avg_run_ns  = (feat.avg_run_ns * 7 + delta_run / (delta_switch ? delta_switch : 1)) / 8;
        feat.avg_wait_ns = (feat.avg_wait_ns * 7 + delta_wait / (delta_wake ? delta_wake : 1)) / 8;
        feat.wakeup_rate = delta_wake;
        feat.switch_rate = delta_switch;
        feat.migration_rate = delta_migrate;
        feat.io_wait_count = delta_io_wait;
        feat.d_state_count = delta_d_state;
        feat.is_kthread  = val.is_kthread;
        feat.nice = val.nice;
        memcpy(feat.comm, val.comm, 16);

        snap.prev_run_ns    = val.total_run_ns;
        snap.prev_wait_ns   = val.total_wait_ns;
        snap.prev_wakeup    = val.wakeup_count;
        snap.prev_switch    = val.switch_count;
        snap.prev_migration = val.cpu_migrations;
        snap.prev_io_wait   = val.io_wait_count;
        snap.prev_d_state   = val.d_state_count;

        prev_key = key;
    }

    last_snapshot_ts_ = now;
}

classify_score CPUSchedSkill::score_task(const task_features &feat)
{
    classify_score s = {};

    if (feat.wakeup_rate == 0 && feat.switch_rate == 0)
        return s;

    double wake_rate = (double)feat.wakeup_rate;
    double switch_rate = (double)feat.switch_rate;
    double avg_run_ms = feat.avg_run_ns / 1000000.0;
    double avg_wait_ms = feat.avg_wait_ns / 1000000.0;
    double io_ratio = (feat.io_wait_count + feat.d_state_count) /
                      (double)(feat.switch_rate ? feat.switch_rate : 1);

    double min_score = cfg_.get_double("cpu.interactive_min_score", 0.4);

    /* IO_BOUND first: high I/O wait ratio means task spends time waiting for I/O, not CPU */
    if (io_ratio > 0.5 && avg_run_ms < 5.0)
        s.io_bound = min_score * 1.2;
    if (io_ratio > 0.3 && feat.d_state_count > 0)
        s.io_bound += min_score * 0.6;
    if (io_ratio > 0.7)
        s.io_bound += min_score * 0.6;

    /* INTERACTIVE: high wakeup rate, short run times, low wait times */
    if (wake_rate >= 3 && avg_run_ms < 5.0 && avg_wait_ms < 20.0)
        s.interactive = min_score * 1.0;
    if (wake_rate >= 5 && avg_run_ms < 2.0 && avg_wait_ms < 10.0)
        s.interactive += min_score * 0.75;
    if (wake_rate >= 10 && avg_run_ms < 1.0)
        s.interactive += min_score * 0.75;
    /* boost high-priority (negative nice) interactive tasks */
    if (s.interactive > 0 && feat.nice < -5)
        s.interactive += 0.2;

    min_score = cfg_.get_double("cpu.cpu_bound_min_score", 0.4);
    /* CPU_BOUND: low wakeup rate, long run times, few migrations, NOT I/O bound */
    if (wake_rate <= 2 && avg_run_ms > 10.0 && io_ratio < 0.3)
        s.cpu_bound = min_score * 1.0;
    if (wake_rate <= 1 && avg_run_ms > 50.0 && feat.migration_rate <= 2)
        s.cpu_bound += min_score * 0.75;
    if (switch_rate >= 10 && wake_rate <= 1 && io_ratio < 0.2)
        s.cpu_bound += min_score * 0.75;

    min_score = cfg_.get_double("cpu.batch_min_score", 0.4);
    /* BATCH: moderate wakeup, long runs, regular pattern */
    if (avg_run_ms > 5.0 && wake_rate <= 3 && io_ratio < 0.4)
        s.batch = min_score * 0.75;
    if (avg_run_ms > 20.0 && wake_rate <= 5)
        s.batch += min_score * 0.75;
    if (switch_rate >= 15 && wake_rate <= 3)
        s.batch += min_score * 0.5;
    if (feat.migration_rate <= 3 && avg_run_ms > 50.0)
        s.batch += min_score * 0.5;

    return s;
}

void CPUSchedSkill::apply_classification()
{
    for (auto &kv : snapshots_) {
        uint32_t pid = kv.first;
        auto &snap = kv.second;

        auto fit = features_.find(pid);
        if (fit == features_.end()) continue;

        classify_score sc = score_task(fit->second);

        enum arca_task_class new_cls = ARCA_CLASS_UNKNOWN;
        double best = 0.0;

        if (sc.interactive > best) { best = sc.interactive; new_cls = ARCA_CLASS_INTERACTIVE; }
        if (sc.cpu_bound > best) { best = sc.cpu_bound; new_cls = ARCA_CLASS_CPU_BOUND; }
        if (sc.batch > best) { best = sc.batch; new_cls = ARCA_CLASS_BATCH; }
        if (sc.io_bound > best) { best = sc.io_bound; new_cls = ARCA_CLASS_IO_BOUND; }

        if (new_cls != ARCA_CLASS_UNKNOWN && new_cls != snap.cls && best >= 0.4) {
            snap.cls = new_cls;
            snap.confidence = best;
            bpf_map_update_elem(class_map_fd_, &pid, &new_cls, BPF_ANY);
        }
    }

    memset(classified_, 0, sizeof(classified_));
    for (auto &kv : snapshots_)
        classified_[kv.second.cls]++;

    /* write to shared store for other skills (LLM) */
    if (store_) {
        store_->put_int("cpu.events", event_count_);
        store_->put_int("cpu.tasks", (int)snapshots_.size());
        store_->put_int("cpu.interactive", classified_[1]);
        store_->put_int("cpu.cpu_bound", classified_[2]);
        store_->put_int("cpu.batch", classified_[3]);
        store_->put_int("cpu.io_bound", classified_[4]);

        /* top 10 active tasks */
        std::ostringstream top;
        int n = 0;
        for (auto &kv : snapshots_) {
            if (++n > 10) break;
            auto fit = features_.find(kv.first);
            top << "pid=" << kv.first
                << " class=" << (int)kv.second.cls
                << " confidence=" << kv.second.confidence;
            if (fit != features_.end()) {
                top << " avg_run_ms=" << (fit->second.avg_run_ns / 1000000.0)
                    << " wakeup_rate=" << fit->second.wakeup_rate
                    << " io_ratio=" << ((fit->second.io_wait_count + fit->second.d_state_count) /
                                       (double)(fit->second.switch_rate ? fit->second.switch_rate : 1))
                    << " nice=" << fit->second.nice
                    << " migration=" << fit->second.migration_rate
                    << " is_kthread=" << fit->second.is_kthread;
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
        else
            ++it;
    }
}

int CPUSchedSkill::policy()
{
    compute_features();
    apply_classification();
    return 0;
}

int CPUSchedSkill::act()
{
    return 0;
}

std::vector<SkillMetrics> CPUSchedSkill::metrics()
{
    return {
        {"events",       (double)event_count_, "cnt",  "Total events"},
        {"tasks",        (double)snapshots_.size(), "cnt", "Tracked tasks"},
        {"interactive",  (double)classified_[1], "cnt", "INTERACTIVE"},
        {"cpu_bound",    (double)classified_[2], "cnt", "CPU_BOUND"},
        {"batch",        (double)classified_[3], "cnt", "BATCH"},
        {"io_bound",     (double)classified_[4], "cnt", "IO_BOUND"},
    };
}

} // namespace arca
