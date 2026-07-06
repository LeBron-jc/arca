#ifndef ARCA_CPU_SKILL_H
#define ARCA_CPU_SKILL_H

#include <unordered_map>
#include <cstdint>
#include <ctime>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
void *arca_scx_open_load_attach(const char *pin_path);
void  arca_scx_destroy(void *state);
}
#include "skill.h"
#include "config.h"
#include "shared_store.h"
#include "arca.h"

namespace arca {

struct task_features {
    uint64_t avg_run_ns;
    uint64_t avg_wait_ns;
    uint32_t wakeup_rate;
    uint32_t switch_rate;
    uint32_t migration_rate;
    uint32_t is_kthread;
    char comm[16];
};

struct task_snapshot {
    uint64_t prev_run_ns;
    uint64_t prev_wait_ns;
    uint32_t prev_wakeup;
    uint32_t prev_switch;
    uint32_t prev_migration;
    enum arca_task_class cls;
    double confidence;
};

struct classify_score {
    double interactive;
    double cpu_bound;
    double batch;
};

class CPUSchedSkill : public Skill {
public:
    CPUSchedSkill(const Config &cfg, SharedStore *store = nullptr)
        : Skill("CPUSched", SkillType::CPU_SCHED),
        trace_obj_(nullptr), rb_(nullptr), scx_state_(nullptr),
        class_map_fd_(-1), stats_map_fd_(-1),
        store_(store), event_count_(0), last_snapshot_ts_(0) {
        cfg_ = cfg;
    }

    int init() override;
    int start() override;
    int stop() override;
    int collect() override;
    int policy() override;
    int act() override;

    std::vector<SkillMetrics> metrics() override;

private:
    struct bpf_object *trace_obj_;
    struct ring_buffer *rb_;
    void *scx_state_;
    int class_map_fd_;
    int stats_map_fd_;
    Config cfg_;
    SharedStore *store_;

    uint64_t event_count_;
    time_t last_snapshot_ts_;

    std::unordered_map<uint32_t, task_features> features_;
    std::unordered_map<uint32_t, task_snapshot> snapshots_;
    int classified_[4] = {};

    static int handle_event_cb(void *ctx, void *data, size_t sz);

    void compute_features();
    classify_score score_task(const task_features &feat);
    void apply_classification();
};

} // namespace arca
#endif
