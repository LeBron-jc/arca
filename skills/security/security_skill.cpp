#include <cstdio>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include "security_skill.h"
#include "security_skill.skel.h"

namespace arca {

struct exec_event_raw { unsigned int pid; unsigned long long timestamp; char comm[16]; char filename[64]; };

int SecurityPolicySkill::handle_event_cb(void *ctx, void *data, size_t sz)
{
    auto *s = static_cast<SecurityPolicySkill *>(ctx);
    auto *e = static_cast<exec_event_raw *>(data);
    if (sz < sizeof(exec_event_raw)) return 0;

    s->exec_count_++;
    uint32_t pid = e->pid;
    auto &info = s->execs_[pid];
    info.last_seen = e->timestamp;
    info.filename = std::string(e->filename);
    info.comm = std::string(e->comm);
    info.count++;
    return 0;
}

int SecurityPolicySkill::init()
{
    struct security_skill *skel = security_skill__open();
    if (!skel) { set_status("disabled"); return 0; }
    if (security_skill__load(skel)) { security_skill__destroy(skel); set_status("load failed"); return 0; }
    if (security_skill__attach(skel)) { security_skill__destroy(skel); set_status("attach failed"); return 0; }

    ring_fd_ = bpf_map__fd(skel->maps.sec_events);
    alert_fd_ = bpf_map__fd(skel->maps.alert_counter);
    obj_ = (struct bpf_object *)skel;
    return 0;
}

int SecurityPolicySkill::start() { running_ = true; return 0; }

int SecurityPolicySkill::stop() {
    running_ = false;
    if (obj_) { security_skill__destroy((struct security_skill *)obj_); obj_ = nullptr; }
    return 0;
}

int SecurityPolicySkill::collect() {
    if (!obj_ || ring_fd_ < 0) return 0;
    struct ring_buffer *rb = ring_buffer__new(ring_fd_, handle_event_cb, this, NULL);
    if (!rb) return 0;
    ring_buffer__poll(rb, 0);
    ring_buffer__free(rb);
    return 0;
}

int SecurityPolicySkill::policy()
{
    if (!store_) return 0;

    /* write data to SharedStore for LLM */
    store_->put_int("sec.exec_count", (int)exec_count_);
    store_->put_int("sec.processes", (int)execs_.size());
    store_->put_int("sec.alerts", (int)alert_count_);

    std::ostringstream top;
    int n = 0;
    for (auto &kv : execs_) {
        if (++n > 5) break;
        top << "pid=" << kv.first << " count=" << kv.second.count
            << " comm=" << kv.second.comm << " file=" << kv.second.filename << "\n";
    }
    store_->put("sec.top_execs", top.str());
    return 0;
}

int SecurityPolicySkill::act()
{
    if (!store_) return 0;

    /* check for LLM alerts */
    for (auto &kv : execs_) {
        uint32_t pid = kv.first;
        std::string decision = store_->get("llm.alert." + std::to_string(pid));
        if (!decision.empty() && !kv.second.alerted) {
            kv.second.alerted = true;
            alert_count_++;
            printf("[SEC] LLM ALERT pid=%u %s\n", pid, decision.c_str());
        }
    }
    return 0;
}

std::vector<SkillMetrics> SecurityPolicySkill::metrics() {
    return {{"execs", (double)exec_count_, "cnt", "Exec calls"},
            {"processes", (double)execs_.size(), "cnt", "Unique PIDs"},
            {"alerts", (double)alert_count_, "cnt", "Alerts"}};
}

} // namespace arca
