#include <cstdio>
#include <cstring>
#include <unistd.h>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#include "security_skill.h"
#include "security_skill.skel.h"

namespace arca {

struct exec_event_raw {
    unsigned int pid;
    unsigned long long timestamp;
    char comm[16];
    char filename[64];
};

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

    /* detect suspicious paths */
    if (info.filename.find("/tmp/") == 0 || info.filename.find("/dev/shm/") == 0) {
        info.alerted = true;
        s->alert_count_++;
        printf("[SEC] ALERT pid=%u comm=%s file=%s\n", pid, info.comm.c_str(), info.filename.c_str());
    }

    /* detect shell interpreters with suspicious args */
    if (info.comm == "bash" || info.comm == "sh" || info.comm == "dash") {
        if (info.filename.find("curl") != std::string::npos ||
            info.filename.find("wget")  != std::string::npos) {
            info.alerted = true;
            s->alert_count_++;
            printf("[SEC] ALERT pid=%u shell downloading: %s\n", pid, info.filename.c_str());
        }
    }

    return 0;
}

int SecurityPolicySkill::init()
{
    struct security_skill *skel = security_skill__open();
    if (!skel) { set_status("disabled: open failed"); return 0; }
    if (security_skill__load(skel)) { set_status("disabled: load failed"); security_skill__destroy(skel); return 0; }
    if (security_skill__attach(skel)) { set_status("disabled: attach failed"); security_skill__destroy(skel); return 0; }

    ring_fd_ = bpf_map__fd(skel->maps.sec_events);
    alert_fd_ = bpf_map__fd(skel->maps.alert_counter);
    obj_ = (struct bpf_object *)skel;
    return 0;
}

int SecurityPolicySkill::start()
{
    running_ = true;
    return 0;
}

int SecurityPolicySkill::stop()
{
    running_ = false;
    if (obj_) { security_skill__destroy((struct security_skill *)obj_); obj_ = nullptr; }
    return 0;
}

int SecurityPolicySkill::collect()
{
    if (!obj_ || ring_fd_ < 0) return 0;
    struct ring_buffer *rb = ring_buffer__new(ring_fd_, handle_event_cb, this, NULL);
    if (!rb) return 0;
    ring_buffer__poll(rb, 0);
    ring_buffer__free(rb);
    return 0;
}

int SecurityPolicySkill::policy()
{
    /* read alert counter from BPF map */
    if (alert_fd_ >= 0) {
        u32 zero = 0;
        u64 cnt = 0;
        bpf_map_lookup_elem(alert_fd_, &zero, &cnt);
        alert_count_ = cnt;
    }
    return 0;
}

int SecurityPolicySkill::act()
{
    return 0;
}

std::vector<SkillMetrics> SecurityPolicySkill::metrics()
{
    return {
        {"execs",     (double)exec_count_, "cnt", "Total exec calls"},
        {"processes", (double)execs_.size(), "cnt", "Unique PIDs"},
        {"alerts",    (double)alert_count_, "cnt", "Security alerts"},
    };
}

} // namespace arca
