#ifndef ARCA_SEC_SKILL_H
#define ARCA_SEC_SKILL_H

#include <cstdint>
#include <unordered_map>
#include <string>
#include <vector>
#include "skill.h"

namespace arca {

struct exec_info {
    uint64_t last_seen;
    std::string filename;
    std::string comm;
    uint32_t count;
    bool alerted;
};

class SecurityPolicySkill : public Skill {
public:
    SecurityPolicySkill() : Skill("SecurityPolicy", SkillType::CUSTOM),
        obj_(nullptr), ring_fd_(-1), alert_fd_(-1) {}

    int init() override;
    int start() override;
    int stop() override;
    int collect() override;
    int policy() override;
    int act() override;
    std::vector<SkillMetrics> metrics() override;

private:
    struct bpf_object *obj_;
    int ring_fd_;
    int alert_fd_;

    uint64_t exec_count_ = 0;
    uint64_t alert_count_ = 0;
    std::unordered_map<uint32_t, exec_info> execs_;

    static int handle_event_cb(void *ctx, void *data, size_t sz);
};

} // namespace arca
#endif
