#ifndef ARCA_RES_SKILL_H
#define ARCA_RES_SKILL_H

#include <cstdint>
#include <string>
#include <vector>
#include "skill.h"
#include "config.h"

namespace arca {

struct resource_stats {
    uint64_t mem_usage_mb;
    uint64_t cpu_usage_pct;
    uint64_t io_read_kb;
    uint64_t io_write_kb;
    uint64_t oom_count;
};

class ResourceControlSkill : public Skill {
public:
    ResourceControlSkill(const Config &cfg) : Skill("ResourceCtrl", SkillType::RESOURCE_CONTROL), cfg_(cfg) {}

    int init() override;
    int start() override;
    int stop() override;
    int collect() override;
    int policy() override;
    int act() override;

    std::vector<SkillMetrics> metrics() override;

private:
    resource_stats stats_ = {};
    std::string cgroup_path_;
    Config cfg_;
};

} // namespace arca

#endif
