#ifndef ARCA_LLM_SKILL_H
#define ARCA_LLM_SKILL_H

#include <string>
#include <vector>
#include <cstdio>
#include "skill.h"
#include "shared_store.h"
#include "config.h"
#include "arca.h"

namespace arca {

struct llm_command {
    std::string type;     /* PRIORITY, BLOCK, THROTTLE, ALERT */
    int pid;
    int value;            /* priority value, or throttle value */
    std::string reason;
};

class LLMDecisionSkill : public Skill {
public:
    LLMDecisionSkill(SharedStore *store, const Config &cfg)
        : Skill("LLMDecision", SkillType::CUSTOM),
          store_(store), cfg_(cfg), class_map_fd_(-1),
          call_count_(0), last_call_time_(0) {}

    int init() override;
    int start() override;
    int stop() override;
    int collect() override;
    int policy() override;
    int act() override;
    std::vector<SkillMetrics> metrics() override;

private:
    SharedStore *store_;
    Config cfg_;
    int class_map_fd_;
    int call_count_;
    time_t last_call_time_;

    std::string build_prompt();
    std::string call_api(const std::string &prompt);
    std::vector<llm_command> parse_response(const std::string &response);
    void apply_commands(const std::vector<llm_command> &cmds);
};

} // namespace arca
#endif
