#ifndef ARCA_SKILL_MANAGER_H
#define ARCA_SKILL_MANAGER_H

#include <vector>
#include <string>
#include <memory>
#include <cstdio>
#include <ctime>

#include "skill.h"
#include "shared_store.h"

namespace arca {

class SkillManager {
public:
    SkillManager() : store_(new SharedStore()) {}

    SharedStore *store() { return store_.get(); }
    void register_skill(std::shared_ptr<Skill> skill) {
        skills_.push_back(skill);
        printf("[Manager] Registered: %s\n", skill->name().c_str());
    }

    int init_all() {
        for (auto &s : skills_) {
            printf("[Manager] Init: %s\n", s->name().c_str());
            if (s->init() != 0) {
                fprintf(stderr, "[Manager] FAILED init: %s\n", s->name().c_str());
                return -1;
            }
            s->set_status("initialized");
        }
        return 0;
    }

    int start_all() {
        for (auto &s : skills_) {
            printf("[Manager] Start: %s\n", s->name().c_str());
            if (s->start() != 0) {
                fprintf(stderr, "[Manager] FAILED start: %s\n", s->name().c_str());
                return -1;
            }
            s->set_status("running");
        }
        return 0;
    }

    int stop_all() {
        for (auto &s : skills_) {
            s->stop();
            s->set_status("stopped");
        }
        return 0;
    }

    void tick() {
        for (auto &s : skills_) {
            if (!s->is_running()) continue;
            s->collect();
            s->policy();
            s->act();
        }
    }

    void print_status() {
        printf("[Manager] Skills: %zu\n", skills_.size());
        for (auto &s : skills_) {
            printf("  %-24s type=%d status=%s\n",
                   s->name().c_str(), (int)s->type(), s->status().c_str());
            for (auto &m : s->metrics())
                printf("    %-16s %8.1f %s\n", m.name.c_str(), m.value, m.unit.c_str());
        }
        fflush(stdout);
    }

    size_t count() const { return skills_.size(); }

    const std::vector<std::shared_ptr<Skill>> &get_skills() const { return skills_; }

private:
    std::vector<std::shared_ptr<Skill>> skills_;
    std::shared_ptr<SharedStore> store_;
};

} // namespace arca

#endif
