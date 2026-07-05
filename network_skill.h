#ifndef ARCA_NET_SKILL_H
#define ARCA_NET_SKILL_H

#include <cstdint>
#include <unordered_map>
#include <string>
#include "skill.h"

namespace arca {

struct net_flow {
    uint32_t pid;
    uint64_t bytes;
    uint64_t packets;
    uint64_t last_seen;
    char comm[16];
};

class NetworkPolicySkill : public Skill {
public:
    NetworkPolicySkill() : Skill("NetworkPolicy", SkillType::NETWORK_POLICY),
        obj_(nullptr), ring_fd_(-1), map_fd_(-1) {}

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
    int map_fd_;

    uint64_t total_bytes_ = 0;
    uint64_t total_packets_ = 0;
    uint64_t blocked_flows_ = 0;
    std::unordered_map<uint32_t, net_flow> flows_;
};

} // namespace arca

#endif
