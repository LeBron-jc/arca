#ifndef ARCA_NET_SKILL_H
#define ARCA_NET_SKILL_H

#include <cstdint>
#include <unordered_map>
#include <string>
#include "skill.h"
#include "shared_store.h"

namespace arca {

struct net_flow_info {
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t last_seen;
    uint64_t total_events;
    bool blocked;
    char comm[16];
};

class NetworkPolicySkill : public Skill {
public:
    NetworkPolicySkill(SharedStore *store = nullptr) : Skill("NetworkPolicy", SkillType::NETWORK_POLICY),
        obj_(nullptr), rb_(nullptr), block_fd_(-1), store_(store) {}

    int init() override;
    int start() override;
    int stop() override;
    int collect() override;
    int policy() override;
    int act() override;

    std::vector<SkillMetrics> metrics() override;

private:
    struct bpf_object *obj_;
    struct ring_buffer *rb_;
    int block_fd_;
    SharedStore *store_;

    uint64_t total_tx_ = 0, total_rx_ = 0;
    uint64_t total_blocked_ = 0, total_retransmit_ = 0, total_connects_ = 0;
    std::unordered_map<uint32_t, net_flow_info> flows_;

    static int handle_event_cb(void *ctx, void *data, size_t sz);
};

} // namespace arca
#endif
