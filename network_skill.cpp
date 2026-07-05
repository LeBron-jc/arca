#include <cstdio>
#include <cstring>
#include <unistd.h>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#include "network_skill.h"
#include "network_skill.skel.h"

namespace arca {

int NetworkPolicySkill::init()
{
    struct network_skill *skel = network_skill__open();
    if (!skel) { fprintf(stderr, "NET: open failed\n"); return -1; }
    if (network_skill__load(skel)) { fprintf(stderr, "NET: load failed\n"); return -1; }
    network_skill__attach(skel);

    ring_fd_ = bpf_map__fd(skel->maps.net_events);
    map_fd_  = bpf_map__fd(skel->maps.block_list);
    obj_ = (struct bpf_object *)skel;
    return 0;
}

int NetworkPolicySkill::start()
{
    running_ = true;
    return 0;
}

int NetworkPolicySkill::stop()
{
    running_ = false;
    if (obj_) { network_skill__destroy((struct network_skill *)obj_); obj_ = nullptr; }
    return 0;
}

int NetworkPolicySkill::collect()
{
    return 0;
}

int NetworkPolicySkill::policy()
{
    return 0;
}

int NetworkPolicySkill::act()
{
    return 0;
}

std::vector<SkillMetrics> NetworkPolicySkill::metrics()
{
    return {
        {"bytes_tx",   (double)total_bytes_, "B",   "Bytes transmitted"},
        {"packets",    (double)total_packets_, "cnt", "Packets"},
        {"flows",      (double)flows_.size(), "cnt",  "Active flows"},
        {"blocked",    (double)blocked_flows_, "cnt", "Blocked flows"},
    };
}

} // namespace arca
