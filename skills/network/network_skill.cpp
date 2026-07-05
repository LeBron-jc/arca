#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#include "network_skill.h"
#include "network_skill.skel.h"

namespace arca {

struct net_event_raw {
    unsigned int pid;
    unsigned long long bytes;
    unsigned long long timestamp;
    char comm[16];
    unsigned char is_tx;
};

int NetworkPolicySkill::handle_event_cb(void *ctx, void *data, size_t sz)
{
    auto *s = static_cast<NetworkPolicySkill *>(ctx);
    auto *e = static_cast<net_event_raw *>(data);
    if (sz < sizeof(net_event_raw)) return 0;

    uint32_t pid = e->pid;
    auto &f = s->flows_[pid];
    f.last_seen = e->timestamp;
    f.total_events++;

    if (e->is_tx) {
        f.tx_bytes += e->bytes;
        s->total_tx_ += e->bytes;
    } else {
        f.rx_bytes += e->bytes;
        s->total_rx_ += e->bytes;
    }
    memcpy(f.comm, e->comm, 16);
    return 0;
}

int NetworkPolicySkill::init()
{
    struct network_skill *skel = network_skill__open();
    if (!skel) { set_status("disabled"); return 0; }
    if (network_skill__load(skel)) { set_status("load failed"); network_skill__destroy(skel); return 0; }
    if (network_skill__attach(skel)) { set_status("attach failed"); network_skill__destroy(skel); return 0; }

    rb_ = ring_buffer__new(bpf_map__fd(skel->maps.net_events), handle_event_cb, this, NULL);
    block_fd_ = bpf_map__fd(skel->maps.block_list);
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
    if (rb_) { ring_buffer__free(rb_); rb_ = nullptr; }
    if (obj_) { network_skill__destroy((struct network_skill *)obj_); obj_ = nullptr; }
    return 0;
}

int NetworkPolicySkill::collect()
{
    if (rb_) ring_buffer__poll(rb_, 0);
    return 0;
}

void NetworkPolicySkill::block_pid(uint32_t pid)
{
    u8 val = 1;
    bpf_map_update_elem(block_fd_, &pid, &val, BPF_ANY);
    flows_[pid].blocked = true;
    total_blocked_++;
}

int NetworkPolicySkill::policy()
{
    uint64_t now = time(NULL);

    for (auto &kv : flows_) {
        auto &f = kv.second;
        if (f.blocked) continue;

        /* auto-block PID if it exceeds 1MB/s tx */
        uint64_t dt = now * 1000000000ULL - f.last_seen;
        if (dt < 10000000000ULL) dt = 10000000000ULL;
        uint64_t rate = f.tx_bytes * 1000000000ULL / dt;

        if (rate > 1000000 && f.total_events > 100) {
            block_pid(kv.first);
            printf("[NET] BLOCKED pid=%u comm=%.16s tx=%luB rate=%luB/s\n",
                   kv.first, f.comm, f.tx_bytes, rate);
        }
    }

    /* reset counters every cycle */
    for (auto &kv : flows_) {
        kv.second.tx_bytes /= 2;
        kv.second.rx_bytes /= 2;
        kv.second.total_events /= 2;
    }

    return 0;
}

int NetworkPolicySkill::act()
{
    return 0;
}

std::vector<SkillMetrics> NetworkPolicySkill::metrics()
{
    return {
        {"tx_bytes",   (double)total_tx_, "B",   "TX bytes"},
        {"rx_bytes",   (double)total_rx_, "B",   "RX bytes"},
        {"flows",      (double)flows_.size(), "cnt",  "Active flows"},
        {"blocked",    (double)total_blocked_, "cnt", "Blocked PIDs"},
    };
}

} // namespace arca
