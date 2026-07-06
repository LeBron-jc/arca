#include <cstdio>
#include <cstring>
#include <csignal>
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
    if (e->is_tx == 1) { f.tx_bytes += e->bytes; s->total_tx_ += e->bytes; }
    else if (e->is_tx == 2) { s->total_retransmit_++; }
    else { f.rx_bytes += e->bytes; s->total_rx_ += e->bytes; }
    memcpy(f.comm, e->comm, 16);
    return 0;
}

int NetworkPolicySkill::init()
{
    struct network_skill *skel = network_skill__open();
    if (!skel) { set_status("disabled"); return 0; }
    if (network_skill__load(skel)) { network_skill__destroy(skel); set_status("load failed"); return 0; }
    if (network_skill__attach(skel)) { network_skill__destroy(skel); set_status("attach failed"); return 0; }

    rb_ = ring_buffer__new(bpf_map__fd(skel->maps.net_events), handle_event_cb, this, NULL);
    block_fd_ = bpf_map__fd(skel->maps.block_list);
    obj_ = (struct bpf_object *)skel;
    return 0;
}

int NetworkPolicySkill::start() { running_ = true; return 0; }

int NetworkPolicySkill::stop() {
    running_ = false;
    if (rb_) { ring_buffer__free(rb_); rb_ = nullptr; }
    if (obj_) { network_skill__destroy((struct network_skill *)obj_); obj_ = nullptr; }
    return 0;
}

int NetworkPolicySkill::collect() {
    if (rb_) ring_buffer__poll(rb_, 0);
    return 0;
}

int NetworkPolicySkill::policy()
{
    if (!store_) return 0;

    /* write collected data to SharedStore for LLM */
    store_->put_int("net.tx_bytes", (int)total_tx_);
    store_->put_int("net.rx_bytes", (int)total_rx_);
    store_->put_int("net.retransmit", (int)total_retransmit_);
    store_->put_int("net.flows", (int)flows_.size());
    store_->put_int("net.blocked", (int)total_blocked_);

    /* top flow data for LLM */
    std::ostringstream top;
    int n = 0;
    for (auto &kv : flows_) {
        if (++n > 5) break;
        top << "pid=" << kv.first << " tx=" << kv.second.tx_bytes
            << " rx=" << kv.second.rx_bytes << " events=" << kv.second.total_events
            << " blocked=" << kv.second.blocked << " comm=" << kv.second.comm << "\n";
    }
    store_->put("net.top_flows", top.str());

    return 0;
}

int NetworkPolicySkill::act()
{
    if (!store_) return 0;

    for (auto &kv : flows_) {
        if (kv.second.blocked) continue;
        uint32_t pid = kv.first;
        std::string decision = store_->get("llm.block." + std::to_string(pid));
        if (!decision.empty()) {
            u8 val = 1;
            bpf_map_update_elem(block_fd_, &pid, &val, BPF_ANY);
            kv.second.blocked = true;
            total_blocked_++;
            printf("[NET] LLM BLOCK pid=%u %s\n", pid, decision.c_str());
        }
    }
    return 0;
}

std::vector<SkillMetrics> NetworkPolicySkill::metrics()
{
    return {
        {"tx_bytes",   (double)total_tx_, "B",   "TX bytes"},
        {"rx_bytes",   (double)total_rx_, "B",   "RX bytes"},
        {"flows",      (double)flows_.size(), "cnt", "Active flows"},
        {"blocked",    (double)total_blocked_, "cnt", "Blocked"},
        {"retransmit", (double)total_retransmit_, "cnt", "Retransmits"},
    };
}

} // namespace arca
