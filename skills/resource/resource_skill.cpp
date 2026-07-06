#include <cstdio>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#include "resource_skill.h"
#include "resource_skill.skel.h"

namespace arca {

static uint64_t rv(const std::string &p) { std::ifstream f(p); uint64_t v=0; if(f.is_open()) f>>v; return v; }
static bool wv(const std::string &p, uint64_t v) { std::ofstream f(p); if(!f.is_open()) return false; f<<v; return true; }

int ResourceControlSkill::init()
{
    if (access("/sys/fs/cgroup/memory.current", R_OK) == 0)
        cgroup_path_ = "/sys/fs/cgroup";
    else if (access("/sys/fs/cgroup/memory/memory.usage_in_bytes", R_OK) == 0)
        cgroup_path_ = "/sys/fs/cgroup/memory";

    struct resource_skill *skel = resource_skill__open();
    if (skel) {
        if (resource_skill__load(skel) == 0 && resource_skill__attach(skel) == 0) {
            counters_fd_ = bpf_map__fd(skel->maps.res_counters);
            bpf_obj_ = (struct bpf_object *)skel;
        } else resource_skill__destroy(skel);
    }
    return 0;
}

int ResourceControlSkill::start() { running_ = true; stats_ = {}; return 0; }

int ResourceControlSkill::stop() {
    running_ = false;
    if (bpf_obj_) { resource_skill__destroy((struct resource_skill *)bpf_obj_); bpf_obj_ = nullptr; }
    return 0;
}

int ResourceControlSkill::collect()
{
    uint64_t total=0, avail=0;
    std::ifstream mi("/proc/meminfo"); std::string line;
    while (std::getline(mi, line)) {
        if (line.find("MemTotal:") == 0)     sscanf(line.c_str(), "MemTotal: %lu kB", &total);
        if (line.find("MemAvailable:") == 0)  sscanf(line.c_str(), "MemAvailable: %lu kB", &avail);
    }
    if (total > avail) stats_.mem_usage_mb = (total - avail) / 1024;

    std::ifstream ps("/proc/stat"); std::getline(ps, line);
    uint64_t u,ni,sy,id,io,ir,sf,st;
    sscanf(line.c_str(), "cpu %lu %lu %lu %lu %lu %lu %lu %lu", &u,&ni,&sy,&id,&io,&ir,&sf,&st);
    uint64_t tc=u+ni+sy+id+io+ir+sf+st, bs=tc-id;
    static uint64_t pt=0,pb=0;
    if (pt>0&&tc>pt) stats_.cpu_usage_pct=(bs-pb)*100/(tc-pt);
    pt=tc; pb=bs;

    stats_.oom_count = rv(cgroup_path_ + "/memory.events");

    if (counters_fd_ >= 0) {
        int nc = libbpf_num_possible_cpus(); u64 vals[4*nc]; u32 idx;
        for (idx=0;idx<4;idx++)
            if (bpf_map_lookup_elem(counters_fd_,&idx,&vals[idx*nc])==0) {
                u64 sum=0; for(int i=0;i<nc;i++) sum+=vals[idx*nc+i];
                if (idx==0) stats_.page_allocs=sum;
                else if (idx==1) stats_.block_ios=sum;
            }
    }
    return 0;
}

int ResourceControlSkill::policy()
{
    if (!store_) return 0;

    store_->put_int("system.mem_usage_mb", (int)stats_.mem_usage_mb);
    store_->put_int("system.cpu_usage_pct", (int)stats_.cpu_usage_pct);
    store_->put_int("system.oom_count", (int)stats_.oom_count);
    store_->put_int("system.page_allocs", (int)stats_.page_allocs);
    store_->put_int("system.block_ios", (int)stats_.block_ios);

    /* status based on LLM throttle commands */
    int tmem = store_->get_int("llm.throttle.mem");
    int tcpu = store_->get_int("llm.throttle.cpu");
    if (tmem > 0) set_status("LLM: memory throttled to " + std::to_string(tmem) + "MB");
    else if (tcpu > 0) set_status("LLM: CPU throttled to " + std::to_string(tcpu) + "%");
    else set_status("normal");
    return 0;
}

int ResourceControlSkill::act()
{
    if (!store_) return 0;

    int tmem = store_->get_int("llm.throttle.mem");
    int tcpu = store_->get_int("llm.throttle.cpu");

    if (tmem > 0) {
        /* create per-PID sub-cgroup and migrate top memory consumer */
        std::string sub = cgroup_path_ + "/arca_mem_limit";
        mkdir(sub.c_str(), 0755);

        std::string mp = sub + "/memory.max";
        if (access(mp.c_str(), W_OK) == 0)
            wv(mp, (uint64_t)tmem * 1024ULL * 1024ULL);

        /* migrate current shell (or heaviest process) into this cgroup */
        std::string pp = sub + "/cgroup.procs";
        if (access(pp.c_str(), W_OK) == 0) {
            wv(pp, (uint64_t)getpid()); /* puts self under limit */
        }

        printf("[RES] LLM THROTTLE mem=%dMB, created cgroup %s\n", tmem, sub.c_str());
    }

    if (tcpu > 0) {
        std::string sub = cgroup_path_ + "/arca_cpu_limit";
        mkdir(sub.c_str(), 0755);

        std::string cp = sub + "/cpu.max";
        if (access(cp.c_str(), W_OK) == 0) {
            char buf[64]; snprintf(buf, sizeof(buf), "%d 100000", tcpu * 1000);
            std::ofstream f(cp); if (f.is_open()) { f << buf; }
        }

        std::string pp = sub + "/cgroup.procs";
        if (access(pp.c_str(), W_OK) == 0) wv(pp, (uint64_t)getpid());

        printf("[RES] LLM THROTTLE cpu=%d%%, created cgroup %s\n", tcpu, sub.c_str());
    }
    return 0;
}

std::vector<SkillMetrics> ResourceControlSkill::metrics() {
    return {{"mem_mb",(double)stats_.mem_usage_mb,"MB","Memory"},
            {"cpu_pct",(double)stats_.cpu_usage_pct,"%","CPU"},
            {"oom",(double)stats_.oom_count,"cnt","OOM"},
            {"page_alloc",(double)stats_.page_allocs,"cnt","Page allocs"}};
}

} // namespace arca
