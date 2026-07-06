#include <cstdio>
#include <cstring>
#include <fstream>
#include <unistd.h>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#include "resource_skill.h"
#include "resource_skill.skel.h"

namespace arca {

static uint64_t read_val(const std::string &path)
{
    std::ifstream f(path);
    uint64_t v = 0;
    if (f.is_open()) f >> v;
    return v;
}

static bool write_val(const std::string &path, uint64_t v)
{
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << v;
    return true;
}

int ResourceControlSkill::init()
{
    /* cgroup detection */
    if (access("/sys/fs/cgroup/memory.current", R_OK) == 0)
        cgroup_path_ = "/sys/fs/cgroup";
    else if (access("/sys/fs/cgroup/memory/memory.usage_in_bytes", R_OK) == 0)
        cgroup_path_ = "/sys/fs/cgroup/memory";

    /* load eBPF for resource monitoring */
    struct resource_skill *skel = resource_skill__open();
    if (skel) {
        if (resource_skill__load(skel) == 0 && resource_skill__attach(skel) == 0) {
            counters_fd_ = bpf_map__fd(skel->maps.res_counters);
            bpf_obj_ = (struct bpf_object *)skel;
        } else {
            resource_skill__destroy(skel);
        }
    }
    return 0;
}

int ResourceControlSkill::start()
{
    running_ = true;
    stats_ = {};
    return 0;
}

int ResourceControlSkill::stop()
{
    running_ = false;
    if (bpf_obj_) { resource_skill__destroy((struct resource_skill *)bpf_obj_); bpf_obj_ = nullptr; }
    return 0;
}

int ResourceControlSkill::collect()
{
    /* memory from /proc/meminfo */
    stats_.mem_usage_mb = 0;
    std::ifstream mi("/proc/meminfo");
    std::string line;
    uint64_t total = 0, avail = 0;
    while (std::getline(mi, line)) {
        if (line.find("MemTotal:") == 0)
            sscanf(line.c_str(), "MemTotal: %lu kB", &total);
        if (line.find("MemAvailable:") == 0)
            sscanf(line.c_str(), "MemAvailable: %lu kB", &avail);
    }
    if (total > avail) stats_.mem_usage_mb = (total - avail) / 1024;

    /* cpu from /proc/stat */
    std::ifstream ps("/proc/stat");
    std::getline(ps, line);
    uint64_t user, nice, sys, idle, iowait, irq, softirq, steal;
    sscanf(line.c_str(), "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
           &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal);
    uint64_t total_cpu = user+nice+sys+idle+iowait+irq+softirq+steal;
    uint64_t busy = total_cpu - idle;
    static uint64_t prev_total = 0, prev_busy = 0;
    if (prev_total > 0 && total_cpu > prev_total) {
        stats_.cpu_usage_pct = (busy - prev_busy) * 100 / (total_cpu - prev_total);
    }
    prev_total = total_cpu;
    prev_busy = busy;

    stats_.oom_count = read_val(cgroup_path_ + "/memory.events");

    /* read eBPF counters */
    if (counters_fd_ >= 0) {
        int nr_cpus = libbpf_num_possible_cpus();
        u64 vals[4 * nr_cpus];
        u32 idx;
        for (idx = 0; idx < 4; idx++) {
            if (bpf_map_lookup_elem(counters_fd_, &idx, &vals[idx * nr_cpus]) == 0) {
                u64 sum = 0;
                for (int i = 0; i < nr_cpus; i++) sum += vals[idx * nr_cpus + i];
                switch (idx) {
                case 0: stats_.page_allocs = sum; break;
                case 1: stats_.block_ios = sum; break;
                }
            }
        }
    }

    /* write to shared store */
    if (store_) {
        store_->put_int("system.mem_usage_mb", (int)stats_.mem_usage_mb);
        store_->put_int("system.cpu_usage_pct", (int)stats_.cpu_usage_pct);
        store_->put_int("system.oom_count", (int)stats_.oom_count);
        store_->put("system.status", status());
    }

    return 0;
}

int ResourceControlSkill::policy()
{
    int mem_alert = cfg_.get_int("resource.memory_alert_mb", 6144);
    int cpu_alert = cfg_.get_int("resource.cpu_alert_pct", 95);

    if (stats_.mem_usage_mb > mem_alert)
        set_status("ALERT: high memory");
    else if (stats_.cpu_usage_pct > cpu_alert)
        set_status("ALERT: high CPU");
    else
        set_status("normal");
    return 0;
}

int ResourceControlSkill::act()
{
    /* apply cgroup limits when thresholds exceeded */
    if (status().find("ALERT") != std::string::npos && status().find("memory") != std::string::npos) {
        /* reduce memory limit to 90% of current usage */
        int limit = cfg_.get_int("resource.memory_alert_mb", 6144);
        limit = limit * 9 / 10;
        std::string mem_path = cgroup_path_ + "/memory.max";
        if (access(mem_path.c_str(), W_OK) == 0)
            write_val(mem_path, limit * 1024ULL * 1024ULL);
    }

    if (status().find("high CPU") != std::string::npos) {
        /* reduce CPU quota */
        std::string cpu_path = cgroup_path_ + "/cpu.max";
        if (access(cpu_path.c_str(), W_OK) == 0)
            write_val(cpu_path, 50000); /* 50% of a CPU */
    }

    return 0;
}

std::vector<SkillMetrics> ResourceControlSkill::metrics()
{
    return {
        {"mem_mb",   (double)stats_.mem_usage_mb, "MB",  "Memory used"},
        {"cpu_pct",  (double)stats_.cpu_usage_pct, "%",  "CPU usage"},
        {"io_read",  (double)stats_.io_read_kb, "KB",  "IO read"},
        {"io_write", (double)stats_.io_write_kb, "KB",  "IO write"},
        {"oom",      (double)stats_.oom_count, "cnt",  "OOM events"},
        {"page_alloc", (double)stats_.page_allocs, "cnt", "Page allocs"},
        {"block_io",   (double)stats_.block_ios, "cnt",  "Block I/O"},
    };
}

} // namespace arca
