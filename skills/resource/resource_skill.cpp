#include <cstdio>
#include <cstring>
#include <fstream>
#include <unistd.h>
#include "resource_skill.h"

namespace arca {

static uint64_t read_val(const std::string &path)
{
    std::ifstream f(path);
    uint64_t v = 0;
    if (f.is_open()) f >> v;
    return v;
}

int ResourceControlSkill::init()
{
    if (access("/sys/fs/cgroup/memory.current", R_OK) == 0)
        cgroup_path_ = "/sys/fs/cgroup";           /* cgroup v2 */
    else if (access("/sys/fs/cgroup/memory/memory.usage_in_bytes", R_OK) == 0)
        cgroup_path_ = "/sys/fs/cgroup/memory";    /* cgroup v1 */
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
    return 0;
}

int ResourceControlSkill::collect()
{
    if (cgroup_path_.find("/memory") != std::string::npos) {
        /* cgroup v1 */
        stats_.mem_usage_mb = read_val(cgroup_path_ + "/memory.usage_in_bytes") / (1024*1024);
    } else {
        stats_.mem_usage_mb = read_val(cgroup_path_ + "/memory.current") / (1024*1024);
    }

    /* read /proc/meminfo for system-wide memory */
    stats_.mem_usage_mb = 0;
    std::ifstream mi("/proc/meminfo");
    std::string line;
    while (std::getline(mi, line)) {
        if (line.find("MemTotal:") == 0) {
            uint64_t total;
            sscanf(line.c_str(), "MemTotal: %lu kB", &total);
            uint64_t avail = 0;
            std::ifstream mi2("/proc/meminfo");
            std::string l2;
            while (std::getline(mi2, l2)) {
                if (l2.find("MemAvailable:") == 0) {
                    sscanf(l2.c_str(), "MemAvailable: %lu kB", &avail);
                    break;
                }
            }
            stats_.mem_usage_mb = (total - avail) / 1024;
            break;
        }
    }

    /* cpu from /proc/stat */
    std::ifstream ps("/proc/stat");
    std::getline(ps, line);
    uint64_t user, nice, sys, idle, iowait, irq, softirq, steal;
    sscanf(line.c_str(), "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
           &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal);
    uint64_t total = user + nice + sys + idle + iowait + irq + softirq + steal;
    uint64_t busy = total - idle;
    static uint64_t prev_total = 0, prev_busy = 0;
    if (prev_total > 0) {
        uint64_t dt = total - prev_total;
        uint64_t db = busy - prev_busy;
        stats_.cpu_usage_pct = dt > 0 ? (db * 100 / dt) : 0;
    }
    prev_total = total;
    prev_busy = busy;

    stats_.io_read_kb  = read_val("/sys/fs/cgroup/io.stat") / 1024;
    stats_.io_write_kb = read_val("/sys/fs/cgroup/io.stat") / 1024;
    stats_.oom_count   = read_val("/sys/fs/cgroup/memory.events");

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

int ResourceControlSkill::act() { return 0; }

std::vector<SkillMetrics> ResourceControlSkill::metrics()
{
    return {
        {"mem_mb",   (double)stats_.mem_usage_mb, "MB",  "Memory used"},
        {"cpu_pct",  (double)stats_.cpu_usage_pct, "%",  "CPU usage"},
        {"io_read",  (double)stats_.io_read_kb, "KB",  "IO read"},
        {"io_write", (double)stats_.io_write_kb, "KB",  "IO write"},
        {"oom",      (double)stats_.oom_count, "cnt",  "OOM events"},
    };
}

} // namespace arca
