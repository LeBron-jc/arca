#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <unistd.h>

extern "C" {
#include <bpf/bpf.h>
}
#include "llm_skill.h"

namespace arca {

static std::string json_escape(const std::string &s)
{
    std::string r;
    for (auto c : s) {
        if (c == '"') { r += "\\\""; continue; }
        if (c == '\\') { r += "\\\\"; continue; }
        if (c == '\n') { r += "\\n"; continue; }
        if (c == '\r') { r += "\\r"; continue; }
        if (c == '\t') { r += "\\t"; continue; }
        if (c < 0x20) continue;
        r += c;
    }
    return r;
}

static std::string rtrim(const std::string &s) {
    auto end = s.find_last_not_of(" \t\n\r");
    return end == std::string::npos ? "" : s.substr(0, end + 1);
}

int LLMDecisionSkill::init()
{
    std::string api_key = cfg_.get_str("llm.api_key", "");
    if (api_key.empty()) api_key = getenv("DEEPSEEK_API_KEY") ?: "";
    if (api_key.empty()) { set_status("no api key"); return 0; }
    return 0;
}

int LLMDecisionSkill::start()
{
    running_ = true;
    class_map_fd_ = bpf_obj_get("/sys/fs/bpf/task_class_map");
    return 0;
}

int LLMDecisionSkill::stop()    { running_ = false; return 0; }
int LLMDecisionSkill::collect() { return 0; }

std::string LLMDecisionSkill::build_prompt()
{
    std::ostringstream ss;
    ss << R"(You are a Linux kernel scheduling expert. Analyze system state and assign per-task CPU priorities.

## System State
)";
    if (store_) ss << store_->dump();

    ss << R"(

## Priority Scale
- +80 to +100: Latency-critical (interactive shell, database, real-time). Must preempt.
- +20 to +70:  Interactive (GUI, network server). Prefer idle CPU.
- -20 to +20:  Normal (unclassified, mixed workload).
- -50 to -20:  Batch (compilation, backup, log processing). Run in background.
- -100 to -50: Idle/I/O blocked (waiting on disk/network). Lowest priority.

## Rules
1. Network-heavy + low wakeup → probably a server → +60
2. High io_ratio + low run_time → I/O blocked → -30
3. High wakeup_rate + short run_time → interactive → +80
4. Long run_time + low wakeup → CPU-bound → +10
5. Newly forked + parent is high priority → inherit +40
6. kthread → 0 (let kernel manage)

## Output Format (respond ONLY with these lines)
PRIORITY: pid=<pid> priority=<int> reason=<one sentence>
STATUS: <normal|alert|warning>
)";
    return ss.str();
}

std::string LLMDecisionSkill::call_deepseek_api(const std::string &prompt)
{
    std::string api_key = cfg_.get_str("llm.api_key", "");
    if (api_key.empty()) api_key = getenv("DEEPSEEK_API_KEY") ?: "";
    if (api_key.empty()) return "";

    std::string model = cfg_.get_str("llm.model", "deepseek-chat");
    std::string json_body = "{\"model\":\"" + model + "\",\"messages\":[";
    json_body += R"({"role":"system","content":"You are an OS scheduling expert. Output only PRIORITY lines."},)";
    json_body += R"({"role":"user","content":")";
    json_body += json_escape(prompt);
    json_body += R"("}],"temperature":0.3,"max_tokens":2048})";

    char tmpfile[256];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/arca_llm_%d.json", getpid());
    FILE *fp = fopen(tmpfile, "w");
    if (!fp) return "";
    fwrite(json_body.c_str(), 1, json_body.size(), fp);
    fclose(fp);

    std::ostringstream cmd;
    cmd << "curl -s -X POST https://api.deepseek.com/v1/chat/completions"
        << " -H \"Content-Type: application/json\""
        << " -H \"Authorization: Bearer " << api_key << "\""
        << " -d @" << tmpfile
        << " --connect-timeout 10 --max-time 30 2>/dev/null";

    fp = popen(cmd.str().c_str(), "r");
    if (!fp) { unlink(tmpfile); return ""; }

    std::string result;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) result += buf;
    pclose(fp);
    unlink(tmpfile);

    call_count_++;
    last_call_time_ = time(NULL);
    return result;
}

std::vector<llm_decision> LLMDecisionSkill::parse_response(const std::string &response)
{
    std::vector<llm_decision> decisions;
    if (response.empty()) return decisions;

    auto pos = response.find("\"content\":\"");
    if (pos == std::string::npos) {
        pos = response.find("\"reasoning_content\":\"");
        if (pos != std::string::npos) pos += 22;
    } else {
        pos += 11;
    }
    if (pos == std::string::npos) return decisions;

    std::string content;
    while (pos < response.size()) {
        char c = response[pos];
        if (c == '\\' && pos + 1 < response.size()) {
            char nxt = response[pos + 1];
            if (nxt == 'n') { content += '\n'; pos += 2; continue; }
            if (nxt == 'r') { content += '\r'; pos += 2; continue; }
            if (nxt == 't') { content += '\t'; pos += 2; continue; }
            if (nxt == '"') { content += '"';  pos += 2; continue; }
            if (nxt == '\\'){ content += '\\'; pos += 2; continue; }
            content += nxt; pos += 2;
        } else if (c == '"') {
            break;
        } else {
            content += c; pos++;
        }
    }

    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        line = rtrim(line);
        if (line.compare(0, 9, "PRIORITY:") != 0) continue;

        llm_decision d = {};

        auto p1 = line.find("pid=");
        auto p2 = line.find(" priority=");
        auto p3 = line.find(" reason=");

        if (p1 != std::string::npos && p2 != std::string::npos) {
            d.pid = atoi(line.c_str() + p1 + 4);
            d.priority = atoi(line.c_str() + p2 + 10);
            if (p3 != std::string::npos)
                d.reason = rtrim(line.substr(p3 + 8));
            if (d.pid > 0 && d.priority >= -100 && d.priority <= 100)
                decisions.push_back(d);
        }
    }
    return decisions;
}

void LLMDecisionSkill::apply_decisions(const std::vector<llm_decision> &decisions)
{
    for (auto &d : decisions) {
        if (class_map_fd_ < 0) continue;

        int old_prio = 0;
        bpf_map_lookup_elem(class_map_fd_, &d.pid, &old_prio);

        if (old_prio != d.priority) {
            bpf_map_update_elem(class_map_fd_, &d.pid, &d.priority, BPF_ANY);
            printf("[LLM] pid=%d priority=%d (was %d) reason=%s\n",
                   d.pid, d.priority, old_prio, d.reason.c_str());
        }
    }
}

int LLMDecisionSkill::policy()
{
    if (!store_ || store_->size() < 2) return 0;

    int interval = cfg_.get_int("llm.call_interval_sec", 10);
    time_t now = time(NULL);
    if (now - last_call_time_ < interval) return 0;

    std::string prompt = build_prompt();
    std::string response = call_deepseek_api(prompt);
    if (response.empty()) { set_status("api call failed"); return 0; }

    auto decisions = parse_response(response);
    fprintf(stderr, "[LLM] #%d: %zu chars, %zu decisions\n",
            call_count_, response.size(), decisions.size());

    apply_decisions(decisions);

    char buf[64];
    snprintf(buf, sizeof(buf), "#%d, %zu priorities", call_count_, decisions.size());
    set_status(buf);
    return 0;
}

int LLMDecisionSkill::act() { return 0; }

std::vector<SkillMetrics> LLMDecisionSkill::metrics()
{
    return {
        {"llm_calls", (double)call_count_, "cnt", "LLM API calls"},
        {"last_call", (double)(time(NULL)-last_call_time_), "s", "Seconds since last call"},
    };
}

} // namespace arca
