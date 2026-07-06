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

static std::string json_escape(const std::string &s) {
    std::string r;
    for (auto c : s) {
        if (c == '"')  { r += "\\\""; continue; }
        if (c == '\\') { r += "\\\\"; continue; }
        if (c == '\n') { r += "\\n";  continue; }
        if (c == '\r') { r += "\\r";  continue; }
        if (c == '\t') { r += "\\t";  continue; }
        if (c < 0x20) continue;
        r += c;
    }
    return r;
}

static std::string rtrim(const std::string &s) {
    auto e = s.find_last_not_of(" \t\n\r");
    return e == std::string::npos ? "" : s.substr(0, e + 1);
}

int LLMDecisionSkill::init() {
    std::string key = cfg_.get_str("llm.api_key", "");
    if (key.empty()) key = getenv("DEEPSEEK_API_KEY") ?: "";
    if (key.empty()) { set_status("no api key"); return 0; }
    return 0;
}

int LLMDecisionSkill::start() {
    running_ = true;
    class_map_fd_ = bpf_obj_get("/sys/fs/bpf/task_class_map");
    return 0;
}

int LLMDecisionSkill::stop()    { running_ = false; return 0; }
int LLMDecisionSkill::collect() { return 0; }

std::string LLMDecisionSkill::build_prompt()
{
    std::ostringstream ss;
    ss << R"(You are the central decision engine for ARCA, an OS resource control agent.
Based on the system state below, output management commands.

## System State
)";
    if (store_) ss << store_->dump();

    ss << R"(

## Your Role
You manage FOUR subsystems. For each, output the appropriate commands:

### 1. CPU Scheduling (PRIORITY)
Priority scale: +100(highest) to -100(lowest)
Rules:
- High wakeup + short runtime + low blocked time → +60 to +90 (interactive)
- Low wakeup + long runtime + few migrations → +10 to +30 (CPU-bound)
- High I/O blocked time → -30 to -10 (I/O blocked, don't waste CPU)
- New task, no data → 0 (normal)
- Server process (network heavy) → +50 to +70

### 2. Network Control (BLOCK)
Block a PID from network when:
- TX rate exceeds 10MB/s AND is not a known service
- Retransmit count > 100 (network abuse)
- Multiple connections from temp directory processes

### 3. Resource Control (THROTTLE)
Apply cgroup limits when:
- Memory > 80% of total → THROTTLE mem with limit in MB
- CPU > 90% sustained → THROTTLE cpu with percentage
- OOM events detected → THROTTLE mem aggressively

### 4. Security Alert (ALERT)
Alert when:
- Process executed from /tmp/ or /dev/shm/
- Shell (bash/sh/dash) launching download tools (curl/wget)
- Exit of a previously-alerted process

## Output Format (one command per line)
PRIORITY: pid=<pid> value=<int> reason=<sentence>
BLOCK: pid=<pid> reason=<sentence>
THROTTLE: type=<mem|cpu> value=<int> reason=<sentence>
ALERT: pid=<pid> severity=<1-5> reason=<sentence>
STATUS: <normal|alert>
)";
    return ss.str();
}

std::string LLMDecisionSkill::call_api(const std::string &prompt)
{
    std::string key = cfg_.get_str("llm.api_key", "");
    if (key.empty()) key = getenv("DEEPSEEK_API_KEY") ?: "";
    if (key.empty()) return "";

    std::string model = cfg_.get_str("llm.model", "deepseek-chat");
    std::string body = "{\"model\":\"" + model + "\",\"messages\":[";
    body += R"({"role":"system","content":"ARCA decision engine. Output only command lines."},)";
    body += R"({"role":"user","content":")" + json_escape(prompt) + R"("}])";
    body += ",\"temperature\":0.3,\"max_tokens\":2048}";

    char tmpf[256]; snprintf(tmpf, sizeof(tmpf), "/tmp/arca_llm_%d.json", getpid());
    FILE *fp = fopen(tmpf, "w");
    if (!fp) return "";
    fwrite(body.c_str(), 1, body.size(), fp); fclose(fp);

    std::ostringstream cmd;
    cmd << "curl -s -X POST https://api.deepseek.com/v1/chat/completions"
        << " -H \"Content-Type: application/json\""
        << " -H \"Authorization: Bearer " << key << "\""
        << " -d @" << tmpf << " --connect-timeout 10 --max-time 30 2>/dev/null";

    fp = popen(cmd.str().c_str(), "r");
    if (!fp) { unlink(tmpf); return ""; }
    std::string r; char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) r += buf;
    pclose(fp); unlink(tmpf);

    call_count_++; last_call_time_ = time(NULL);
    return r;
}

std::vector<llm_command> LLMDecisionSkill::parse_response(const std::string &response)
{
    std::vector<llm_command> cmds;
    if (response.empty()) return cmds;

    auto pos = response.find("\"content\":\"");
    if (pos == std::string::npos) {
        pos = response.find("\"reasoning_content\":\"");
        if (pos != std::string::npos) pos += 22;
    } else pos += 11;
    if (pos == std::string::npos) return cmds;

    std::string content;
    while (pos < response.size()) {
        char c = response[pos];
        if (c == '\\' && pos + 1 < response.size()) {
            char n = response[pos+1];
            if      (n == 'n') { content += '\n'; pos += 2; continue; }
            else if (n == 'r') { content += '\r'; pos += 2; continue; }
            else if (n == 't') { content += '\t'; pos += 2; continue; }
            else if (n == '"') { content += '"';  pos += 2; continue; }
            else if (n == '\\'){ content += '\\'; pos += 2; continue; }
            content += n; pos += 2;
        } else if (c == '"') { break; }
        else { content += c; pos++; }
    }

    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        line = rtrim(line);
        llm_command cmd = {};
        bool valid = false;

        if (line.compare(0, 9, "PRIORITY:") == 0) {
            cmd.type = "PRIORITY";
            auto p1 = line.find("pid="), p2 = line.find(" value="), p3 = line.find(" reason=");
            if (p1 != std::string::npos && p2 != std::string::npos) {
                cmd.pid = atoi(line.c_str() + p1 + 4);
                cmd.value = atoi(line.c_str() + p2 + 7);
                if (p3 != std::string::npos) cmd.reason = rtrim(line.substr(p3 + 8));
                if (cmd.pid > 0 && cmd.value >= -100 && cmd.value <= 100) valid = true;
            }
        } else if (line.compare(0, 6, "BLOCK:") == 0) {
            cmd.type = "BLOCK";
            auto p1 = line.find("pid="), p2 = line.find(" reason=");
            if (p1 != std::string::npos) {
                cmd.pid = atoi(line.c_str() + p1 + 4);
                if (p2 != std::string::npos) cmd.reason = rtrim(line.substr(p2 + 8));
                if (cmd.pid > 0) valid = true;
            }
        } else if (line.compare(0, 9, "THROTTLE:") == 0) {
            cmd.type = "THROTTLE";
            auto p1 = line.find("type="), p2 = line.find(" value="), p3 = line.find(" reason=");
            if (p1 != std::string::npos && p2 != std::string::npos) {
                std::string t = line.substr(p1+5, p2-p1-5);
                if (t == "mem") { cmd.pid = 1; } else { cmd.pid = 2; }
                cmd.value = atoi(line.c_str() + p2 + 7);
                if (p3 != std::string::npos) cmd.reason = rtrim(line.substr(p3 + 8));
                if (cmd.value > 0) valid = true;
            }
        } else if (line.compare(0, 6, "ALERT:") == 0) {
            cmd.type = "ALERT";
            auto p1 = line.find("pid="), p2 = line.find(" severity="), p3 = line.find(" reason=");
            if (p1 != std::string::npos) {
                cmd.pid = atoi(line.c_str() + p1 + 4);
                if (p2 != std::string::npos) cmd.value = atoi(line.c_str() + p2 + 10);
                if (p3 != std::string::npos) cmd.reason = rtrim(line.substr(p3 + 8));
                if (cmd.pid > 0) valid = true;
            }
        }

        if (valid) cmds.push_back(cmd);
    }
    return cmds;
}

void LLMDecisionSkill::apply_commands(const std::vector<llm_command> &cmds)
{
    for (auto &c : cmds) {
        if (c.type == "PRIORITY") {
            if (class_map_fd_ >= 0) {
                int old; bpf_map_lookup_elem(class_map_fd_, &c.pid, &old);
                if (old != c.value)
                    bpf_map_update_elem(class_map_fd_, &c.pid, &c.value, BPF_ANY);
            }
            char k[64]; snprintf(k, sizeof(k), "llm.priority.%d", c.pid);
            store_->put_int(k, c.value);
            printf("[LLM] PRIORITY pid=%d val=%d %s\n", c.pid, c.value, c.reason.c_str());
        } else if (c.type == "BLOCK") {
            store_->put("llm.block." + std::to_string(c.pid), c.reason);
            printf("[LLM] BLOCK pid=%d %s\n", c.pid, c.reason.c_str());
        } else if (c.type == "THROTTLE") {
            std::string key = c.pid == 1 ? "llm.throttle.mem" : "llm.throttle.cpu";
            store_->put_int(key, c.value);
            printf("[LLM] THROTTLE %s=%d %s\n",
                   c.pid == 1 ? "mem" : "cpu", c.value, c.reason.c_str());
        } else if (c.type == "ALERT") {
            store_->put("llm.alert." + std::to_string(c.pid), c.reason);
            printf("[LLM] ALERT pid=%d sev=%d %s\n", c.pid, c.value, c.reason.c_str());
        }
    }
}

int LLMDecisionSkill::policy()
{
    if (!store_ || store_->size() < 5) return 0;

    int interval = cfg_.get_int("llm.call_interval_sec", 10);
    time_t now = time(NULL);
    if (now - last_call_time_ < interval) return 0;

    std::string prompt = build_prompt();
    std::string response = call_api(prompt);
    if (response.empty()) { set_status("api failed"); return 0; }

    auto cmds = parse_response(response);
    fprintf(stderr, "[LLM] #%d: %zu chars, %zu commands\n",
            call_count_, response.size(), cmds.size());

    apply_commands(cmds);

    char buf[64]; snprintf(buf, sizeof(buf), "#%d, %zu cmds", call_count_, cmds.size());
    set_status(buf);
    return 0;
}

int LLMDecisionSkill::act() { return 0; }

std::vector<SkillMetrics> LLMDecisionSkill::metrics() {
    return {{"calls", (double)call_count_, "cnt", "API calls"}};
}

} // namespace arca
