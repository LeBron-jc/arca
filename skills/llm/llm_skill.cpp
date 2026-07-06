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

int LLMDecisionSkill::init()
{
    std::string api_key = cfg_.get_str("llm.api_key", "");
    if (api_key.empty()) api_key = getenv("DEEPSEEK_API_KEY") ?: "";
    if (api_key.empty()) {
        set_status("disabled: set llm.api_key in arca.conf or DEEPSEEK_API_KEY env");
        return 0;
    }
    return 0;
}

int LLMDecisionSkill::start()
{
    running_ = true;
    /* open the pinned map that CPUSchedSkill has already created */
    class_map_fd_ = bpf_obj_get("/sys/fs/bpf/task_class_map");
    if (class_map_fd_ < 0)
        fprintf(stderr, "[LLM] Warning: cannot open /sys/fs/bpf/task_class_map\n");
    return 0;
}

int LLMDecisionSkill::stop()
{
    running_ = false;
    return 0;
}

int LLMDecisionSkill::collect()
{
    return 0;
}

static std::string rtrim(const std::string &s) {
    auto end = s.find_last_not_of(" \t\n\r");
    return end == std::string::npos ? "" : s.substr(0, end + 1);
}

std::string LLMDecisionSkill::build_prompt()
{
    std::ostringstream ss;

    ss << R"(You are an OS scheduling expert. Analyze the following system state and workload data to optimize CPU scheduling.

## System State
)";
    if (store_) ss << store_->dump();

    ss << R"(

## Instructions
1. Review each task's workload pattern.
2. Decide its scheduling class:
   - 1 = INTERACTIVE (high wakeup rate, short runtime, latency-sensitive)
   - 2 = CPU_BOUND (low wakeup rate, long continuous runtime)
   - 3 = BATCH (moderate wakeup, bulk processing, not latency-sensitive)
3. Suggest optimal time slice in microseconds (1000-50000).
4. Provide a one-sentence reason.

## Output Format
Respond ONLY with lines in this exact format:
CLASSIFY: pid=<pid> class=<1|2|3> slice=<us> reason=<one sentence>
STATUS: <normal|alert|warning>

## Example
CLASSIFY: pid=1234 class=1 slice=1000 reason=High wakeup rate indicates interactive shell
CLASSIFY: pid=5678 class=2 slice=10000 reason=Long continuous runs with low wakeup count
STATUS: normal
)";

    return ss.str();
}

std::string LLMDecisionSkill::call_deepseek_api(const std::string &prompt)
{
    std::string api_key = cfg_.get_str("llm.api_key", "");
    if (api_key.empty()) api_key = getenv("DEEPSEEK_API_KEY") ?: "";
    if (api_key.empty()) return "";

    /* write request body to temp file to avoid shell command length limit */
    std::string model = cfg_.get_str("llm.model", "deepseek-chat");
    std::string json_body = "{\"model\":\"" + model + "\",\"messages\":[";
    json_body += R"({"role":"system","content":"You are an OS scheduling expert. Respond concisely."},)";
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
    while (fgets(buf, sizeof(buf), fp))
        result += buf;
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

    /* extract content from JSON response: check "content":"..." and "reasoning_content":"..." */
    auto pos = response.find("\"content\":\"");
    if (pos == std::string::npos) {
        pos = response.find("\"reasoning_content\":\"");
        if (pos != std::string::npos) pos += 22; /* skip past "reasoning_content":" */
    } else {
        pos += 11; /* skip past "content":" */
    }
    std::string content;
    while (pos < response.size()) {
        char c = response[pos];
        if (c == '\\' && pos + 1 < response.size()) {
            char nxt = response[pos + 1];
            if (nxt == 'n') { content += '\n'; pos += 2; continue; }
            if (nxt == 'r') { content += '\r'; pos += 2; continue; }
            if (nxt == 't') { content += '\t'; pos += 2; continue; }
            if (nxt == '"') { content += '"';  pos += 2; continue; }
            if (nxt == '\\') { content += '\\'; pos += 2; continue; }
            content += nxt;
            pos += 2;
        } else if (c == '"') {
            break;
        } else {
            content += c;
            pos++;
        }
    }

    /* parse CLASSIFY lines from content */
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        line = rtrim(line);
        if (line.compare(0, 9, "CLASSIFY:") != 0) continue;

        llm_decision d = {};
        d.new_slice_us = -1;
        d.new_class = -1;

        /* parse pid=1234 class=1 slice=1000 reason=... */
        auto p1 = line.find("pid=");
        auto p2 = line.find(" class=");
        auto p3 = line.find(" slice=");
        auto p4 = line.find(" reason=");

        if (p1 != std::string::npos && p2 != std::string::npos) {
            d.pid = atoi(line.c_str() + p1 + 4);

            auto cls_str = line.substr(p2 + 7, 1);
            d.new_class = atoi(cls_str.c_str());

            if (p3 != std::string::npos) {
                auto slice_str = line.substr(p3 + 7);
                auto sp = slice_str.find(" ");
                if (sp != std::string::npos) slice_str = slice_str.substr(0, sp);
                d.new_slice_us = atoi(slice_str.c_str());
            }

            if (p4 != std::string::npos) {
                d.reason = rtrim(line.substr(p4 + 8));
            }

            if (d.pid > 0 && d.new_class >= 1 && d.new_class <= 3)
                decisions.push_back(d);
        }
    }

    return decisions;
}

void LLMDecisionSkill::apply_decisions(const std::vector<llm_decision> &decisions)
{
    for (auto &d : decisions) {
        if (class_map_fd_ < 0) continue;

        enum arca_task_class cls = (enum arca_task_class)d.new_class;

        /* read current class from map */
        enum arca_task_class old_cls = ARCA_CLASS_UNKNOWN;
        bpf_map_lookup_elem(class_map_fd_, &d.pid, &old_cls);

        if (old_cls != cls) {
            bpf_map_update_elem(class_map_fd_, &d.pid, &cls, BPF_ANY);
            printf("[LLM] pid=%d: override %d→%d slice=%dus reason=%s\n",
                   d.pid, (int)old_cls, (int)cls,
                   d.new_slice_us, d.reason.c_str());
        }
    }
}

int LLMDecisionSkill::policy()
{
    if (store_->size() < 2) return 0; /* wait for data */

    /* rate limit: max 1 call per 5 seconds */
    time_t now = time(NULL);
    int interval = cfg_.get_int("llm.call_interval_sec", 10);
    if (now - last_call_time_ < interval) return 0;

    std::string prompt = build_prompt();
    std::string response = call_deepseek_api(prompt);

    if (response.empty()) {
        set_status("API call failed, using rule-based fallback");
        return 0;
    }

    auto decisions = parse_response(response);
    fprintf(stderr, "[LLM] API call #%d returned %zu chars, %zu decisions\n",
            call_count_, response.size(), decisions.size());

    if (decisions.empty()) {
        set_status("LLM returned no decisions");
        return 0;
    }

    apply_decisions(decisions);

    char buf[64];
    snprintf(buf, sizeof(buf), "called #%d, %zu decisions",
             call_count_, decisions.size());
    set_status(buf);
    return 0;
}

int LLMDecisionSkill::act()
{
    return 0;
}

std::vector<SkillMetrics> LLMDecisionSkill::metrics()
{
    return {
        {"llm_calls",    (double)call_count_, "cnt",  "LLM API calls"},
        {"last_call_sec", (double)(time(NULL)-last_call_time_), "s", "Seconds since last call"},
    };
}

} // namespace arca
