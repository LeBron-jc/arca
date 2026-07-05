#ifndef ARCA_CONFIG_H
#define ARCA_CONFIG_H

#include <string>
#include <map>
#include <fstream>
#include <cstdlib>
#include <cstdio>

namespace arca {

class Config {
public:
    Config(const std::string &path = "/home/cuijian/arca/arca.conf") {
        load(path);
    }

    int get_int(const std::string &key, int def = 0) const {
        auto it = kv_.find(key);
        return it != kv_.end() ? atoi(it->second.c_str()) : def;
    }

    double get_double(const std::string &key, double def = 0.0) const {
        auto it = kv_.find(key);
        return it != kv_.end() ? atof(it->second.c_str()) : def;
    }

    std::string get_str(const std::string &key, const std::string &def = "") const {
        auto it = kv_.find(key);
        return it != kv_.end() ? it->second : def;
    }

    bool get_bool(const std::string &key, bool def = false) const {
        auto it = kv_.find(key);
        return it != kv_.end() ? (it->second == "true" || it->second == "1" || it->second == "yes") : def;
    }

    bool exists(const std::string &key) const {
        return kv_.find(key) != kv_.end();
    }

private:
    std::map<std::string, std::string> kv_;
    std::string cur_section_;

    void load(const std::string &path) {
        std::ifstream f(path);
        if (!f.is_open()) {
            fprintf(stderr, "Config: cannot open %s, using defaults\n", path.c_str());
            return;
        }

        std::string line;
        while (std::getline(f, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;

            if (line[0] == '[' && line.back() == ']') {
                cur_section_ = line.substr(1, line.size() - 2);
                continue;
            }

            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;

            std::string key = trim(line.substr(0, eq));
            std::string val = trim(line.substr(eq + 1));

            std::string full_key = cur_section_ + "." + key;
            kv_[full_key] = val;
        }
    }

    static std::string trim(const std::string &s) {
        size_t b = 0, e = s.size();
        while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) b++;
        while (e > b && (s[e-1] == ' ' || s[e-1] == '\t' || s[e-1] == '\r')) e--;
        return s.substr(b, e - b);
    }
};

} // namespace arca

#endif
