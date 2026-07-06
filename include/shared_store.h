#ifndef ARCA_SHARED_STORE_H
#define ARCA_SHARED_STORE_H

#include <string>
#include <map>
#include <mutex>
#include <vector>
#include <sstream>
#include <cstdio>

namespace arca {

class SharedStore {
public:
    void put(const std::string &key, const std::string &val) {
        std::lock_guard<std::mutex> lock(mtx_);
        store_[key] = val;
    }

    std::string get(const std::string &key, const std::string &def = "") const {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = store_.find(key);
        return it != store_.end() ? it->second : def;
    }

    void put_int(const std::string &key, int val) {
        put(key, std::to_string(val));
    }

    void put_double(const std::string &key, double val) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%.2f", val);
        put(key, buf);
    }

    int get_int(const std::string &key, int def = 0) const {
        auto s = get(key);
        return s.empty() ? def : atoi(s.c_str());
    }

    double get_double(const std::string &key, double def = 0.0) const {
        auto s = get(key);
        return s.empty() ? def : atof(s.c_str());
    }

    /* dump all keys to a string for LLM prompt */
    std::string dump() const {
        std::lock_guard<std::mutex> lock(mtx_);
        std::ostringstream oss;
        oss << "{\n";
        int i = 0;
        for (auto &kv : store_) {
            oss << "  \"" << kv.first << "\": " << kv.second;
            if (++i < (int)store_.size()) oss << ",";
            oss << "\n";
        }
        oss << "}";
        return oss.str();
    }

    size_t size() const { return store_.size(); }

private:
    mutable std::mutex mtx_;
    std::map<std::string, std::string> store_;
};

} // namespace arca

#endif
