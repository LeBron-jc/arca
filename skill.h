#ifndef ARCA_SKILL_H
#define ARCA_SKILL_H

#include <string>
#include <vector>
#include <map>

namespace arca {

enum class SkillType {
    CPU_SCHED,
    NETWORK_POLICY,
    RESOURCE_CONTROL,
    CUSTOM
};

struct SkillMetrics {
    std::string name;
    double value;
    std::string unit;
    std::string description;
};

class Skill {
public:
    Skill(const std::string &name, SkillType type)
        : name_(name), type_(type), running_(false) {}
    virtual ~Skill() = default;

    virtual int init()    = 0;
    virtual int start()   = 0;
    virtual int stop()    = 0;

    virtual int collect() = 0;
    virtual int policy()  = 0;
    virtual int act()     = 0;

    virtual std::vector<SkillMetrics> metrics() = 0;

    const std::string &name() const { return name_; }
    SkillType type() const { return type_; }
    bool is_running() const { return running_; }

    void set_status(const std::string &s) { status_ = s; }
    const std::string &status() const { return status_; }

protected:
    std::string name_;
    SkillType type_;
    bool running_;
    std::string status_;
};

} // namespace arca

#endif
