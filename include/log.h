#ifndef ARCA_LOG_H
#define ARCA_LOG_H

#include <cstdio>
#include <ctime>
#include <cstdarg>
#include <string>

namespace arca {

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    static Logger &instance() { static Logger l; return l; }

    void set_level(LogLevel l) { min_level_ = l; }
    void set_quiet(bool q) { quiet_ = q; }

    void log(LogLevel lv, const char *module, const char *fmt, ...) {
        if (lv < min_level_) return;
        if (quiet_ && lv < LogLevel::WARN) return;

        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        char ts[32];
        strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

        const char *lv_str = "???";
        switch (lv) {
        case LogLevel::DEBUG: lv_str = "DEBUG"; break;
        case LogLevel::INFO:  lv_str = "INFO";  break;
        case LogLevel::WARN:  lv_str = "WARN";  break;
        case LogLevel::ERROR: lv_str = "ERROR"; break;
        }

        fprintf(stderr, "[%s %-5s %-12s] ", ts, lv_str, module);

        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        fprintf(stderr, "\n");
        fflush(stderr);
    }

private:
    LogLevel min_level_ = LogLevel::INFO;
    bool quiet_ = false;
};

#define LOG_DEBUG(m, ...) Logger::instance().log(LogLevel::DEBUG, m, ##__VA_ARGS__)
#define LOG_INFO(m, ...)  Logger::instance().log(LogLevel::INFO,  m, ##__VA_ARGS__)
#define LOG_WARN(m, ...)  Logger::instance().log(LogLevel::WARN,  m, ##__VA_ARGS__)
#define LOG_ERROR(m, ...) Logger::instance().log(LogLevel::ERROR, m, ##__VA_ARGS__)

} // namespace arca

#endif
