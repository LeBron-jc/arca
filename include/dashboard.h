#ifndef ARCA_DASHBOARD_H
#define ARCA_DASHBOARD_H

#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <sys/ioctl.h>
#include "skill_manager.h"

namespace arca {

class Dashboard {
public:
    Dashboard() : height_(40), width_(120) {}

    void render(SkillManager &mgr) {
        get_terminal_size();
        clear_screen();

        render_header();
        render_cpu_section(mgr);
        render_network_section(mgr);
        render_resource_section(mgr);
        render_footer(mgr);

        fflush(stdout);
    }

private:
    int height_, width_;

    void get_terminal_size() {
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
            height_ = w.ws_row;
            width_  = w.ws_col;
        }
    }

    void clear_screen() {
        printf("\033[2J\033[H"); /* clear, home */
    }

    void set_color(const char *c) { printf("\033[%sm", c); }
    void reset() { printf("\033[0m"); }

    void render_header() {
        char buf[32];
        time_t now = time(NULL);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

        set_color("1;36"); printf("╔"); for (int i = 0; i < width_-2; i++) printf("═"); printf("╗\n"); reset();
        set_color("1;36"); printf("║"); reset();
        set_color("1;37"); printf("  ARCA  Adaptive Resource Control Agent  |  %s", buf);
        for (int i = 42 + (int)strlen(buf); i < width_-3; i++) printf(" ");
        set_color("1;36"); printf("║\n"); reset();
        set_color("1;36"); printf("╚"); for (int i = 0; i < width_-2; i++) printf("═"); printf("╝\n\n"); reset();
    }

    void render_cpu_section(SkillManager &mgr) {
        set_color("1;33"); printf("═══ CPU Scheduling ═══"); reset(); printf("\n");

        for (auto &s : mgr.get_skills()) {
            if (s->type() != SkillType::CPU_SCHED) continue;

            auto m = s->metrics();
            uint64_t tasks = 0;
            for (auto &mt : m) {
                if (mt.name == "tasks")       tasks  = (uint64_t)mt.value;
            }

            printf("  Tasks: ");
            set_color("1;37"); printf("%lu", tasks); reset();
            printf("  |  SCX: ");
            FILE *f = fopen("/sys/kernel/sched_ext/state", "r");
            if (f) {
                char state[16];
                if (fgets(state, sizeof(state), f)) {
                    char *nl = strchr(state, '\n');
                    if (nl) *nl = 0;
                    if (strcmp(state, "enabled") == 0) set_color("1;32");
                    else set_color("1;31");
                    printf("%s", state);
                }
                fclose(f);
            }
            reset(); printf("\n\n");
        }
    }

    void render_network_section(SkillManager &mgr) {
        set_color("1;33"); printf("═══ Network Policy ═══"); reset(); printf("\n");
        for (auto &s : mgr.get_skills()) {
            if (s->type() != SkillType::NETWORK_POLICY) continue;
            printf("  Status: %s", s->status().c_str());
            auto m = s->metrics();
            for (auto &mt : m)
                printf("  |  %s: %.0f %s", mt.name.c_str(), mt.value, mt.unit.c_str());
            printf("\n");
        }
        printf("\n");
    }

    void render_resource_section(SkillManager &mgr) {
        set_color("1;33"); printf("═══ Resource Control ═══"); reset(); printf("\n");
        for (auto &s : mgr.get_skills()) {
            if (s->type() != SkillType::RESOURCE_CONTROL) continue;
            printf("  Status: ");
            if (s->status().find("ALERT") != std::string::npos) set_color("1;31");
            else set_color("1;32");
            printf("%s", s->status().c_str());
            reset();
            auto m = s->metrics();
            for (auto &mt : m) {
                printf("  |  ");
                if (mt.name == "mem_mb") set_color("1;35");
                else if (mt.name == "cpu_pct") set_color("1;33");
                else set_color("0;37");
                printf("%s: %.0f %s", mt.name.c_str(), mt.value, mt.unit.c_str());
                reset();
            }
            printf("\n");
        }
        printf("\n");
    }

    void render_footer(SkillManager &mgr) {
        set_color("0;37");
        for (int i = 0; i < width_; i++) printf("─");
        printf("\n  Skills: %zu  |  Ctrl-C to exit", mgr.count());
        reset(); printf("\n");
    }
};

} // namespace arca
#endif
