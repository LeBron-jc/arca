#include <cstdio>
#include <csignal>
#include <unistd.h>
#include <ctime>
#include <memory>

#include "config.h"
#include "skill.h"
#include "skill_manager.h"
#include "cpu_skill.h"
#include "network_skill.h"
#include "resource_skill.h"
#include "security_skill.h"
#include "dashboard.h"

using namespace arca;

static volatile bool running = true;
static void sig_handler(int) { running = false; }

int main(int argc, char **argv)
{
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    const char *cfg_path = "arca.conf";
    if (argc > 1) cfg_path = argv[1];
    Config cfg(cfg_path);

    SkillManager mgr;

    auto cpu_skill = std::make_shared<CPUSchedSkill>(cfg);
    mgr.register_skill(cpu_skill);

    auto net_skill = std::make_shared<NetworkPolicySkill>();
    mgr.register_skill(net_skill);

    auto res_skill = std::make_shared<ResourceControlSkill>(cfg);
    mgr.register_skill(res_skill);

    auto sec_skill = std::make_shared<SecurityPolicySkill>();
    mgr.register_skill(sec_skill);

    if (mgr.init_all() != 0) {
        fprintf(stderr, "Init failed\n");
        return 1;
    }

    if (mgr.start_all() != 0) {
        fprintf(stderr, "Start failed\n");
        return 1;
    }

    Dashboard dash;
    time_t last_render = 0;
    int interval = cfg.get_int("general.refresh_interval_s", 1);

    while (running) {
        usleep(100000);
        mgr.tick();

        time_t now = time(NULL);
        if (now - last_render >= interval) {
            last_render = now;
            dash.render(mgr);
        }
    }

    printf("\033[2J\033[H");
    printf("ARCA stopped.\n");
    mgr.stop_all();
    return 0;
}
