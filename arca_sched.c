#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "arca_sched.bpf.skel.h"

static volatile int exit_req;

static void sigint_handler(int s)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct arca_sched *skel;
	struct bpf_link *link;
	__u64 ecode;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(arca_ops, arca_sched);

	/* reuse the pinned classification map from agent */
	int pin_fd = bpf_obj_get("/sys/fs/bpf/task_class_map");
	if (pin_fd >= 0) {
		bpf_map__reuse_fd(skel->maps.task_class_map, pin_fd);
		close(pin_fd);
	} else {
		fprintf(stderr, "WARNING: /sys/fs/bpf/task_class_map not found, "
			"all tasks default to NORMAL DSQ. Start arca_agent first.\n");
	}

	SCX_OPS_LOAD(skel, arca_ops, arca_sched, uei);
	link = SCX_OPS_ATTACH(skel, arca_ops, arca_sched);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	arca_sched__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
