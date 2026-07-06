#include <stdio.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "arca_sched.bpf.skel.h"

struct arca_scx_state {
	struct arca_sched *skel;
	struct bpf_link *link;
};

void *arca_scx_open_load_attach(const char *pin_path)
{
	struct arca_scx_state *st = calloc(1, sizeof(*st));
	if (!st) return NULL;

	st->skel = SCX_OPS_OPEN(arca_ops, arca_sched);

	if (pin_path) {
		int fd = bpf_obj_get(pin_path);
		if (fd >= 0) {
            bpf_map__reuse_fd(st->skel->maps.task_class_map, fd);
			close(fd);
		}
	}

	SCX_OPS_LOAD(st->skel, arca_ops, arca_sched, uei);
	st->link = SCX_OPS_ATTACH(st->skel, arca_ops, arca_sched);
	return st;
}

void arca_scx_destroy(void *state)
{
	struct arca_scx_state *st = (struct arca_scx_state *)state;
	if (!st) return;
	if (st->link) bpf_link__destroy(st->link);
	if (st->skel) arca_sched__destroy(st->skel);
	free(st);
}
