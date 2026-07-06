#ifndef __ARCA_H
#define __ARCA_H

#define ARCA_TASK_COMM_LEN 16

/* sched_switch prev_state bits */
#define TASK_RUNNING            0
#define TASK_INTERRUPTIBLE      1
#define TASK_UNINTERRUPTIBLE    2

enum arca_task_class {
    ARCA_CLASS_UNKNOWN     = 0,
    ARCA_CLASS_INTERACTIVE = 1,
    ARCA_CLASS_CPU_BOUND   = 2,
    ARCA_CLASS_BATCH       = 3,
    ARCA_CLASS_IO_BOUND    = 4,
};

struct arca_task_event {
    unsigned int pid;
    unsigned int tgid;
    unsigned int cpu;
    unsigned int event_type;
    unsigned long long timestamp;
    char comm[ARCA_TASK_COMM_LEN];
    unsigned int prev_pid;
    unsigned int next_pid;
    unsigned long long run_time_ns;
    unsigned int wait_time_us;
    unsigned int wakee_pid;
    unsigned int waker_pid;
};

struct arca_stats_key {
    unsigned int pid;
    unsigned long long tgid;
};

struct arca_stats_val {
    unsigned long long total_run_ns;
    unsigned long long total_wait_ns;
    unsigned long long last_run_start_ns;
    unsigned long long last_wake_ns;
    unsigned int wakeup_count;
    unsigned int switch_count;
    unsigned int last_cpu;
    unsigned int cpu_migrations;
    unsigned int is_kthread;
    unsigned int io_wait_count;
    unsigned int d_state_count;
    unsigned int preempt_count;
    int nice;
    char comm[ARCA_TASK_COMM_LEN];
};

#endif
