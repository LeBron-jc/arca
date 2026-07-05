#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#define CPU_WORKERS   4
#define INT_WORKERS   2
#define BATCH_WORKERS 2
#define RUN_SECONDS   10
#define INTERACTIVE_PERIOD_US 2000
#define INTERACTIVE_WORK_US    100

static volatile int running = 1;

struct worker_stats {
	const char *name;
	double   ops_per_sec;
	double   latency_p50_us;
	double   latency_p99_us;
	double   avg_latency_us;
	long     total_ops;
	long     latency_samples;
	double   latency_sum;
	long     latency_hist[11];
};

static struct worker_stats g_cpu_stats[CPU_WORKERS];
static struct worker_stats g_int_stats[INT_WORKERS];
static struct worker_stats g_batch_stats[BATCH_WORKERS];

static long now_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000L + tv.tv_usec;
}

static void record_latency(struct worker_stats *ws, long latency_us)
{
	ws->latency_sum += latency_us;
	ws->latency_samples++;
	int bucket = 0;
	if (latency_us >= 10000) bucket = 10;
	else if (latency_us >= 5000) bucket = 9;
	else if (latency_us >= 2000) bucket = 8;
	else if (latency_us >= 1000) bucket = 7;
	else if (latency_us >= 500)  bucket = 6;
	else if (latency_us >= 200)  bucket = 5;
	else if (latency_us >= 100)  bucket = 4;
	else if (latency_us >= 50)   bucket = 3;
	else if (latency_us >= 20)   bucket = 2;
	else if (latency_us >= 10)   bucket = 1;
	ws->latency_hist[bucket]++;
}

static void *cpu_worker(void *arg)
{
	int id = *(int *)arg;
	struct worker_stats *ws = &g_cpu_stats[id];
	ws->name = "CPU-bound";
	long ops = 0;
	long start_us = now_us();

	while (running) {
		double x = 1.0;
		for (int i = 0; i < 1000; i++)
			x = sin(x + 0.1);
		ops++;
		if (x < -99.0) printf("impossible\n");
	}

	long elapsed = now_us() - start_us;
	ws->total_ops = ops;
	ws->ops_per_sec = (elapsed > 0) ? (double)ops * 1e6 / elapsed : 0;
	return NULL;
}

static void *interactive_worker(void *arg)
{
	int id = *(int *)arg;
	struct worker_stats *ws = &g_int_stats[id];
	ws->name = "Interactive";
	long ops = 0;
	long start_us = now_us();

	while (running) {
		long wake_time = now_us();

		usleep(INTERACTIVE_PERIOD_US);
		record_latency(ws, now_us() - wake_time - INTERACTIVE_PERIOD_US);

		long work_start = now_us();
		long work_end;
		do { work_end = now_us(); } while (work_end - work_start < INTERACTIVE_WORK_US);

		ops++;
	}

	long elapsed = now_us() - start_us;
	ws->total_ops = ops;
	ws->ops_per_sec = (elapsed > 0) ? (double)ops * 1e6 / elapsed : 0;
	ws->avg_latency_us = (ws->latency_samples > 0) ? ws->latency_sum / ws->latency_samples : 0;
	return NULL;
}

static void *batch_worker(void *arg)
{
	int id = *(int *)arg;
	struct worker_stats *ws = &g_batch_stats[id];
	ws->name = "Batch";
	long ops = 0;
	long start_us = now_us();

	while (running) {
		double x = 0.0;
		for (int i = 0; i < 5000; i++)
			x += sin(i * 0.01) * cos(i * 0.03);
		if ((ops & 0x3F) == 0)
			sched_yield();
		ops++;
	}

	long elapsed = now_us() - start_us;
	ws->total_ops = ops;
	ws->ops_per_sec = (elapsed > 0) ? (double)ops * 1e6 / elapsed : 0;
	return NULL;
}

static void compute_latency(struct worker_stats *ws)
{
	long sorted[10000];
	int n = ws->latency_samples > 10000 ? 10000 : ws->latency_samples;
	ws->latency_p50_us = ws->avg_latency_us;
	ws->latency_p99_us = ws->avg_latency_us * 2;
}

int main(int argc, char **argv)
{
	int secs = RUN_SECONDS;
	if (argc > 1) secs = atoi(argv[1]);

	pthread_t cpu_thr[CPU_WORKERS], int_thr[INT_WORKERS], bat_thr[BATCH_WORKERS];
	int ids[CPU_WORKERS > INT_WORKERS ? (CPU_WORKERS > BATCH_WORKERS ? CPU_WORKERS : BATCH_WORKERS) : (INT_WORKERS > BATCH_WORKERS ? INT_WORKERS : BATCH_WORKERS)];

	for (int i = 0; i < CPU_WORKERS; i++) { ids[i] = i; pthread_create(&cpu_thr[i], NULL, cpu_worker, &ids[i]); }
	for (int i = 0; i < INT_WORKERS; i++) { ids[i] = i; pthread_create(&int_thr[i], NULL, interactive_worker, &ids[i]); }
	for (int i = 0; i < BATCH_WORKERS; i++) { ids[i] = i; pthread_create(&bat_thr[i], NULL, batch_worker, &ids[i]); }

	fprintf(stderr, "Running %d sec with %d CPU + %d INT + %d BATCH workers...\n",
		secs, CPU_WORKERS, INT_WORKERS, BATCH_WORKERS);
	sleep(secs);
	running = 0;

	for (int i = 0; i < CPU_WORKERS; i++) pthread_join(cpu_thr[i], NULL);
	for (int i = 0; i < INT_WORKERS; i++) pthread_join(int_thr[i], NULL);
	for (int i = 0; i < BATCH_WORKERS; i++) pthread_join(bat_thr[i], NULL);

	for (int i = 0; i < BATCH_WORKERS; i++) compute_latency(&g_batch_stats[i]);

	printf("\n=== WORKLOAD RESULTS ===\n\n");
	printf("%-14s %12s %12s %12s\n", "Worker", "Ops/sec", "AvgLat(us)", "MaxLat(us)");
	printf("--------------------------------------------------------------\n");

	double cpu_total = 0, batch_total = 0;
	double int_lat_total = 0;

	for (int i = 0; i < CPU_WORKERS; i++) {
		cpu_total += g_cpu_stats[i].ops_per_sec;
		printf("%-14s %12.0f %12s %12s\n",
		       g_cpu_stats[i].name, g_cpu_stats[i].ops_per_sec, "-", "-");
	}

	for (int i = 0; i < INT_WORKERS; i++) {
		int_lat_total += g_int_stats[i].avg_latency_us;
		double max_lat = 0;
		for (int j = 10; j >= 0; j--) {
			if (g_int_stats[i].latency_hist[j] > 0) {
				max_lat = j == 10 ? 10000.0 : (double)(1 << (j+1)) * 50;
				break;
			}
		}
		printf("%-14s %12.0f %12.1f %12.1f\n",
		       g_int_stats[i].name, g_int_stats[i].ops_per_sec,
		       g_int_stats[i].avg_latency_us, max_lat);
	}

	for (int i = 0; i < BATCH_WORKERS; i++) {
		batch_total += g_batch_stats[i].ops_per_sec;
		printf("%-14s %12.0f %12s %12s\n",
		       g_batch_stats[i].name, g_batch_stats[i].ops_per_sec, "-", "-");
	}

	printf("--------------------------------------------------------------\n");
	printf("%-14s %12.0f\n", "TOTAL", cpu_total + batch_total);

	double int_avg_lat = INT_WORKERS > 0 ? int_lat_total / INT_WORKERS : 0;
	printf("\nInteractive avg latency: %.1f us\n", int_avg_lat);
	printf("CPU-bound total ops/sec: %.0f\n", cpu_total);
	printf("Batch total ops/sec:     %.0f\n", batch_total);

	return 0;
}
