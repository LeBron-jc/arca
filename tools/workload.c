#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>

typedef struct { const char *name; int cpu_w; int int_w; int bat_w; int period_us; int work_us; } profile_t;

static profile_t g_profiles[] = {
    {"web",    2, 6, 0,  2000,  50},
    {"db",     3, 3, 2,  5000, 200},
    {"batch",  4, 1, 3, 20000, 500},
    {"mixed",  4, 2, 2,  5000, 200},
    {"default",4, 2, 2,  2000, 100},
};
static profile_t *cur = &g_profiles[4];
static volatile int running = 1;

#define MAX_LAT_SAMPLES 10000
static struct { double ops; long samples; long *lat_arr; int lat_cnt; } g_int[8];
static struct { double ops; } g_cpu[8], g_bat[8];

static int cmp(const void *a, const void *b) {
    long va=*(long*)a, vb=*(long*)b;
    return va<vb?-1:va>vb?1:0;
}

static long now_us() { struct timeval tv; gettimeofday(&tv,NULL); return tv.tv_sec*1000000L+tv.tv_usec; }

static double pc(long *arr, int n, double p) {
    if (n==0) return 0;
    qsort(arr, n, sizeof(long), cmp);
    return arr[(int)(n * p / 100.0)];
}

static void *cpu_worker(void *arg) {
    int id=*(int*)arg; long ops=0,start=now_us();
    while(running){double x=1.0;for(int i=0;i<1000;i++)x=sin(x+0.1);ops++;}
    g_cpu[id].ops=ops*1e6/(now_us()-start);
    return NULL;
}

static void *int_worker(void *arg) {
    int id=*(int*)arg; long ops=0,start=now_us();
    g_int[id].lat_arr=(long*)malloc(MAX_LAT_SAMPLES*sizeof(long));
    while(running&&g_int[id].lat_cnt<MAX_LAT_SAMPLES){
        long t=now_us();usleep(cur->period_us);
        long lat=now_us()-t-cur->period_us;
        g_int[id].lat_arr[g_int[id].lat_cnt++]=lat;
        g_int[id].samples++;
        long ws=now_us();while(now_us()-ws<(long)cur->work_us);
        ops++;
    }
    g_int[id].ops=ops*1e6/(now_us()-start);
    return NULL;
}

static void *bat_worker(void *arg) {
    int id=*(int*)arg; long ops=0,start=now_us();
    while(running){double x=0;for(int i=0;i<5000;i++)x+=sin(i*0.01)*cos(i*0.03);if((ops&0x3F)==0)sched_yield();ops++;}
    g_bat[id].ops=ops*1e6/(now_us()-start);
    return NULL;
}

int main(int argc, char **argv) {
    int secs=10; char *profile="default";
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-p")&&i+1<argc)profile=argv[++i];
        else secs=atoi(argv[i]);
    }
    for(int i=0;i<5;i++) if(!strcmp(g_profiles[i].name,profile))cur=&g_profiles[i];

    fprintf(stderr,"Profile: %s | %dCPU+%dINT+%dBAT | %ds\n",cur->name,cur->cpu_w,cur->int_w,cur->bat_w,secs);

    pthread_t tc[8],ti[8],tb[8];int ids[8];
    for(int i=0;i<cur->cpu_w;i++){ids[i]=i;pthread_create(&tc[i],NULL,cpu_worker,&ids[i]);}
    for(int i=0;i<cur->int_w;i++){ids[i]=i;pthread_create(&ti[i],NULL,int_worker,&ids[i]);}
    for(int i=0;i<cur->bat_w;i++){ids[i]=i;pthread_create(&tb[i],NULL,bat_worker,&ids[i]);}
    sleep(secs);running=0;
    for(int i=0;i<cur->cpu_w;i++)pthread_join(tc[i],NULL);
    for(int i=0;i<cur->int_w;i++)pthread_join(ti[i],NULL);
    for(int i=0;i<cur->bat_w;i++)pthread_join(tb[i],NULL);

    double total_cpu=0,total_bat=0; long total_lats=0,total_cnt=0;
    printf("\n%-12s %12s %8s %8s %8s\n","Worker","Ops/sec","p50(us)","p95(us)","p99(us)");
    printf("──────────────────────────────────────────────────\n");
    for(int i=0;i<cur->cpu_w;i++){total_cpu+=g_cpu[i].ops;printf("%-12s %12.0f %8s %8s %8s\n","CPU-bound",g_cpu[i].ops,"-","-","-");}
    for(int i=0;i<cur->int_w;i++){
        double lats=0; for(int j=0;j<g_int[i].lat_cnt;j++)lats+=g_int[i].lat_arr[j];
        double avg=g_int[i].lat_cnt>0?lats/g_int[i].lat_cnt:0;
        double p50=pc(g_int[i].lat_arr,g_int[i].lat_cnt,50);
        double p95=pc(g_int[i].lat_arr,g_int[i].lat_cnt,95);
        double p99=pc(g_int[i].lat_arr,g_int[i].lat_cnt,99);
        total_lats+=avg;total_cnt++;
        printf("%-12s %12.0f %8.0f %8.0f %8.0f\n","Interactive",g_int[i].ops,p50,p95,p99);
        free(g_int[i].lat_arr);
    }
    for(int i=0;i<cur->bat_w;i++){total_bat+=g_bat[i].ops;printf("%-12s %12.0f %8s %8s %8s\n","Batch",g_bat[i].ops,"-","-","-");}
    printf("──────────────────────────────────────────────────\n");
    printf("TOTAL               %12.0f\n",total_cpu+total_bat);
    printf("\nInteractive avg latency: %.1f us\n",total_cnt>0?total_lats/total_cnt:0);
    printf("CPU-bound total ops/sec: %.0f\n",total_cpu);
    return 0;
}
