#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

typedef struct { const char *name; int cpu_w; int int_w; int bat_w; int period_us; int work_us; } profile_t;

static profile_t g_profiles[] = {
    {"web",    2, 6, 0,  2000,  50},   /* many interactive, few CPU */
    {"db",     3, 3, 2,  5000, 200},   /* balanced + batch */
    {"batch",  4, 1, 3, 20000, 500},   /* heavy batch + CPU, one interactive */
    {"mixed",  4, 2, 2,  5000, 200},   /* everything mixed */
    {"default",4, 2, 2,  2000, 100},   /* original */
};

static profile_t *cur = &g_profiles[4];
static volatile int running = 1;
static struct { double ops, avg_lat, max_lat; long samples; } g_cpu[8], g_int[8], g_bat[8];
static long g_lat_hist[8][11];

static long now_us(void) { struct timeval tv; gettimeofday(&tv,NULL); return tv.tv_sec*1000000L+tv.tv_usec; }

static void record_lat(int id, long lat) {
    g_int[id].samples++; g_int[id].avg_lat += lat;
    if (lat > g_int[id].max_lat) g_int[id].max_lat = lat;
    int b=0;
    if (lat>=10000)b=10; else if(lat>=5000)b=9; else if(lat>=2000)b=8;
    else if(lat>=1000)b=7; else if(lat>=500)b=6; else if(lat>=200)b=5;
    else if(lat>=100)b=4; else if(lat>=50)b=3; else if(lat>=20)b=2;
    else if(lat>=10)b=1;
    g_lat_hist[id][b]++;
}

static void *cpu_worker(void *arg) {
    int id = *(int*)arg; long ops=0, start=now_us();
    while(running) { double x=1.0; for(int i=0;i<1000;i++)x=sin(x+0.1); ops++; if(x<-99)puts("!"); }
    g_cpu[id].ops = ops*1e6/(now_us()-start);
    return NULL;
}

static void *int_worker(void *arg) {
    int id = *(int*)arg; long ops=0, start=now_us();
    while(running) {
        long t = now_us();
        usleep(cur->period_us);
        record_lat(id, now_us()-t-cur->period_us);
        long ws = now_us(); while(now_us()-ws < (long)cur->work_us);
        ops++;
    }
    g_int[id].ops = ops*1e6/(now_us()-start);
    g_int[id].avg_lat = g_int[id].samples>0 ? g_int[id].avg_lat/g_int[id].samples : 0;
    return NULL;
}

static void *bat_worker(void *arg) {
    int id = *(int*)arg; long ops=0, start=now_us();
    while(running) { double x=0; for(int i=0;i<5000;i++)x+=sin(i*0.01)*cos(i*0.03); if((ops&0x3F)==0)sched_yield(); ops++; }
    g_bat[id].ops = ops*1e6/(now_us()-start);
    return NULL;
}

int main(int argc, char **argv) {
    int secs=10; char *profile="default";
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"-p")&&i+1<argc) profile=argv[++i];
        else secs=atoi(argv[i]);
    }
    for(int i=0;i<5;i++) if(!strcmp(g_profiles[i].name,profile)) cur=&g_profiles[i];

    fprintf(stderr,"Profile: %s | %dCPU+%dINT+%dBAT | %ds\n",cur->name,cur->cpu_w,cur->int_w,cur->bat_w,secs);

    pthread_t tc[8],ti[8],tb[8]; int ids[8];
    for(int i=0;i<cur->cpu_w;i++){ids[i]=i;pthread_create(&tc[i],NULL,cpu_worker,&ids[i]);}
    for(int i=0;i<cur->int_w;i++){ids[i]=i;pthread_create(&ti[i],NULL,int_worker,&ids[i]);}
    for(int i=0;i<cur->bat_w;i++){ids[i]=i;pthread_create(&tb[i],NULL,bat_worker,&ids[i]);}
    sleep(secs); running=0;
    for(int i=0;i<cur->cpu_w;i++)pthread_join(tc[i],NULL);
    for(int i=0;i<cur->int_w;i++)pthread_join(ti[i],NULL);
    for(int i=0;i<cur->bat_w;i++)pthread_join(tb[i],NULL);

    printf("\n%-12s %12s %12s %12s\n","Worker","Ops/sec","AvgLat(us)","MaxLat(us)");
    printf("──────────────────────────────────────────────────\n");
    double total_cpu=0,total_bat=0,total_lat=0; int lats=0;
    for(int i=0;i<cur->cpu_w;i++){ total_cpu+=g_cpu[i].ops; printf("%-12s %12.0f %12s %12s\n","CPU-bound",g_cpu[i].ops,"-","-"); }
    for(int i=0;i<cur->int_w;i++){ total_lat+=g_int[i].avg_lat; lats++;
        double max=0; for(int j=10;j>=0;j--)if(g_lat_hist[i][j]>0){max=j==10?10000.0:(double)(1<<(j+1))*10;break;}
        printf("%-12s %12.0f %12.1f %12.1f\n","Interactive",g_int[i].ops,g_int[i].avg_lat,max);
    }
    for(int i=0;i<cur->bat_w;i++){ total_bat+=g_bat[i].ops; printf("%-12s %12.0f %12s %12s\n","Batch",g_bat[i].ops,"-","-"); }
    printf("──────────────────────────────────────────────────\n");
    printf("TOTAL               %12.0f\n",total_cpu+total_bat);
    printf("\nInteractive avg latency: %.1f us\n",lats>0?total_lat/lats:0);
    printf("CPU-bound total ops/sec: %.0f\n",total_cpu);
    return 0;
}
