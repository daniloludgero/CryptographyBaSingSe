/* Compilar: gcc -O3 -mavx2 bench_core.c ../../implementacao/c_core/rsd_s_v5_ct.c [-lm] */
#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>
int rsd_s_v5_core_ct(const uint16_t*, const uint16_t*, const uint16_t*, int, int, uint16_t, uint16_t*);
static uint64_t ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC_RAW,&t);return (uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;}
static int cmp(const void*a,const void*b){double x=*(double*)a,y=*(double*)b;return (x>y)-(x<y);}
int main(int argc,char**argv){
  int rounds=argc>1?atoi(argv[1]):8; int iters=argc>2?atoi(argv[2]):20000; int reps=argc>3?atoi(argv[3]):21;
  uint16_t in[32],rk[(256)*32],rc[256],out[32]; uint64_t s=88172645463325252ull;
  #define RND() (s^=s<<13,s^=s>>7,s^=s<<17,(uint16_t)s)
  for(int i=0;i<32;i++)in[i]=RND(); for(int i=0;i<(rounds+1)*32;i++)rk[i]=RND(); for(int i=0;i<rounds;i++)rc[i]=RND();
  for(int i=0;i<2000;i++){int r=rsd_s_v5_core_ct(in,rk,rc,rounds,-1,0,out); if(r)return 2; in[0]^=out[0];}
  double us[64],cyc[64];
  // TSC freq
  uint64_t t0=ns(),c0=__rdtsc(); while(ns()-t0<200000000ull); double ghz=(double)(__rdtsc()-c0)/(double)(ns()-t0);
  volatile uint16_t sink=0;
  for(int k=0;k<reps;k++){uint64_t a=ns(),c=__rdtsc();
    for(int i=0;i<iters;i++){rsd_s_v5_core_ct(in,rk,rc,rounds,-1,0,out); in[0]^=out[0]; sink^=out[1];}
    uint64_t b=ns(),d=__rdtsc(); us[k]=(double)(b-a)/1000.0/iters; cyc[k]=(double)(d-c)/iters;}
  qsort(us,reps,sizeof(double),cmp); qsort(cyc,reps,sizeof(double),cmp);
  double med=us[reps/2],mn=us[0],p95=us[(int)(reps*0.95)>=reps?reps-1:(int)(reps*0.95)];
  printf("{\"rounds\":%d,\"iters\":%d,\"reps\":%d,\"tsc_ghz\":%.4f,\"us_median\":%.4f,\"us_min\":%.4f,\"us_p95\":%.4f,\"cyc_median\":%.0f,\"cpb_median\":%.2f,\"mib_s_median\":%.4f}\n",
    rounds,iters,reps,ghz,med,mn,p95,cyc[reps/2],cyc[reps/2]/64.0,64.0/med*1e6/1048576.0);
  return 0;}
