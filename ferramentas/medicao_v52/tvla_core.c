/* Compilar: gcc -O3 -mavx2 tvla_core.c ../../implementacao/c_core/rsd_s_v5_ct.c [-lm] */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <x86intrin.h>
int rsd_s_v5_core_ct(const uint16_t*, const uint16_t*, const uint16_t*, int, int, uint16_t, uint16_t*);
static uint64_t s=0x9E3779B97F4A7C15ull;
static uint64_t rnd(void){s^=s<<13;s^=s>>7;s^=s<<17;return s;}
typedef struct{double n,m,M2;}W;
static void add(W*w,double x){w->n++;double d=x-w->m;w->m+=d/w->n;w->M2+=d*(x-w->m);}
static double tstat(W*a,W*b){return (a->m-b->m)/sqrt(a->M2/(a->n-1)/a->n+b->M2/(b->n-1)/b->n);}
static int cmpd(const void*a,const void*b){double x=*(double*)a,y=*(double*)b;return (x>y)-(x<y);}
static uint64_t meas(const uint16_t*in,const uint16_t*rk,const uint16_t*rc,uint16_t*out){
  unsigned aux; _mm_lfence(); uint64_t a=__rdtscp(&aux); _mm_lfence();
  rsd_s_v5_core_ct(in,rk,rc,8,-1,0,out);
  _mm_lfence(); uint64_t b=__rdtscp(&aux); _mm_lfence(); return b-a;}
int main(int argc,char**argv){
  int N=atoi(argv[1]); int mode=atoi(argv[2]); /*0 fixo/aleatorio 1 zeros/uns 2 controle aleatorio/aleatorio*/
  uint16_t rk[9*32],rc[8],out[32],A[32],B[32],in[32];
  for(int i=0;i<9*32;i++)rk[i]=(uint16_t)rnd(); for(int i=0;i<8;i++)rc[i]=(uint16_t)rnd();
  for(int i=0;i<32;i++){A[i]=(mode==1)?0:0x1234+i; B[i]=0xFFFF;}
  for(int i=0;i<3000;i++){for(int j=0;j<32;j++)in[j]=(uint16_t)rnd(); meas(in,rk,rc,out);}
  double *t0=malloc(sizeof(double)*N),*t1=malloc(sizeof(double)*N); int n0=0,n1=0;
  while(n0<N||n1<N){
    int g=rnd()&1; if(g&&n1>=N)g=0; if(!g&&n0>=N)g=1;
    for(int j=0;j<32;j++){ if(mode==0) in[j]= g?(uint16_t)rnd():A[j]; else if(mode==1) in[j]= g?B[j]:A[j]; else in[j]=(uint16_t)rnd(); }
    double c=(double)meas(in,rk,rc,out);
    if(g)t1[n1++]=c; else t0[n0++]=c; }
  W a={0,0,0},b={0,0,0}; for(int i=0;i<N;i++){add(&a,t0[i]);add(&b,t1[i]);}
  double traw=tstat(&a,&b);
  /* recorte: descarta 1% superior de cada grupo (padrão TVLA para ruído de interrupções) */
  qsort(t0,N,sizeof(double),cmpd);qsort(t1,N,sizeof(double),cmpd);
  W ac={0,0,0},bc={0,0,0}; int K=(int)(N*0.99); for(int i=0;i<K;i++){add(&ac,t0[i]);add(&bc,t1[i]);}
  double tcrop=tstat(&ac,&bc);
  printf("{\"mode\":%d,\"t_assinado_bruto\":%.4f,\"N_por_grupo\":%d,\"abs_t_bruto\":%.4f,\"abs_t_recorte_1pct\":%.4f,\"media_ciclos_g0\":%.1f,\"media_ciclos_g1\":%.1f}\n",mode,traw,N,fabs(traw),fabs(tcrop),a.m,b.m);
  return 0;}
