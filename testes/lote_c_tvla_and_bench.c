/*
 * lote_c_tvla_and_bench.c
 *
 * Harness reproduzível para o Lote C (Round 2 - BaSingSe):
 *   1. TVLA estendido (Welch's t-test, N >= 100.000 por grupo = 200.000 amostras)
 *      em rsd_s_v5_core_ct(), medindo ciclos (RDTSC/RDTSCP) e tempo (CLOCK_MONOTONIC_RAW).
 *      Inclui TVLA-A (entrada fixa vs aleatória, chave fixa) e TVLA-B (chave+entrada fixa vs aleatória).
 *   2. Benchmark real de throughput (MB/s, ciclos/byte, latência) para payloads de
 *      64B, 1KB, 64KB e 1MB comparando RSD-S v5 C99 vs OpenSSL AES-256-GCM e ChaCha20-Poly1305.
 */

#define _POSIX_C_SOURCE 200809L
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#define RSD_W 32
#define RSD_ROUNDS 8

/* Protótipo do núcleo C99 em implementacao/c_core/rsd_s_v5_ct.c */
int rsd_s_v5_core_ct(
    const uint16_t *in_state,
    const uint16_t *rk_flat,
    const uint16_t *rc,
    int rounds,
    int fault_word,
    uint16_t fault_mask,
    uint16_t *out_state
);

static volatile uint16_t g_sink16 = 0;
static volatile uint8_t g_sink8 = 0;

/* xorshift64* determinístico para geração de entradas fora da janela medida */
static uint64_t g_rng_state = 0x9E3779B97F4A7C15ULL;

static inline uint64_t xorshift64star(void) {
    uint64_t x = g_rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static inline uint64_t rdtsc_begin(void) {
    uint32_t lo, hi;
    __asm__ __volatile__(
        "lfence\n\t"
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void) {
    uint32_t lo, hi, aux;
    __asm__ __volatile__(
        "rdtscp\n\t"
        "lfence\n\t"
        : "=a"(lo), "=d"(hi), "=c"(aux)
        :
        : "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

typedef struct {
    double mean;
    double std;
    double welch_t_raw;
    double welch_t_p99;
    uint64_t min;
    uint64_t p50;
    uint64_t p95;
    uint64_t p99;
    uint64_t max;
} tvla_stats_t;

static void compute_stats_and_t(
    const uint64_t *g0, size_t n0,
    const uint64_t *g1, size_t n1,
    tvla_stats_t *s0, tvla_stats_t *s1
) {
    uint64_t *c0 = (uint64_t *)malloc(n0 * sizeof(uint64_t));
    uint64_t *c1 = (uint64_t *)malloc(n1 * sizeof(uint64_t));
    memcpy(c0, g0, n0 * sizeof(uint64_t));
    memcpy(c1, g1, n1 * sizeof(uint64_t));
    qsort(c0, n0, sizeof(uint64_t), cmp_u64);
    qsort(c1, n1, sizeof(uint64_t), cmp_u64);

    double sum0 = 0.0, sum1 = 0.0;
    for (size_t i = 0; i < n0; ++i) sum0 += (double)c0[i];
    for (size_t i = 0; i < n1; ++i) sum1 += (double)c1[i];
    double m0 = sum0 / (double)n0;
    double m1 = sum1 / (double)n1;

    double var0 = 0.0, var1 = 0.0;
    for (size_t i = 0; i < n0; ++i) {
        double d = (double)c0[i] - m0;
        var0 += d * d;
    }
    for (size_t i = 0; i < n1; ++i) {
        double d = (double)c1[i] - m1;
        var1 += d * d;
    }
    var0 /= (double)(n0 - 1);
    var1 /= (double)(n1 - 1);

    double denom_raw = sqrt(var0 / (double)n0 + var1 / (double)n1);
    double t_raw = (denom_raw > 0.0) ? (m0 - m1) / denom_raw : 0.0;

    /* p99-trimmed (remove top 1% OS-interrupt outliers) */
    size_t k0 = (size_t)(0.99 * (double)n0);
    size_t k1 = (size_t)(0.99 * (double)n1);
    double tsum0 = 0.0, tsum1 = 0.0;
    for (size_t i = 0; i < k0; ++i) tsum0 += (double)c0[i];
    for (size_t i = 0; i < k1; ++i) tsum1 += (double)c1[i];
    double tm0 = tsum0 / (double)k0;
    double tm1 = tsum1 / (double)k1;
    double tvar0 = 0.0, tvar1 = 0.0;
    for (size_t i = 0; i < k0; ++i) {
        double d = (double)c0[i] - tm0;
        tvar0 += d * d;
    }
    for (size_t i = 0; i < k1; ++i) {
        double d = (double)c1[i] - tm1;
        tvar1 += d * d;
    }
    tvar0 /= (double)(k0 - 1);
    tvar1 /= (double)(k1 - 1);
    double denom_p99 = sqrt(tvar0 / (double)k0 + tvar1 / (double)k1);
    double t_p99 = (denom_p99 > 0.0) ? (tm0 - tm1) / denom_p99 : 0.0;

    s0->mean = m0; s0->std = sqrt(var0);
    s0->welch_t_raw = t_raw; s0->welch_t_p99 = t_p99;
    s0->min = c0[0]; s0->p50 = c0[n0 / 2];
    s0->p95 = c0[(size_t)(0.95 * (double)n0)];
    s0->p99 = c0[(size_t)(0.99 * (double)n0)];
    s0->max = c0[n0 - 1];

    s1->mean = m1; s1->std = sqrt(var1);
    s1->welch_t_raw = t_raw; s1->welch_t_p99 = t_p99;
    s1->min = c1[0]; s1->p50 = c1[n1 / 2];
    s1->p95 = c1[(size_t)(0.95 * (double)n1)];
    s1->p99 = c1[(size_t)(0.99 * (double)n1)];
    s1->max = c1[n1 - 1];

    free(c0);
    free(c1);
}

static void fill_random_u16(uint16_t *buf, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        buf[i] = (uint16_t)(xorshift64star() & 0xFFFFu);
    }
}

static void run_tvla_suite(size_t n_per_group, const char *opt_label) {
    uint16_t in_fixed[RSD_W];
    uint16_t rk_fixed[(RSD_ROUNDS + 1) * RSD_W];
    uint16_t rc_fixed[RSD_ROUNDS];
    uint16_t in_cur[RSD_W];
    uint16_t rk_cur[(RSD_ROUNDS + 1) * RSD_W];
    uint16_t rc_cur[RSD_ROUNDS];
    uint16_t out_state[RSD_W];

    for (int i = 0; i < RSD_W; ++i) in_fixed[i] = (uint16_t)(0xA55Au ^ (uint16_t)(i * 0x1337u));
    for (int i = 0; i < (RSD_ROUNDS + 1) * RSD_W; ++i) rk_fixed[i] = (uint16_t)(0x5A01u + (uint16_t)(i * 0x0103u));
    for (int i = 0; i < RSD_ROUNDS; ++i) rc_fixed[i] = (uint16_t)(0x2468u + (uint16_t)(i * 0x1111u));

    /* Warmup */
    for (int i = 0; i < 2000; ++i) {
        rsd_s_v5_core_ct(in_fixed, rk_fixed, rc_fixed, RSD_ROUNDS, -1, 0, out_state);
        g_sink16 ^= out_state[0];
    }

    uint64_t *cyc_g0 = (uint64_t *)malloc(n_per_group * sizeof(uint64_t));
    uint64_t *cyc_g1 = (uint64_t *)malloc(n_per_group * sizeof(uint64_t));
    uint64_t *ns_g0 = (uint64_t *)malloc(n_per_group * sizeof(uint64_t));
    uint64_t *ns_g1 = (uint64_t *)malloc(n_per_group * sizeof(uint64_t));

    /* TVLA-A: Fixed-vs-Random Input (Fixed Key) */
    size_t rem0 = n_per_group, rem1 = n_per_group;
    size_t idx0 = 0, idx1 = 0;
    while (rem0 > 0 || rem1 > 0) {
        uint64_t r = xorshift64star() % (rem0 + rem1);
        int group = (r < rem0) ? 0 : 1;
        if (group == 0) {
            memcpy(in_cur, in_fixed, sizeof(in_fixed));
        } else {
            fill_random_u16(in_cur, RSD_W);
        }
        uint64_t t0_ns = now_ns();
        uint64_t t0_c = rdtsc_begin();
        int rc = rsd_s_v5_core_ct(in_cur, rk_fixed, rc_fixed, RSD_ROUNDS, -1, 0, out_state);
        uint64_t t1_c = rdtsc_end();
        uint64_t t1_ns = now_ns();
        g_sink16 ^= (uint16_t)(out_state[0] ^ (uint16_t)rc);

        if (group == 0) {
            cyc_g0[idx0] = t1_c - t0_c;
            ns_g0[idx0] = t1_ns - t0_ns;
            idx0++;
            rem0--;
        } else {
            cyc_g1[idx1] = t1_c - t0_c;
            ns_g1[idx1] = t1_ns - t0_ns;
            idx1++;
            rem1--;
        }
    }

    tvla_stats_t a_c0, a_c1, a_n0, a_n1;
    compute_stats_and_t(cyc_g0, n_per_group, cyc_g1, n_per_group, &a_c0, &a_c1);
    compute_stats_and_t(ns_g0, n_per_group, ns_g1, n_per_group, &a_n0, &a_n1);

    /* TVLA-B: Fixed-vs-Random Key & Input */
    rem0 = n_per_group; rem1 = n_per_group;
    idx0 = 0; idx1 = 0;
    while (rem0 > 0 || rem1 > 0) {
        uint64_t r = xorshift64star() % (rem0 + rem1);
        int group = (r < rem0) ? 0 : 1;
        if (group == 0) {
            memcpy(in_cur, in_fixed, sizeof(in_fixed));
            memcpy(rk_cur, rk_fixed, sizeof(rk_fixed));
            memcpy(rc_cur, rc_fixed, sizeof(rc_fixed));
        } else {
            fill_random_u16(in_cur, RSD_W);
            fill_random_u16(rk_cur, (RSD_ROUNDS + 1) * RSD_W);
            fill_random_u16(rc_cur, RSD_ROUNDS);
        }
        uint64_t t0_ns = now_ns();
        uint64_t t0_c = rdtsc_begin();
        int rc = rsd_s_v5_core_ct(in_cur, rk_cur, rc_cur, RSD_ROUNDS, -1, 0, out_state);
        uint64_t t1_c = rdtsc_end();
        uint64_t t1_ns = now_ns();
        g_sink16 ^= (uint16_t)(out_state[0] ^ (uint16_t)rc);

        if (group == 0) {
            cyc_g0[idx0] = t1_c - t0_c;
            ns_g0[idx0] = t1_ns - t0_ns;
            idx0++;
            rem0--;
        } else {
            cyc_g1[idx1] = t1_c - t0_c;
            ns_g1[idx1] = t1_ns - t0_ns;
            idx1++;
            rem1--;
        }
    }

    tvla_stats_t b_c0, b_c1, b_n0, b_n1;
    compute_stats_and_t(cyc_g0, n_per_group, cyc_g1, n_per_group, &b_c0, &b_c1);
    compute_stats_and_t(ns_g0, n_per_group, ns_g1, n_per_group, &b_n0, &b_n1);

    printf("{\n");
    printf("  \"opt_level\": \"%s\",\n", opt_label);
    printf("  \"n_per_group\": %zu,\n", n_per_group);
    printf("  \"total_samples_per_test\": %zu,\n", n_per_group * 2);
    printf("  \"tvla_a_fixed_vs_random_input\": {\n");
    printf("    \"cycles\": {\"fixed_mean\": %.2f, \"fixed_std\": %.2f, \"fixed_p50\": %llu, \"fixed_p99\": %llu, \"random_mean\": %.2f, \"random_std\": %.2f, \"random_p50\": %llu, \"random_p99\": %llu, \"abs_t_raw\": %.4f, \"abs_t_p99_trimmed\": %.4f},\n",
        a_c0.mean, a_c0.std, (unsigned long long)a_c0.p50, (unsigned long long)a_c0.p99,
        a_c1.mean, a_c1.std, (unsigned long long)a_c1.p50, (unsigned long long)a_c1.p99,
        fabs(a_c0.welch_t_raw), fabs(a_c0.welch_t_p99));
    printf("    \"ns\": {\"fixed_mean\": %.2f, \"fixed_std\": %.2f, \"fixed_p50\": %llu, \"fixed_p99\": %llu, \"random_mean\": %.2f, \"random_std\": %.2f, \"random_p50\": %llu, \"random_p99\": %llu, \"abs_t_raw\": %.4f, \"abs_t_p99_trimmed\": %.4f}\n",
        a_n0.mean, a_n0.std, (unsigned long long)a_n0.p50, (unsigned long long)a_n0.p99,
        a_n1.mean, a_n1.std, (unsigned long long)a_n1.p50, (unsigned long long)a_n1.p99,
        fabs(a_n0.welch_t_raw), fabs(a_n0.welch_t_p99));
    printf("  },\n");
    printf("  \"tvla_b_fixed_vs_random_key_and_input\": {\n");
    printf("    \"cycles\": {\"fixed_mean\": %.2f, \"fixed_std\": %.2f, \"fixed_p50\": %llu, \"fixed_p99\": %llu, \"random_mean\": %.2f, \"random_std\": %.2f, \"random_p50\": %llu, \"random_p99\": %llu, \"abs_t_raw\": %.4f, \"abs_t_p99_trimmed\": %.4f},\n",
        b_c0.mean, b_c0.std, (unsigned long long)b_c0.p50, (unsigned long long)b_c0.p99,
        b_c1.mean, b_c1.std, (unsigned long long)b_c1.p50, (unsigned long long)b_c1.p99,
        fabs(b_c0.welch_t_raw), fabs(b_c0.welch_t_p99));
    printf("    \"ns\": {\"fixed_mean\": %.2f, \"fixed_std\": %.2f, \"fixed_p50\": %llu, \"fixed_p99\": %llu, \"random_mean\": %.2f, \"random_std\": %.2f, \"random_p50\": %llu, \"random_p99\": %llu, \"abs_t_raw\": %.4f, \"abs_t_p99_trimmed\": %.4f}\n",
        b_n0.mean, b_n0.std, (unsigned long long)b_n0.p50, (unsigned long long)b_n0.p99,
        b_n1.mean, b_n1.std, (unsigned long long)b_n1.p50, (unsigned long long)b_n1.p99,
        fabs(b_n0.welch_t_raw), fabs(b_n0.welch_t_p99));
    printf("  }\n");
    printf("}\n");

    free(cyc_g0); free(cyc_g1);
    free(ns_g0); free(ns_g1);
}

static void bench_evp_aead(
    const EVP_CIPHER *cipher,
    const char *name,
    size_t payload_bytes,
    int iters,
    double *out_mbps,
    double *out_cpb,
    double *out_us_per_op
) {
    uint8_t key[32];
    uint8_t iv[12];
    uint8_t tag[16];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; ++i) iv[i] = (uint8_t)(i + 1);

    uint8_t *pt = (uint8_t *)malloc(payload_bytes);
    uint8_t *ct = (uint8_t *)malloc(payload_bytes + 32);
    memset(pt, 0xAB, payload_bytes);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    /* Warmup */
    for (int w = 0; w < 5; ++w) {
        int outl = 0, tmpl = 0;
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
        EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)payload_bytes);
        EVP_EncryptFinal_ex(ctx, ct + outl, &tmpl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        g_sink8 ^= ct[0] ^ tag[0];
    }

    uint64_t t0_ns = now_ns();
    uint64_t t0_c = rdtsc_begin();
    for (int it = 0; it < iters; ++it) {
        int outl = 0, tmpl = 0;
        iv[0] = (uint8_t)(it & 0xFF);
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
        EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)payload_bytes);
        EVP_EncryptFinal_ex(ctx, ct + outl, &tmpl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        g_sink8 ^= ct[0] ^ tag[0];
    }
    uint64_t t1_c = rdtsc_end();
    uint64_t t1_ns = now_ns();

    double total_bytes = (double)payload_bytes * (double)iters;
    double elapsed_s = (double)(t1_ns - t0_ns) / 1e9;
    *out_mbps = (total_bytes / (1024.0 * 1024.0)) / elapsed_s;
    *out_cpb = (double)(t1_c - t0_c) / total_bytes;
    *out_us_per_op = ((double)(t1_ns - t0_ns) / 1000.0) / (double)iters;

    EVP_CIPHER_CTX_free(ctx);
    free(pt);
    free(ct);
    (void)name;
}

static void bench_rsd_c99(
    size_t payload_bytes,
    int iters,
    double *out_mbps,
    double *out_cpb,
    double *out_us_per_op
) {
    uint16_t in_state[RSD_W];
    uint16_t rk_flat[(RSD_ROUNDS + 1) * RSD_W];
    uint16_t rc[RSD_ROUNDS];
    uint16_t out_state[RSD_W];
    for (int i = 0; i < RSD_W; ++i) in_state[i] = (uint16_t)i;
    for (int i = 0; i < (RSD_ROUNDS + 1) * RSD_W; ++i) rk_flat[i] = (uint16_t)(i * 3 + 1);
    for (int i = 0; i < RSD_ROUNDS; ++i) rc[i] = (uint16_t)(0x1234 + i);

    size_t blocks = (payload_bytes + 63) / 64;

    /* Warmup */
    for (int w = 0; w < 20; ++w) {
        rsd_s_v5_core_ct(in_state, rk_flat, rc, RSD_ROUNDS, -1, 0, out_state);
        g_sink16 ^= out_state[0];
    }

    uint64_t t0_ns = now_ns();
    uint64_t t0_c = rdtsc_begin();
    for (int it = 0; it < iters; ++it) {
        for (size_t b = 0; b < blocks; ++b) {
            in_state[0] = (uint16_t)(b & 0xFFFFu);
            rsd_s_v5_core_ct(in_state, rk_flat, rc, RSD_ROUNDS, -1, 0, out_state);
            g_sink16 ^= out_state[0];
        }
    }
    uint64_t t1_c = rdtsc_end();
    uint64_t t1_ns = now_ns();

    double total_bytes = (double)payload_bytes * (double)iters;
    double elapsed_s = (double)(t1_ns - t0_ns) / 1e9;
    *out_mbps = (total_bytes / (1024.0 * 1024.0)) / elapsed_s;
    *out_cpb = (double)(t1_c - t0_c) / total_bytes;
    *out_us_per_op = ((double)(t1_ns - t0_ns) / 1000.0) / (double)iters;
}

static void run_bench_suite(const char *opt_label) {
    const size_t sizes[4] = {64, 1024, 65536, 1048576};
    const char *labels[4] = {"64B", "1KB", "64KB", "1MB"};
    const int rsd_iters[4] = {5000, 500, 10, 2};
    const int evp_iters[4] = {200000, 50000, 5000, 500};

    printf("{\n");
    printf("  \"opt_level\": \"%s\",\n", opt_label);
    printf("  \"payloads\": {\n");
    for (int i = 0; i < 4; ++i) {
        double r_mbps, r_cpb, r_us;
        double a_mbps, a_cpb, a_us;
        double c_mbps, c_cpb, c_us;

        bench_rsd_c99(sizes[i], rsd_iters[i], &r_mbps, &r_cpb, &r_us);
        bench_evp_aead(EVP_aes_256_gcm(), "AES-256-GCM", sizes[i], evp_iters[i], &a_mbps, &a_cpb, &a_us);
        bench_evp_aead(EVP_chacha20_poly1305(), "ChaCha20-Poly1305", sizes[i], evp_iters[i], &c_mbps, &c_cpb, &c_us);

        printf("    \"%s\": {\n", labels[i]);
        printf("      \"bytes\": %zu,\n", sizes[i]);
        printf("      \"rsd_s_v5_c99\": {\"mib_s\": %.4f, \"cycles_per_byte\": %.2f, \"latency_us\": %.3f},\n", r_mbps, r_cpb, r_us);
        printf("      \"openssl_aes_256_gcm\": {\"mib_s\": %.4f, \"cycles_per_byte\": %.2f, \"latency_us\": %.3f},\n", a_mbps, a_cpb, a_us);
        printf("      \"openssl_chacha20_poly1305\": {\"mib_s\": %.4f, \"cycles_per_byte\": %.2f, \"latency_us\": %.3f},\n", c_mbps, c_cpb, c_us);
        printf("      \"latency_ratio_vs_aes_gcm\": %.2f,\n", r_us / a_us);
        printf("      \"latency_ratio_vs_chacha20\": %.2f\n", r_us / c_us);
        printf("    }%s\n", (i < 3) ? "," : "");
    }
    printf("  }\n");
    printf("}\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s --tvla <n_per_group> <opt_label> | --bench <opt_label>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--tvla") == 0) {
        size_t n = (size_t)atoll(argv[2]);
        const char *opt = (argc >= 4) ? argv[3] : "unknown";
        run_tvla_suite(n, opt);
    } else if (strcmp(argv[1], "--bench") == 0) {
        const char *opt = argv[2];
        run_bench_suite(opt);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
