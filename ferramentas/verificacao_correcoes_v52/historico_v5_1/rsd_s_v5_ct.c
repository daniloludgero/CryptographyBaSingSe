/*
 * rsd_s_v5_ct.c
 *
 * Núcleo criptográfico RSD-S v5.1 em C99 estritamente CONSTANT-TIME, TABLE-FREE
 * e com aceleração SIMD (AVX2 / Bitsliced Paralelo em GF(2^16)).
 *
 * Remediações implementadas (Rodada 1 + Rodada 2 / Lotes A, B, C, D):
 *   - VULN-02 (TVLA): zero ramificações dependentes de dados secretos (branchless).
 *   - VULN-03 (Cache L1): zero tabelas LUT dependentes de segredo; inversão em GF(2^16)
 *     via cadeia de adição de Itoh-Tsujii (15 quadrados + 5 multiplicações).
 *   - VULN-04 (Algébrico): transformação afim F_2-linear A_16 + constante 0x63A9.
 *   - VULN-01 (DFA): execução redundante da rodada final com comparação constant-time;
 *     qualquer divergência limpa buffers e retorna -2 (FAULT_DETECTED).
 *   - VULN-05 (Memória): limpeza segura via barreira volatile (secure_wipe).
 *   - LOTE-B (Invariante M^2 = 0x5E26*I): permutação assimétrica de colunas
 *     p(j) = (5*j + 1) mod 32 na matriz Cauchy MDS 32x32, preservando Branch Number 33
 *     e tornando 100% das 992 posições fora da diagonal de M^2 não-nulas.
 *   - LOTE-C (Throughput): pré-cálculo das matrizes binárias de multiplicação no corpo
 *     e redução de grau constante + vetorização SIMD AVX2 (-mavx2) nas 32 S-boxes
 *     paralelas em Itoh-Tsujii.
 *
 * Compilação recomendada (Linux):
 *   gcc -O3 -mavx2 -Wall -Wextra -Werror -shared -fPIC rsd_s_v5_ct.c -o lib_rsd_s_v5.so
 */

#include <stddef.h>
#include <stdint.h>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

#define RSD_W 32
#define GF16_POLY 0x1100Bu
#define AFFINE_CONST_V5 0x63A9u

/* Limpeza segura resistente a eliminação de código morto (DCE) pelo compilador. */
static void secure_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0u;
    }
}

/* Multiplicação 100% constant-time escalar em GF(2^16) mod 0x1100B (laço fixo, sem if). */
static inline uint16_t gf16_mul_ct(uint16_t a, uint16_t b) {
    uint32_t aa = (uint32_t)a;
    uint32_t bb = (uint32_t)b;
    uint32_t res = 0u;
    for (int i = 0; i < 16; ++i) {
        uint32_t mask = (uint32_t)(-(int32_t)(bb & 1u));
        res ^= (aa & mask);
        uint32_t hi = (uint32_t)(-(int32_t)((aa >> 15) & 1u));
        aa = ((aa << 1) ^ (GF16_POLY & hi)) & 0xFFFFu;
        bb >>= 1;
    }
    return (uint16_t)(res & 0xFFFFu);
}

#if defined(__AVX2__)
/*
 * Multiplicação SIMD AVX2 constant-time de 16 palavras uint16_t em paralelo em GF(2^16).
 * Processa metade do estado (16 palavras = 256 bits) por instrução vetorial, sem LUT em memória.
 */
static inline __m256i gf16_mul_avx2(__m256i a, __m256i b) {
    const __m256i one = _mm256_set1_epi16(1);
    const __m256i zero = _mm256_setzero_si256();
    const __m256i poly = _mm256_set1_epi16((short)0x100B);
    __m256i res = zero;

    for (int i = 0; i < 16; ++i) {
        __m256i lsb = _mm256_and_si256(b, one);
        __m256i mask = _mm256_cmpeq_epi16(lsb, one);
        res = _mm256_xor_si256(res, _mm256_and_si256(a, mask));

        /* Carry do bit 15 via comparação com sinal < 0 */
        __m256i hi_mask = _mm256_cmpgt_epi16(zero, a);
        a = _mm256_xor_si256(_mm256_slli_epi16(a, 1), _mm256_and_si256(poly, hi_mask));
        b = _mm256_srli_epi16(b, 1);
    }
    return res;
}

static inline __m256i gf16_sq_avx2(__m256i a) {
    return gf16_mul_avx2(a, a);
}

static inline __m256i gf16_sqn_avx2(__m256i a, int n) {
    for (int i = 0; i < n; ++i) {
        a = gf16_sq_avx2(a);
    }
    return a;
}

static inline __m256i rotl16_avx2(__m256i x, int k) {
    return _mm256_or_si256(_mm256_slli_epi16(x, k), _mm256_srli_epi16(x, 16 - k));
}

/* Avalia 16 S-boxes v5.1 em paralelo via AVX2 (Itoh-Tsujii + A_16 + 0x63A9). */
static inline __m256i sbox_v5_avx2(__m256i x) {
    __m256i a2  = gf16_mul_avx2(gf16_sq_avx2(x), x);
    __m256i a3  = gf16_mul_avx2(gf16_sq_avx2(a2), x);
    __m256i a6  = gf16_mul_avx2(gf16_sqn_avx2(a3, 3), a3);
    __m256i a7  = gf16_mul_avx2(gf16_sq_avx2(a6), x);
    __m256i a14 = gf16_mul_avx2(gf16_sqn_avx2(a7, 7), a7);
    __m256i a15 = gf16_mul_avx2(gf16_sq_avx2(a14), x);
    __m256i v   = gf16_sq_avx2(a15);

    __m256i aff = v;
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 1));
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 2));
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 3));
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 4));
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 5));
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 7));
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 11));
    aff = _mm256_xor_si256(aff, rotl16_avx2(v, 13));
    return _mm256_xor_si256(aff, _mm256_set1_epi16((short)AFFINE_CONST_V5));
}
#endif

static inline uint16_t gf16_sq_ct(uint16_t a) {
    return gf16_mul_ct(a, a);
}

static inline uint16_t gf16_sqn_ct(uint16_t a, int n) {
    for (int i = 0; i < n; ++i) {
        a = gf16_sq_ct(a);
    }
    return a;
}

static inline uint16_t gf16_inv_ct(uint16_t x) {
    uint16_t a2  = gf16_mul_ct(gf16_sq_ct(x), x);
    uint16_t a3  = gf16_mul_ct(gf16_sq_ct(a2), x);
    uint16_t a6  = gf16_mul_ct(gf16_sqn_ct(a3, 3), a3);
    uint16_t a7  = gf16_mul_ct(gf16_sq_ct(a6), x);
    uint16_t a14 = gf16_mul_ct(gf16_sqn_ct(a7, 7), a7);
    uint16_t a15 = gf16_mul_ct(gf16_sq_ct(a14), x);
    return gf16_sq_ct(a15);
}

static inline uint16_t rotl16(uint16_t x, unsigned int k) {
    return (uint16_t)(((uint32_t)x << k) | ((uint32_t)x >> (16u - k)));
}

static inline uint16_t sbox_v5_ct(uint16_t u) {
    uint16_t v = gf16_inv_ct(u);
    uint16_t aff = v
        ^ rotl16(v, 1u)
        ^ rotl16(v, 2u)
        ^ rotl16(v, 3u)
        ^ rotl16(v, 4u)
        ^ rotl16(v, 5u)
        ^ rotl16(v, 7u)
        ^ rotl16(v, 11u)
        ^ rotl16(v, 13u);
    return (uint16_t)(aff ^ AFFINE_CONST_V5);
}

/*
 * Matriz pública Cauchy MDS 32x32 com permutação assimétrica de colunas
 * p(j) = (5*j + 1) mod 32 (quebra M^2 = 0x5E26*I descoberta no Lote B) +
 * Tabela pública de base de bits CAUCHY_BIT_BASIS[j][bit][i] para multiplicação
 * MDS vetorial em 16 passos (em vez de 32*32*16 = 16.384 passos escalares).
 *
 * Nota de Segurança de Cache: CAUCHY_BIT_BASIS é indexada APENAS pelas variáveis
 * de loop públicas (j = 0..31, bit = 0..15), NUNCA por valores secretos!
 */
static uint16_t CAUCHY_MDS[RSD_W][RSD_W];
static uint16_t CAUCHY_BIT_BASIS[RSD_W][16][RSD_W] __attribute__((aligned(32)));
static int CAUCHY_INIT = 0;

static void init_cauchy_mds(void) {
    if (CAUCHY_INIT) {
        return;
    }
    for (int i = 0; i < RSD_W; ++i) {
        for (int j = 0; j < RSD_W; ++j) {
            int perm_j = (5 * j + 1) % RSD_W;
            uint16_t denom = (uint16_t)(i ^ (RSD_W + perm_j));
            CAUCHY_MDS[i][j] = gf16_inv_ct(denom);
        }
    }
    for (int j = 0; j < RSD_W; ++j) {
        for (int bit = 0; bit < 16; ++bit) {
            uint16_t basis_val = (uint16_t)(1u << bit);
            for (int i = 0; i < RSD_W; ++i) {
                CAUCHY_BIT_BASIS[j][bit][i] = gf16_mul_ct(CAUCHY_MDS[i][j], basis_val);
            }
        }
    }
    CAUCHY_INIT = 1;
}

/* Multiplicação matriz-vetor MDS 32x32 100% constant-time acelerada por decomposição binária + AVX2. */
static void mds_mult_ct(const uint16_t in_vec[RSD_W], uint16_t out_vec[RSD_W]) {
#if defined(__AVX2__)
    __m256i acc_lo = _mm256_setzero_si256();
    __m256i acc_hi = _mm256_setzero_si256();
    for (int j = 0; j < RSD_W; ++j) {
        uint16_t vj = in_vec[j];
        for (int bit = 0; bit < 16; ++bit) {
            uint16_t m = (uint16_t)(-(int16_t)((vj >> bit) & 1u));
            __m256i vmask = _mm256_set1_epi16((short)m);
            __m256i b_lo = _mm256_load_si256((const __m256i *)&CAUCHY_BIT_BASIS[j][bit][0]);
            __m256i b_hi = _mm256_load_si256((const __m256i *)&CAUCHY_BIT_BASIS[j][bit][16]);
            acc_lo = _mm256_xor_si256(acc_lo, _mm256_and_si256(b_lo, vmask));
            acc_hi = _mm256_xor_si256(acc_hi, _mm256_and_si256(b_hi, vmask));
        }
    }
    _mm256_storeu_si256((__m256i *)&out_vec[0], acc_lo);
    _mm256_storeu_si256((__m256i *)&out_vec[16], acc_hi);
#else
    for (int i = 0; i < RSD_W; ++i) {
        out_vec[i] = 0u;
    }
    for (int j = 0; j < RSD_W; ++j) {
        uint16_t vj = in_vec[j];
        for (int bit = 0; bit < 16; ++bit) {
            uint16_t m = (uint16_t)(-(int16_t)((vj >> bit) & 1u));
            for (int i = 0; i < RSD_W; ++i) {
                out_vec[i] ^= (uint16_t)(CAUCHY_BIT_BASIS[j][bit][i] & m);
            }
        }
    }
#endif
}

static void single_round_ct(
    const uint16_t state_in[RSD_W],
    uint16_t rc,
    const uint16_t rk[RSD_W],
    uint16_t state_out[RSD_W]
) {
    uint16_t sub[RSD_W] __attribute__((aligned(32)));
    uint16_t mds[RSD_W] __attribute__((aligned(32)));
#if defined(__AVX2__)
    __m256i vrc = _mm256_set1_epi16((short)rc);
    __m256i in_lo = _mm256_loadu_si256((const __m256i *)&state_in[0]);
    __m256i in_hi = _mm256_loadu_si256((const __m256i *)&state_in[16]);
    __m256i sub_lo = _mm256_xor_si256(sbox_v5_avx2(in_lo), vrc);
    __m256i sub_hi = _mm256_xor_si256(sbox_v5_avx2(in_hi), vrc);
    _mm256_store_si256((__m256i *)&sub[0], sub_lo);
    _mm256_store_si256((__m256i *)&sub[16], sub_hi);
#else
    for (int i = 0; i < RSD_W; ++i) {
        sub[i] = (uint16_t)(sbox_v5_ct(state_in[i]) ^ rc);
    }
#endif
    mds_mult_ct(sub, mds);
    for (int i = 0; i < RSD_W; ++i) {
        state_out[i] = (uint16_t)(mds[i] ^ rk[i]);
    }
    secure_wipe(sub, sizeof(sub));
    secure_wipe(mds, sizeof(mds));
}

int rsd_s_v5_core_ct(
    const uint16_t *in_state,
    const uint16_t *rk_flat,
    const uint16_t *rc,
    int rounds,
    int fault_word,
    uint16_t fault_mask,
    uint16_t *out_state
) {
    if (!in_state || !rk_flat || !rc || !out_state || rounds < 1 || rounds > 255) {
        return -1;
    }
    init_cauchy_mds();

    uint16_t state[RSD_W];
    uint16_t next_state[RSD_W];
    uint16_t state_a[RSD_W];
    uint16_t state_b[RSD_W];
    uint16_t out_a[RSD_W];
    uint16_t out_b[RSD_W];

    for (int i = 0; i < RSD_W; ++i) {
        state[i] = (uint16_t)(in_state[i] ^ rk_flat[i]);
    }

    for (int r = 1; r < rounds; ++r) {
        single_round_ct(state, rc[r - 1], &rk_flat[r * RSD_W], next_state);
        for (int i = 0; i < RSD_W; ++i) {
            state[i] = next_state[i];
        }
    }

    for (int i = 0; i < RSD_W; ++i) {
        state_a[i] = state[i];
        state_b[i] = state[i];
    }
    if (fault_word >= 0 && fault_word < RSD_W) {
        state_a[fault_word] ^= fault_mask;
    }

    single_round_ct(state_a, rc[rounds - 1], &rk_flat[rounds * RSD_W], out_a);
    single_round_ct(state_b, rc[rounds - 1], &rk_flat[rounds * RSD_W], out_b);

    uint16_t diff = 0u;
    for (int i = 0; i < RSD_W; ++i) {
        diff |= (uint16_t)(out_a[i] ^ out_b[i]);
    }

    int status = 0;
    uint16_t keep_mask = (uint16_t)(-(int16_t)(diff == 0u));
    for (int i = 0; i < RSD_W; ++i) {
        out_state[i] = (uint16_t)(out_a[i] & keep_mask);
    }
    if (diff != 0u) {
        status = -2;
    }

    secure_wipe(state, sizeof(state));
    secure_wipe(next_state, sizeof(next_state));
    secure_wipe(state_a, sizeof(state_a));
    secure_wipe(state_b, sizeof(state_b));
    secure_wipe(out_a, sizeof(out_a));
    secure_wipe(out_b, sizeof(out_b));

    return status;
}

int rsd_s_v5_verify_wipe_ct(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }
    secure_wipe(buf, len);
    uint8_t acc = 0u;
    for (size_t i = 0; i < len; ++i) {
        acc |= buf[i];
    }
    return (acc == 0u) ? 0 : 1;
}
