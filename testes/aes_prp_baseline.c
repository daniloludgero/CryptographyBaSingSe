/*
 * aes_prp_baseline.c — Implementacao C99 genuina e completa de AES-128 e AES-256
 * conforme NIST FIPS 197, com suporte a truncamento real de rodadas (1..10 / 1..14)
 * e processamento em lote para comparacao de baseline PRP contra RSD-S v5.1.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1U) * 0x1bU));
}

static inline void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = AES_SBOX[state[i]];
    }
}

static inline void shift_rows(uint8_t s[16]) {
    uint8_t t;
    /* Row 1: shift left by 1 */
    t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    /* Row 2: shift left by 2 */
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;

    /* Row 3: shift left by 3 (right by 1) */
    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

static inline void mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        int idx = 4 * c;
        uint8_t a0 = s[idx + 0];
        uint8_t a1 = s[idx + 1];
        uint8_t a2 = s[idx + 2];
        uint8_t a3 = s[idx + 3];

        uint8_t x0 = xtime(a0);
        uint8_t x1 = xtime(a1);
        uint8_t x2 = xtime(a2);
        uint8_t x3 = xtime(a3);

        s[idx + 0] = (uint8_t)(x0 ^ x1 ^ a1 ^ a2 ^ a3);
        s[idx + 1] = (uint8_t)(a0 ^ x1 ^ x2 ^ a2 ^ a3);
        s[idx + 2] = (uint8_t)(a0 ^ a1 ^ x2 ^ x3 ^ a3);
        s[idx + 3] = (uint8_t)(x0 ^ a0 ^ a1 ^ a2 ^ x3);
    }
}

static inline void add_round_key(uint8_t state[16], const uint8_t *rk) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= rk[i];
    }
}

int aes_key_expand(const uint8_t *key, int key_bits, uint8_t *round_keys_out) {
    if (key == NULL || round_keys_out == NULL) {
        return -1;
    }

    int nk = 0;
    int nr = 0;
    if (key_bits == 128) {
        nk = 4;
        nr = 10;
    } else if (key_bits == 256) {
        nk = 8;
        nr = 14;
    } else {
        return -1;
    }

    int total_words = 4 * (nr + 1);
    int key_bytes = 4 * nk;
    memcpy(round_keys_out, key, (size_t)key_bytes);

    for (int i = nk; i < total_words; ++i) {
        uint8_t temp[4];
        memcpy(temp, round_keys_out + 4 * (i - 1), 4);

        if (i % nk == 0) {
            uint8_t t = temp[0];
            temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[i / nk];
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[t];
        } else if (nk == 8 && (i % nk == 4)) {
            temp[0] = AES_SBOX[temp[0]];
            temp[1] = AES_SBOX[temp[1]];
            temp[2] = AES_SBOX[temp[2]];
            temp[3] = AES_SBOX[temp[3]];
        }

        const uint8_t *prev = round_keys_out + 4 * (i - nk);
        uint8_t *dst = round_keys_out + 4 * i;
        dst[0] = prev[0] ^ temp[0];
        dst[1] = prev[1] ^ temp[1];
        dst[2] = prev[2] ^ temp[2];
        dst[3] = prev[3] ^ temp[3];
    }

    return 0;
}

static inline void aes_encrypt_block_core(
    const uint8_t in[16],
    const uint8_t *round_keys,
    int rounds,
    int final_no_mixcolumns,
    uint8_t out[16]
) {
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, round_keys);

    for (int r = 1; r <= rounds; ++r) {
        sub_bytes(state);
        shift_rows(state);
        if (r < rounds || final_no_mixcolumns == 0) {
            mix_columns(state);
        }
        add_round_key(state, round_keys + (size_t)r * 16U);
    }

    memcpy(out, state, 16);
}

int aes_encrypt_block_rounds(
    const uint8_t in[16],
    const uint8_t *round_keys,
    int key_bits,
    int rounds,
    int final_no_mixcolumns,
    uint8_t out[16]
) {
    if (in == NULL || round_keys == NULL || out == NULL) {
        return -1;
    }

    int max_rounds = 0;
    if (key_bits == 128) {
        max_rounds = 10;
    } else if (key_bits == 256) {
        max_rounds = 14;
    } else {
        return -1;
    }

    if (rounds < 1 || rounds > max_rounds) {
        return -1;
    }

    aes_encrypt_block_core(in, round_keys, rounds, final_no_mixcolumns, out);
    return 0;
}

int aes_encrypt_batch_rounds(
    const uint8_t *in_blocks,
    size_t n_blocks,
    const uint8_t *round_keys,
    int key_bits,
    int rounds,
    int final_no_mixcolumns,
    uint8_t *out_blocks
) {
    if (n_blocks == 0) {
        return 0;
    }
    if (in_blocks == NULL || round_keys == NULL || out_blocks == NULL) {
        return -1;
    }

    int max_rounds = 0;
    if (key_bits == 128) {
        max_rounds = 10;
    } else if (key_bits == 256) {
        max_rounds = 14;
    } else {
        return -1;
    }

    if (rounds < 1 || rounds > max_rounds) {
        return -1;
    }

    for (size_t i = 0; i < n_blocks; ++i) {
        aes_encrypt_block_core(
            in_blocks + i * 16U,
            round_keys,
            rounds,
            final_no_mixcolumns,
            out_blocks + i * 16U
        );
    }

    return 0;
}
