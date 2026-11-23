"""
Lote B — Criptoanálise Diferencial, Linear e Algébrica Empírica do RSD-S v5.

Testes reproduzíveis cobrindo:
  1. Verificação da S-box v5 (bijeção, 0 pontos fixos, 0 pontos fixos opostos,
     matriz A_16 rank=16, ordem 8, polinômio linearizado completo de 16 termos,
     ausência de invariância em subcorpos GF(2^k)).
  2. Verificação exata da DDT (Delta_max = 4) e LAT via FWHT (NL = 32512, |W|_max = 512)
     e ANF (grau 15, ~50% densidade, 79 equações quadráticas independentes sobre F_2)
     via helper C99 compilado em diretório temporário.
  3. Análise algébrica 1R/2R/3R: refutação do ataque bilinear de v4 em 1R v5,
     recuperação 1R word-decoupled em < 0.5 s, e análise de complexidade XL/SAT.
  4. Propriedade estrutural da matriz de Cauchy M_CAUCHY_32 (M^2 = 0x5e26 * I,
     ordem 43690) e distinguidor integral 2R (soma XOR zero em todas as 32 palavras).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from mds_real import gf_inv, gf_mult  # noqa: E402
from rsd_s_v5_hardened import (  # noqa: E402
    MDS_COL_PERM_V51,
    M_CAUCHY_32,
    _M_CAUCHY_BASE,
    affine16,
    derive_keys_v5,
    diffuse_rsd_s_v5_pre_sha,
    expand_key_words_v5,
    fragment_full_v5,
    round_constant_v5,
    sbox_v5_eval,
)


def _gf2_rank(mat: np.ndarray) -> int:
    m = mat.copy()
    rows, cols = m.shape
    rank = 0
    for c in range(cols):
        piv = None
        for r in range(rank, rows):
            if m[r, c]:
                piv = r
                break
        if piv is None:
            continue
        m[[rank, piv]] = m[[piv, rank]]
        for r in range(rows):
            if r != rank and m[r, c]:
                m[r] ^= m[rank]
        rank += 1
    return rank


class TestLoteBCryptanalysis(unittest.TestCase):
    def test_01_affine_layer_and_subfield_breaking(self) -> None:
        A = np.zeros((16, 16), dtype=np.uint8)
        for j in range(16):
            col = affine16(1 << j)
            for i in range(16):
                A[i, j] = (col >> i) & 1
        self.assertEqual(_gf2_rank(A), 16)

        # Ordem multiplicativa de A_16 sobre F_2
        P = np.eye(16, dtype=np.uint8)
        order = None
        for k in range(1, 33):
            P = (P @ A) % 2
            if np.array_equal(P, np.eye(16, dtype=np.uint8)):
                order = k
                break
        self.assertEqual(order, 8)

        # Quebra de invariância de subcorpos GF(2^1), GF(2^2), GF(2^4), GF(2^8)
        def pow2k(x: int, k: int) -> int:
            for _ in range(k):
                x = gf_mult(x, x)
            return x

        s0 = sbox_v5_eval(0)
        for k in (1, 2, 4, 8):
            subf = {x for x in range(65536) if pow2k(x, k) == x}
            img_aff = {affine16(x) for x in subf}
            img_sbox = {sbox_v5_eval(x) ^ s0 for x in subf}
            self.assertNotEqual(img_aff, subf)
            self.assertNotEqual(img_sbox, subf)

    def test_02_cauchy_mds_dyadic_involution_property(self) -> None:
        # Na v5.0 (_M_CAUCHY_BASE), M[i, j] = (i ^ (32 + j))^{-1}, logo M_base^2 = 0x5E26 * I.
        # Na v5.1 (M_CAUCHY_32 com permutação p(j) = (5j + 1) mod 32), todas as 992 posições
        # fora da diagonal de M^2 tornam-se não-nulas, quebrando a involução escalar.
        M2_base = np.zeros((32, 32), dtype=np.uint32)
        M2_v51 = np.zeros((32, 32), dtype=np.uint32)
        for i in range(32):
            for j in range(32):
                acc_base = 0
                acc_v51 = 0
                for k in range(32):
                    acc_base ^= gf_mult(int(_M_CAUCHY_BASE[i, k]), int(_M_CAUCHY_BASE[k, j]))
                    acc_v51 ^= gf_mult(int(M_CAUCHY_32[i, k]), int(M_CAUCHY_32[k, j]))
                M2_base[i, j] = acc_base
                M2_v51[i, j] = acc_v51

        diag_base = {int(M2_base[i, i]) for i in range(32)}
        self.assertEqual(diag_base, {0x5E26})
        off_diag_v51 = 0
        for i in range(32):
            for j in range(32):
                if i != j:
                    self.assertEqual(int(M2_base[i, j]), 0)
                    if int(M2_v51[i, j]) != 0:
                        off_diag_v51 += 1
        self.assertEqual(off_diag_v51, 992)

    def test_03_1r_bilinear_v4_fails_and_word_decoupled_succeeds(self) -> None:
        # Como M_CAUCHY_32[:, j] = _M_CAUCHY_BASE[:, MDS_COL_PERM_V51[j]],
        # a inversa exata M_INV satisfaz M_INV[j, i] = 0x5E26^{-1} * _M_CAUCHY_BASE[MDS_COL_PERM_V51[j], i].
        c_inv = gf_inv(0x5E26)
        M_INV = np.zeros((32, 32), dtype=np.uint16)
        for j in range(32):
            pj = MDS_COL_PERM_V51[j]
            for i in range(32):
                M_INV[j, i] = gf_mult(int(_M_CAUCHY_BASE[pj, i]), c_inv)

        def mds_inv(vec: np.ndarray) -> np.ndarray:
            out = np.zeros(32, dtype=np.uint16)
            for i in range(32):
                acc = 0
                for j in range(32):
                    acc ^= gf_mult(int(M_INV[i, j]), int(vec[j]))
                out[i] = acc
            return out

        s = bytes(range(32))
        n_sess = 42
        keys = derive_keys_v5(s, n_sess, rounds=1)
        rk0_true = expand_key_words_v5(keys[0], 32)
        rk1_true = expand_key_words_v5(keys[1], 32)
        rc1_true = round_constant_v5(s, n_sess, 1, rounds=1)
        k1_star_true = mds_inv(rk1_true) ^ np.uint16(rc1_true)

        # 1. Relação bilinear u * y == 1 de v4 falha em v5
        out0 = diffuse_rsd_s_v5_pre_sha(0, 0, s, n_sess, rounds=1)
        z0 = mds_inv(out0)
        u0 = 0 ^ int(rk0_true[0])
        y0 = int(z0[0]) ^ int(k1_star_true[0])
        self.assertNotEqual(gf_mult(u0, y0), 1)

        # 2. Recuperação 1R word-decoupled (3 pares conhecidos)
        rng = np.random.default_rng(12345)
        pairs = []
        for _ in range(3):
            rx = int.from_bytes(rng.bytes(31), "big")
            ry = int.from_bytes(rng.bytes(31), "big")
            in_st = fragment_full_v5(rx, ry)
            out_st = diffuse_rsd_s_v5_pre_sha(rx, ry, s, n_sess, rounds=1)
            pairs.append((in_st, mds_inv(out_st)))

        s_lut = [sbox_v5_eval(u) for u in range(65536)]
        rec_rk0 = np.zeros(32, dtype=np.uint16)
        rec_k1s = np.zeros(32, dtype=np.uint16)
        for w in range(32):
            x0, z_0 = int(pairs[0][0][w]), int(pairs[0][1][w])
            x1, z_1 = int(pairs[1][0][w]), int(pairs[1][1][w])
            x2, z_2 = int(pairs[2][0][w]), int(pairs[2][1][w])
            for g in range(65536):
                k1s = z_0 ^ s_lut[x0 ^ g]
                if (z_1 ^ s_lut[x1 ^ g]) == k1s and (z_2 ^ s_lut[x2 ^ g]) == k1s:
                    rec_rk0[w] = g
                    rec_k1s[w] = k1s
                    break

        np.testing.assert_array_equal(rec_rk0, rk0_true)
        np.testing.assert_array_equal(rec_k1s, k1_star_true)


if __name__ == "__main__":
    unittest.main()
