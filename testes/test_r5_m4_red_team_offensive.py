"""
M_R5_4 — Suíte Ofensiva de Red-Team (Criptoanálise & Segurança de Implementação) para RSD-S v5.1.

Frente 1 — Criptoanálise Ofensiva (RSD-S v5.1):
  1. Boomerang / Rectangle (1R-4R pre_sha): quartets exatos, M-alinhados e truncados.
  2. Diferencial Impossível & Meet-in-the-Middle (1R-3R): MDS B=33 (0 transições 1 -> <32)
     e distinguidor diferencial impossível 2R (0 hits) vs 3R (~32/65536 hits).
  3. Slide / Related-Key / Chosen-Nonce:
     - Separação de domínio HMAC-SHA256 (_domain_tag com rounds e n_sess).
     - Simetria de round_constant_v5 (idêntica nas 32 palavras) vs quebra de subespaço
       simétrico por M_CAUCHY_32 + p(j)=(5j+1)%32 + rk[r].
     - Achado real de Key Schedule: expand_key_words_v5 expõe keys[r] em rk[r][0..15],
       permitindo reconstruir rk[r][16..31] sem conhecer a chave mestra s.
     - Achado real de Entrada: fragment_full_v5 fixa 2 MSBs (state[15]>>15==0, state[31]>>15==0)
       para todo x, y < 2^255-19; persistência pós-rk[0] e dissipação em 1R.
  4. Algébrica (ANF) & Integral / Square (1R-4R com A_16):
     - Grau ANF exato (15) nas 16 coordenadas de sbox_v5_eval (transformada de Möbius).
     - Recuperação algébrica em 1R (rk[1] dado rk[0]) e contagem de complexidade quadrática
       para 2R-3R (sem execução de solver SAT/MILP completo).
     - Propriedade Integral / Division Property empírica (Lambda-set Square de 2^16 textos
       em 1 palavra): soma XOR zero em 1R e 2R, quebra em 3R e 4R.

Frente 2 — Implementação / Fault / Side-Channel / API:
  1. DFA / SIFA na rodada R-1 (R7): falha em R8 é bloqueada, mas falha em R7 propaga
     identicamente para state_a e state_b e passa 100% despercebida (Python e C99),
     além de teste com fault_mask == 0.
  2. Concorrência / Data Race & Memória:
     - Data race em init_cauchy_mds() / CAUCHY_INIT não atômico sob 16 threads (TSan real).
     - Verificação de sizeof(CAUCHY_BIT_BASIS) == 32768 bytes (32 KB L1D).
     - Inspeção de assembly AVX2 via objdump -d (ausência de limpeza de registradores ymm).
  3. Side-Channel Python & Folding (_unpadded_z65537_to_bytes64):
     - Vazamento de timing (teste t de Welch) para y_vec[i] == 65536 vs < 65536.
     - Colisão 2-para-1 real em y_pub_bytes (64B) entre dois vetores distintos em Z_65537^32,
       preservando distinção em y_pub_z65537_bytes e y_pub_digest_256.
  4. API & Boundary Fuzzing:
     - Exposição de s_priv_state em BandlimitedDualKeyEngine.refactor_public_output.
     - Fuzzing de fronteira em x, y, n_sess, rounds, output_bytes, s, mode.
"""

from __future__ import annotations

import ctypes
import hmac
import math
import subprocess
import sys
import time
from hashlib import sha256, shake_256
from pathlib import Path

import numpy as np
import pytest
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from bandlimited_dual_key import (  # noqa: E402
    Q_FERMAT,
    BandlimitedDualKeyEngine,
    _unpadded_z65537_to_bytes64,
)
from mds_real import gf_add, gf_mult  # noqa: E402
from rsd_s_v5_hardened import (  # noqa: E402
    AFFINE_CONST_V5,
    M_CAUCHY_32,
    MASK16,
    P_CURVE25519,
    R_V5,
    W,
    FaultDetectedError,
    _domain_tag,
    affine16,
    derive_keys_v5,
    diffuse_rsd_s_v5,
    diffuse_rsd_s_v5_pre_sha,
    expand_key_words_v5,
    fragment_full_v5,
    gf16_inv_itoh_tsujii,
    round_constant_v5,
    run_c_core_pre_sha,
    sbox_v5_eval,
)

BUILD_DIR = Path("/tmp/r5_m4_build")
C_SRC = ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"
LIB_PATH = BUILD_DIR / "lib_rsd_v5.so"


def _ensure_c_lib() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    if not LIB_PATH.exists() or LIB_PATH.stat().st_mtime < C_SRC.stat().st_mtime:
        subprocess.run(
            [
                "gcc",
                "-O3",
                "-mavx2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                str(C_SRC),
                "-o",
                str(LIB_PATH),
            ],
            check=True,
        )
    return LIB_PATH


def _load_c_lib() -> ctypes.CDLL:
    lib = ctypes.CDLL(str(_ensure_c_lib()))
    lib.rsd_s_v5_core_ct.argtypes = [
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint16,
        ctypes.POINTER(ctypes.c_uint16),
    ]
    lib.rsd_s_v5_core_ct.restype = ctypes.c_int
    return lib


def _gf16_inv_fast_table() -> np.ndarray:
    """Constrói tabela exata de inversão em GF(2^16) usando potências do gerador 0x0003."""
    exp_tbl = [0] * 65536
    log_tbl = [0] * 65536
    cur = 1
    for i in range(65535):
        exp_tbl[i] = cur
        log_tbl[cur] = i
        cur = gf_mult(cur, 0x0003)
    inv_tbl = np.zeros(65536, dtype=np.uint16)
    for x in range(1, 65536):
        inv_tbl[x] = exp_tbl[(65535 - log_tbl[x]) % 65535]
    return inv_tbl


def _build_sbox_and_inv_luts() -> tuple[np.ndarray, np.ndarray]:
    inv_tbl = _gf16_inv_fast_table()
    sbox = np.zeros(65536, dtype=np.uint16)
    sbox_inv = np.zeros(65536, dtype=np.uint16)
    for x in range(65536):
        y = (affine16(int(inv_tbl[x])) ^ AFFINE_CONST_V5) & MASK16
        sbox[x] = y
        sbox_inv[y] = x
    return sbox, sbox_inv


def _invert_gf16_matrix(mat: np.ndarray) -> np.ndarray:
    """Inverte matriz 32x32 sobre GF(2^16) por eliminação de Gauss-Jordan."""
    n = mat.shape[0]
    aug = np.zeros((n, 2 * n), dtype=np.uint16)
    aug[:, :n] = mat.copy()
    for i in range(n):
        aug[i, n + i] = 1

    inv_tbl = _gf16_inv_fast_table()
    for col in range(n):
        pivot = -1
        for r in range(col, n):
            if aug[r, col] != 0:
                pivot = r
                break
        if pivot < 0:
            raise ValueError("Matriz singular sobre GF(2^16)")
        if pivot != col:
            aug[[col, pivot]] = aug[[pivot, col]]
        inv_p = int(inv_tbl[int(aug[col, col])])
        for j in range(2 * n):
            aug[col, j] = gf_mult(int(aug[col, j]), inv_p)
        for r in range(n):
            if r != col and aug[r, col] != 0:
                factor = int(aug[r, col])
                for j in range(2 * n):
                    aug[r, j] = gf_add(int(aug[r, j]), gf_mult(factor, int(aug[col, j])))
    return aug[:, n:].copy()


SBOX_LUT, SBOX_INV_LUT = _build_sbox_and_inv_luts()
M_CAUCHY_INV = _invert_gf16_matrix(M_CAUCHY_32)


def _mds_mult_matrix(mat: np.ndarray, vec: np.ndarray) -> np.ndarray:
    out = np.zeros(W, dtype=np.uint16)
    for i in range(W):
        acc = 0
        row = mat[i]
        for j in range(W):
            acc = gf_add(acc, gf_mult(int(row[j]), int(vec[j])))
        out[i] = acc & MASK16
    return out


def _core_inv_rounds(
    out_state: np.ndarray,
    rk_flat: np.ndarray,
    rc: np.ndarray,
    rounds: int,
) -> np.ndarray:
    """Inversa exata de rsd_s_v5_core_ct para `rounds` rodadas (usada no ataque boomerang)."""
    state = out_state.copy()
    for r in range(rounds, 0, -1):
        rk_r = rk_flat[r * W : (r + 1) * W]
        state = np.bitwise_xor(state, rk_r)
        state = _mds_mult_matrix(M_CAUCHY_INV, state)
        state = np.bitwise_xor(state, np.uint16(rc[r - 1]))
        state = SBOX_INV_LUT[state]
    state = np.bitwise_xor(state, rk_flat[:W])
    return state


def _prepare_key_schedule(
    s: bytes = b"\x42" * 32,
    n_sess: int = 1337,
    rounds: int = R_V5,
) -> tuple[np.ndarray, np.ndarray]:
    keys = derive_keys_v5(s, n_sess, rounds)
    rk_flat = np.concatenate([expand_key_words_v5(k, W) for k in keys]).astype(np.uint16)
    rcs = np.array(
        [round_constant_v5(s, n_sess, r, rounds) for r in range(1, rounds + 1)],
        dtype=np.uint16,
    )
    return rk_flat, rcs


def _call_c_core(
    lib: ctypes.CDLL,
    in_state: np.ndarray,
    rk_flat: np.ndarray,
    rcs: np.ndarray,
    rounds: int,
    fault_word: int = -1,
    fault_mask: int = 0,
) -> tuple[int, np.ndarray]:
    out_state = np.zeros(W, dtype=np.uint16)
    rc_code = lib.rsd_s_v5_core_ct(
        in_state.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
        rk_flat.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
        rcs.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
        ctypes.c_int(rounds),
        ctypes.c_int(fault_word),
        ctypes.c_uint16(fault_mask & MASK16),
        out_state.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
    )
    return int(rc_code), out_state


# =============================================================================
# FRENTE 1 — CRIPTOANÁLISE OFENSIVA (RSD-S v5.1)
# =============================================================================


class TestFrente1CriptanaliseOfensiva:
    """Ataques criptoanalíticos genuínos contra RSD-S v5.1 (1R-8R)."""

    def test_01_boomerang_rectangle_1r_to_4r(self) -> None:
        """
        Boomerang / Rectangle em 1R-4R pre_sha sobre rsd_s_v5_core_ct truncado (N=500 quartetos).
        Nota metodológica: `beta_aligned = M * e_1` atua como sonda switch alinhada para 1 rodada;
        não foi executada busca de trilha boomerang multi-rodada ótima. Em 4R, `1/500` em
        `aligned_trunc(<32)` corresponde ao ruído estatístico esperado (E[X] = 500 * 32 / 65536 ≈ 0.244).
        """
        lib = _load_c_lib()
        rk_full, rc_full = _prepare_key_schedule(s=b"\x11" * 32, n_sess=2026, rounds=R_V5)

        # Valida inversão exata em 4R
        rng = np.random.default_rng(101)
        probe = rng.integers(0, 65536, size=W, dtype=np.uint16)
        _, fwd4 = _call_c_core(lib, probe, rk_full[: 5 * W], rc_full[:4], 4)
        inv4 = _core_inv_rounds(fwd4, rk_full[: 5 * W], rc_full[:4], 4)
        assert np.array_equal(probe, inv4), "Inversa 4R deve ser exata"

        # Diferencial alpha de 1 bit na palavra 0; beta_aligned = M * (0x0001 na palavra 1)
        alpha = np.zeros(W, dtype=np.uint16)
        alpha[0] = 0x0001
        delta_s_out = np.zeros(W, dtype=np.uint16)
        delta_s_out[1] = 0x0001
        beta_aligned = _mds_mult_matrix(M_CAUCHY_32, delta_s_out)
        beta_1word = np.zeros(W, dtype=np.uint16)
        beta_1word[1] = 0x0001

        n_quartets = 500
        results = {}
        for r in (1, 2, 3, 4):
            rk_r = rk_full[: (r + 1) * W]
            rc_r = rc_full[:r]
            exact_aligned_hits = 0
            exact_1word_hits = 0
            trunc_hits_aligned = 0  # wt_word(P3 ^ P4) < 32

            for _ in range(n_quartets):
                p1 = rng.integers(0, 65536, size=W, dtype=np.uint16)
                p2 = np.bitwise_xor(p1, alpha)
                _, c1 = _call_c_core(lib, p1, rk_r, rc_r, r)
                _, c2 = _call_c_core(lib, p2, rk_r, rc_r, r)

                # Boomerang M-alinhado
                c3_a = np.bitwise_xor(c1, beta_aligned)
                c4_a = np.bitwise_xor(c2, beta_aligned)
                p3_a = _core_inv_rounds(c3_a, rk_r, rc_r, r)
                p4_a = _core_inv_rounds(c4_a, rk_r, rc_r, r)
                diff_a = np.bitwise_xor(p3_a, p4_a)
                if np.array_equal(diff_a, alpha):
                    exact_aligned_hits += 1
                if int(np.count_nonzero(diff_a)) < W:
                    trunc_hits_aligned += 1

                # Boomerang 1-palavra (não alinhado com M)
                c3_b = np.bitwise_xor(c1, beta_1word)
                c4_b = np.bitwise_xor(c2, beta_1word)
                p3_b = _core_inv_rounds(c3_b, rk_r, rc_r, r)
                p4_b = _core_inv_rounds(c4_b, rk_r, rc_r, r)
                if np.array_equal(np.bitwise_xor(p3_b, p4_b), alpha):
                    exact_1word_hits += 1

            results[r] = (exact_aligned_hits, trunc_hits_aligned, exact_1word_hits)
            print(
                f"[BOOMERANG {r}R] aligned_exact={exact_aligned_hits}/{n_quartets} "
                f"aligned_trunc(<32)={trunc_hits_aligned}/{n_quartets} "
                f"1word_exact={exact_1word_hits}/{n_quartets}"
            )

        # Em 1R, o boomerang M-alinhado (palavra 0 vs palavra 1) retorna alpha com probabilidade 1.0!
        assert results[1][0] == n_quartets
        # Em 2R, 3R e 4R, a difusão MDS total (B=33) zera os retornos boomerang
        assert results[2][0] == 0
        assert results[3][0] == 0
        assert results[4][0] == 0

    def test_02_impossible_differential_mds_and_mitm_2r_vs_3r(self) -> None:
        """
        Propriedade MDS (B=33): 1 palavra ativa -> 32 palavras ativas em 1R (0 transições 1 -> <32).
        Distinguidor Diferencial Impossível em 2R vs 3R:
          Para wt_word(d_in) == 1:
            - Em 2R, wt_word(M^{-1}(d_out)) é SEMPRE 32 (0 ocorrências de <32 em N=8000).
            - Em 3R, M^{-1}(d_out) pode ter <32 palavras ativas (probabilidade teórica ~32/65536 ≈ 4.88e-4).
        """
        lib = _load_c_lib()
        rk_full, rc_full = _prepare_key_schedule(s=b"\x22" * 32, n_sess=99, rounds=R_V5)
        rng = np.random.default_rng(202)

        # 1) Validação MDS em 1R: 1 palavra ativa -> 32 palavras ativas
        n_mds = 1000
        min_active_1r = W
        for _ in range(n_mds):
            p1 = rng.integers(0, 65536, size=W, dtype=np.uint16)
            d_in = np.zeros(W, dtype=np.uint16)
            d_in[int(rng.integers(0, W))] = int(rng.integers(1, 65536))
            p2 = np.bitwise_xor(p1, d_in)
            _, c1 = _call_c_core(lib, p1, rk_full[: 2 * W], rc_full[:1], 1)
            _, c2 = _call_c_core(lib, p2, rk_full[: 2 * W], rc_full[:1], 1)
            active = int(np.count_nonzero(np.bitwise_xor(c1, c2)))
            min_active_1r = min(min_active_1r, active)
        print(f"[MDS 1R] min_active_words={min_active_1r} em {n_mds} diferenciais de 1 palavra")
        assert min_active_1r == W

        # 2) Distinguidor Diferencial Impossível 2R vs 3R
        n_pairs = 8192
        hits_2r = 0
        hits_3r = 0
        for i in range(n_pairs):
            p1 = rng.integers(0, 65536, size=W, dtype=np.uint16)
            d_in = np.zeros(W, dtype=np.uint16)
            d_in[i % W] = int(rng.integers(1, 65536))
            p2 = np.bitwise_xor(p1, d_in)

            _, c1_2 = _call_c_core(lib, p1, rk_full[: 3 * W], rc_full[:2], 2)
            _, c2_2 = _call_c_core(lib, p2, rk_full[: 3 * W], rc_full[:2], 2)
            inv_m_diff_2 = _mds_mult_matrix(M_CAUCHY_INV, np.bitwise_xor(c1_2, c2_2))
            if int(np.count_nonzero(inv_m_diff_2)) < W:
                hits_2r += 1

            _, c1_3 = _call_c_core(lib, p1, rk_full[: 4 * W], rc_full[:3], 3)
            _, c2_3 = _call_c_core(lib, p2, rk_full[: 4 * W], rc_full[:3], 3)
            inv_m_diff_3 = _mds_mult_matrix(M_CAUCHY_INV, np.bitwise_xor(c1_3, c2_3))
            if int(np.count_nonzero(inv_m_diff_3)) < W:
                hits_3r += 1

        print(
            f"[IMPOSSIBLE DIFF 2R vs 3R] N={n_pairs}: "
            f"2R_lt32={hits_2r} (impossível), 3R_lt32={hits_3r} (esperado ~{n_pairs * 32 / 65536:.2f})"
        )
        assert hits_2r == 0, "Diferencial 1 -> <32 (pós-M^{-1}) é estritamente impossível em 2R"
        # Em 3R, a média esperada é 4.0 em 8192 pares (Poisson lambda=4, P(>=1) > 98%)
        assert hits_3r >= 1, "Em 3R o distinguidor impossível de 2R é violado"

        # 3) Barreira Meet-in-the-Middle (MitM) em 2R vs 3R:
        #    Em 2R, dada a chave completa (rk[0], rk[1], rk[2]), o estado intermediário
        #    mid_fwd(P) == mid_bwd(C) coincide em 32/32 palavras. Contudo, já após 1R (forward)
        #    e 1R^{-1} (backward), qualquer alteração de 1 palavra em P ou em C afeta 32/32
        #    palavras do estado intermediário (difusão completa MDS B=33), bloqueando
        #    particionamento parcial independente de palavras em >= 3R.
        p_probe = rng.integers(0, 65536, size=W, dtype=np.uint16)
        _, c_2r = _call_c_core(lib, p_probe, rk_full[: 3 * W], rc_full[:2], 2)
        _, mid_fwd = _call_c_core(lib, p_probe, rk_full[: 2 * W], rc_full[:1], 1)
        mid_bwd = _core_inv_rounds(c_2r, np.concatenate([np.zeros(W, dtype=np.uint16), rk_full[2 * W : 3 * W]]), rc_full[1:2], 1)
        assert np.array_equal(mid_fwd, mid_bwd), "Consistência exata no ponto de encontro de 2R"

        # Verifica dependência total 32/32 no ponto de encontro (forward 1R e backward 1R^{-1})
        p_flip = p_probe.copy()
        p_flip[0] ^= 0x0001
        _, mid_fwd_flip = _call_c_core(lib, p_flip, rk_full[: 2 * W], rc_full[:1], 1)
        c_flip = c_2r.copy()
        c_flip[0] ^= 0x0001
        mid_bwd_flip = _core_inv_rounds(c_flip, np.concatenate([np.zeros(W, dtype=np.uint16), rk_full[2 * W : 3 * W]]), rc_full[1:2], 1)
        dep_fwd = int(np.count_nonzero(np.bitwise_xor(mid_fwd, mid_fwd_flip)))
        dep_bwd = int(np.count_nonzero(np.bitwise_xor(mid_bwd, mid_bwd_flip)))
        print(f"[MITM BARRIER 2R/3R] consistência 2R=32/32, dependência fwd_1R={dep_fwd}/32, bwd_1R={dep_bwd}/32")
        assert dep_fwd == W and dep_bwd == W

    def test_03_slide_related_key_symmetric_subspace_key_schedule_and_input_bias(self) -> None:
        """
        Testa:
          a) Separação de domínio HMAC-SHA256 (_domain_tag) contra slide e related-key.
          b) Simetria de rc(r) nas 32 palavras vs quebra de subespaço simétrico por M_CAUCHY_32 + rk[r].
          c) Achado real de Key Schedule: rk[r][0..15] expõe literalmente keys[r], reconstruindo rk[r][16..31].
          d) Achado real de Entrada: fragment_full_v5 fixa MSBs de state[15] e state[31] em 0;
             viés persiste após rk[0] e dissipa em 1R.
        """
        s1 = b"\x33" * 32
        s2 = bytearray(s1)
        s2[0] ^= 0x01  # 1 bit flip (related-key)
        s2_bytes = bytes(s2)

        # (a) Separação de domínio
        assert _domain_tag(0, 8) != _domain_tag(0, 7)
        assert _domain_tag(0, 8) != _domain_tag(1, 8)
        k_r8_s0 = derive_keys_v5(s1, 0, rounds=8)
        k_r7_s0 = derive_keys_v5(s1, 0, rounds=7)
        k_r8_s1 = derive_keys_v5(s1, 1, rounds=8)
        k_r8_rk = derive_keys_v5(s2_bytes, 0, rounds=8)

        def _bit_hd(a: bytes, b: bytes) -> float:
            return sum((x ^ y).bit_count() for x, y in zip(a, b)) / (len(a) * 8.0)

        hd_rounds = _bit_hd(b"".join(k_r8_s0[:8]), b"".join(k_r7_s0))
        hd_sess = _bit_hd(b"".join(k_r8_s0), b"".join(k_r8_s1))
        hd_relkey = _bit_hd(b"".join(k_r8_s0), b"".join(k_r8_rk))
        print(f"[DOMAIN SEP] HD_rounds={hd_rounds:.4f}, HD_sess={hd_sess:.4f}, HD_relkey={hd_relkey:.4f}")
        assert 0.43 <= hd_rounds <= 0.57
        assert 0.43 <= hd_sess <= 0.57
        assert 0.43 <= hd_relkey <= 0.57

        # (b) Simetria de rc(r) e subespaço simétrico S_eq = {(c, c, ..., c)}
        row_sums = set()
        for i in range(W):
            acc = 0
            for j in range(W):
                acc ^= int(M_CAUCHY_32[i, j])
            row_sums.add(acc)
        print(f"[SUBSPACE] Somas de linha distintas em M_CAUCHY_32: {len(row_sums)}/{W} (valor={hex(next(iter(row_sums)))})")
        assert len(row_sums) == 1, "Todas as 32 linhas de M_CAUCHY_32 têm soma idêntica (0x1731)"

        lib = _load_c_lib()
        rk_full, rc_full = _prepare_key_schedule(s=s1, n_sess=0, rounds=R_V5)
        sym_in = np.full(W, 0x1234, dtype=np.uint16)
        _, out_1r = _call_c_core(lib, sym_in, rk_full[: 2 * W], rc_full[:1], 1)
        _, out_2r = _call_c_core(lib, sym_in, rk_full[: 3 * W], rc_full[:2], 2)
        assert len(set(out_1r.tolist())) > 1
        assert len(set(out_2r.tolist())) > 1

        # (c) RT-F1-01 mitigado em v5.2: todos os blocos expandidos via HMAC com separação de domínio
        for r_idx, key_r in enumerate(k_r8_s0):
            rk_r = expand_key_words_v5(key_r, W)
            leaked_key_r = b"".join(int(w).to_bytes(2, "big") for w in rk_r[:16])
            assert leaked_key_r != key_r, "RT-F1-01 mitigado: rk[r][0..15] não pode expor literalmente keys[r]"
            # Atacante sem acesso a `s` nem a `keys[r]` NÃO consegue reconstruir rk[r][16..31] a partir de rk[r][0..15]:
            forged_second_half = hmac.new(
                leaked_key_r, b"EXP|" + (1).to_bytes(4, "big"), sha256
            ).digest()
            forged_words_16_31 = np.frombuffer(forged_second_half, dtype=">u2").astype(np.uint16)
            assert not np.array_equal(forged_words_16_31, rk_r[16:32])
            expected_b0 = hmac.new(key_r, b"EXP|" + (0).to_bytes(4, "big"), sha256).digest()
            expected_b1 = hmac.new(key_r, b"EXP|" + (1).to_bytes(4, "big"), sha256).digest()
            assert np.array_equal(rk_r[:16], np.frombuffer(expected_b0, dtype=">u2").astype(np.uint16))
            assert np.array_equal(rk_r[16:32], np.frombuffer(expected_b1, dtype=">u2").astype(np.uint16))
        print("[KEY SCHEDULE RT-F1-01 MITIGADO] rk[r][0..15] e rk[r][16..31] derivados independentemente via HMAC(block 0/1)!")

        # (d) Achado real de Entrada: 2 MSBs sempre zero em fragment_full_v5
        rng = np.random.default_rng(303)
        n_samples = 256
        msb15_in = 0
        msb31_in = 0
        msb15_post_rk0 = 0
        msb31_post_rk0 = 0
        msb15_post_1r = 0
        msb31_post_1r = 0
        rk0 = rk_full[:W]
        for _ in range(n_samples):
            x = int.from_bytes(rng.bytes(32), "big") % P_CURVE25519
            y = int.from_bytes(rng.bytes(32), "big") % P_CURVE25519
            st = fragment_full_v5(x, y)
            msb15_in += (int(st[15]) >> 15) & 1
            msb31_in += (int(st[31]) >> 15) & 1
            post_rk0 = np.bitwise_xor(st, rk0)
            msb15_post_rk0 += (int(post_rk0[15]) >> 15) & 1
            msb31_post_rk0 += (int(post_rk0[31]) >> 15) & 1
            _, post_1r = _call_c_core(lib, st, rk_full[: 2 * W], rc_full[:1], 1)
            msb15_post_1r += (int(post_1r[15]) >> 15) & 1
            msb31_post_1r += (int(post_1r[31]) >> 15) & 1

        print(
            f"[INPUT MSB BIAS] N={n_samples}: "
            f"in=({msb15_in},{msb31_in}), "
            f"post_rk0=({msb15_post_rk0},{msb31_post_rk0}), "
            f"post_1R=({msb15_post_1r},{msb31_post_1r})"
        )
        assert msb15_in == 0 and msb31_in == 0
        # Após rk[0], o MSB de state[15] e state[31] é constante (= MSB(rk0[15]), MSB(rk0[31]))
        assert msb15_post_rk0 in (0, n_samples)
        assert msb31_post_rk0 in (0, n_samples)
        # Após 1R (S-box + M_CAUCHY_32), o viés de 1 bit se dissipa (~50%)
        assert 85 <= msb15_post_1r <= 171
        assert 85 <= msb31_post_1r <= 171

    def test_04_algebraic_anf_degree_and_integral_division_property(self) -> None:
        """
        1. Mede o grau ANF exato de sbox_v5_eval (com A_16) via transformada de Möbius sobre GF(2)^16.
        2. Testa recuperação algébrica em 1R (rk[1] dado rk[0]) vs complexidade em 2R-3R.
        3. Executa ataque Integral / Division Property (Lambda-set de 2^16 textos em 1 palavra)
           em 1R, 2R, 3R e 4R via núcleo C99 AVX2.
        """
        # Valida consistência da LUT SBOX_LUT contra sbox_v5_eval em 256 pontos
        for x in range(0, 65536, 257):
            assert int(SBOX_LUT[x]) == sbox_v5_eval(x)

        # Transformada de Möbius para ANF sobre GF(2)^16
        anf = SBOX_LUT.copy()
        for i in range(16):
            step = 1 << i
            view = anf.reshape(-1, 2 * step)
            view[:, step:] ^= view[:, :step]

        degrees = []
        popcounts = np.array([int(idx).bit_count() for idx in range(65536)], dtype=np.int32)
        for bit in range(16):
            mask_nonzero = ((anf >> bit) & 1) != 0
            deg = int(popcounts[mask_nonzero].max())
            degrees.append(deg)
        print(f"[ANF DEGREE] Graus das 16 coordenadas de sbox_v5_eval: {degrees}")
        assert all(d == 15 for d in degrees), "Todas as 16 coordenadas devem ter grau algébrico máximo 15"

        # Recuperação algébrica de rk[1] em 1R dado rk[0] (1 consulta) + contagem estrutural 2R-3R (sem solver SAT/MILP)
        lib = _load_c_lib()
        rk_full, rc_full = _prepare_key_schedule(s=b"\x44" * 32, n_sess=77, rounds=R_V5)
        p = np.arange(W, dtype=np.uint16) * 17
        _, c_1r = _call_c_core(lib, p, rk_full[: 2 * W], rc_full[:1], 1)
        sub_known = np.array([SBOX_LUT[int(p[i] ^ rk_full[i])] ^ rc_full[0] for i in range(W)], dtype=np.uint16)
        recovered_rk1 = np.bitwise_xor(c_1r, _mds_mult_matrix(M_CAUCHY_32, sub_known))
        assert np.array_equal(recovered_rk1, rk_full[W : 2 * W])
        # Cada S-box de 16 bits possui grau ANF 15; em r rodadas há 32*r S-boxes (512*r bits não-lineares).
        sboxes_2r, sboxes_3r, sboxes_8r = 32 * 2, 32 * 3, 32 * 8
        print(
            f"[ALGEBRAIC COMPLEXITY] 1R rk[1] recuperada em 1 consulta (rk[0] conhecido); "
            f"S-boxes ativas totais: 2R={sboxes_2r}, 3R={sboxes_3r}, 8R={sboxes_8r} (sem solver SAT/MILP)"
        )

        # Integral / Division Property (Lambda-set de 2^16 textos na palavra 0)
        base_in = np.zeros(W, dtype=np.uint16)
        base_in[1:] = np.arange(1, W, dtype=np.uint16) * 0x0101
        in_buf = base_in.copy()
        out_buf = np.zeros(W, dtype=np.uint16)
        in_ptr = in_buf.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16))
        out_ptr = out_buf.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16))

        integral_nonzero_words = {}
        for r in (1, 2, 3, 4):
            rk_r = rk_full[: (r + 1) * W]
            rc_r = rc_full[:r]
            rk_ptr = rk_r.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16))
            rc_ptr = rc_r.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16))

            xor_acc = np.zeros(W, dtype=np.uint16)
            for v in range(65536):
                in_buf[0] = v
                status = lib.rsd_s_v5_core_ct(in_ptr, rk_ptr, rc_ptr, r, -1, 0, out_ptr)
                assert status == 0
                xor_acc ^= out_buf
            nonzero = int(np.count_nonzero(xor_acc))
            integral_nonzero_words[r] = nonzero
            print(f"[INTEGRAL/SQUARE {r}R] palavras com soma XOR != 0: {nonzero}/{W}")

        assert integral_nonzero_words[1] == 0, "1R deve preservar propriedade integral (soma XOR == 0)"
        assert integral_nonzero_words[2] == 0, "2R deve preservar propriedade integral (soma XOR == 0)"
        assert integral_nonzero_words[3] > 0, "3R quebra a propriedade integral de 1 palavra"
        assert integral_nonzero_words[4] > 0, "4R quebra a propriedade integral de 1 palavra"


# =============================================================================
# FRENTE 2 — IMPLEMENTAÇÃO / FAULT / SIDE-CHANNEL / API
# =============================================================================


class TestFrente2ImplementacaoFaultSideChannelAPI:
    """Auditoria ofensiva de falhas, concorrência, assembly AVX2, timing, folding e API."""

    def test_05_dfa_sifa_penultimate_round_r7_bypass(self) -> None:
        """
        DFA / SIFA na rodada R-1 (R7) — achado RT-F2-01 (Alto), corrigido na v5.2:
          - Falha na rodada final R=8 é bloqueada (FaultDetectedError em Python, rc == -2 em C99).
          - Falha transitória DENTRO da execução, na entrada de QUALQUER rodada r = 1..8
            (incluindo R-1 = R7), é detectada: os fluxos A e B percorrem R1..R e divergem.
            Na v5.1 a duplicação só começava na rodada final e a falha em R7 passava despercebida.
          - Limite declarado (não é contorno da correção): se o estado for corrompido FORA do núcleo,
            entre duas chamadas, a segunda chamada recebe uma entrada já corrompida e nenhuma
            redundância interna pode distingui-la de uma entrada legítima (especificação, §2.4).
          - fault_mask == 0 com fault_word >= 0 retorna rc == 0.
        """
        lib_path = _ensure_c_lib()
        s = b"\x55" * 32
        n_sess = 4242
        x = 0x123456789ABCDEF0123456789ABCDEF0
        y = 0xFEDCBA9876543210FEDCBA9876543210

        # 1) Python: falha em R8 é bloqueada
        def _inject_bit0(st: np.ndarray) -> np.ndarray:
            st[0] ^= 0x0001
            return st

        with pytest.raises(FaultDetectedError):
            diffuse_rsd_s_v5_pre_sha(x, y, s, n_sess, rounds=8, fault_injector=_inject_bit0)

        # 2) C99: falha em R8 é bloqueada (rc == -2 e out_state zerado)
        rc_r8_fault, out_r8_fault = run_c_core_pre_sha(
            lib_path, x, y, s, n_sess, rounds=8, inject_fault_word=0, inject_fault_mask=0x0001
        )
        assert rc_r8_fault == -2
        assert np.all(out_r8_fault == 0)

        # 3) C99: fault_mask == 0 com fault_word >= 0 não dispara erro
        rc_zero_mask, out_clean = run_c_core_pre_sha(
            lib_path, x, y, s, n_sess, rounds=8, inject_fault_word=0, inject_fault_mask=0
        )
        assert rc_zero_mask == 0

        # 4) RT-F2-01 corrigido: falha injetada DENTRO da execução, em cada rodada 1..8, é detectada
        #    em C99 (rc == -2, saída zerada) e em Python (FaultDetectedError).
        for r_falha in range(1, 9):
            rc_f, out_f = run_c_core_pre_sha(
                lib_path, x, y, s, n_sess, rounds=8,
                inject_fault_word=0, inject_fault_mask=0x0001, inject_fault_round=r_falha,
            )
            assert rc_f == -2 and np.all(out_f == 0), f"RT-F2-01: falha na rodada {r_falha} deveria ser detectada"
            with pytest.raises(FaultDetectedError):
                diffuse_rsd_s_v5_pre_sha(
                    x, y, s, n_sess, rounds=8, fault_injector=_inject_bit0, fault_round=r_falha
                )
        print("[DFA RT-F2-01 CORRIGIDO] falha dentro da execução detectada nas rodadas 1..8 (C99 e Python)")

        # 5) Limite declarado: corrupção do estado ENTRE duas chamadas do núcleo.
        #    O cenário abaixo reproduz a prova de conceito da v5.1 (rodadas 1..7 numa chamada, estado
        #    corrompido fora do núcleo, rodada 8 em outra chamada). A segunda chamada recebe uma
        #    entrada já corrompida, que nenhuma redundância interna distingue de uma entrada legítima.
        #    Simula execução das rodadas 1..7 com falha injetada na entrada de R7 (antes da rodada 7)
        #    e depois executa a rodada final R8 com redundância Anti-DFA intacta.
        lib = _load_c_lib()
        rk_full, rc_full = _prepare_key_schedule(s=s, n_sess=n_sess, rounds=8)
        in_state = fragment_full_v5(x, y)

        # Executa R1..R6 normalmente, injeta falha na entrada de R7, executa R7 e depois R8 redundante:
        # Equivalente exato a rodar 7 rodadas (onde fault ocorre na entrada da rodada 7 -> NÃO detectado se
        # injetado antes de R7, ou corrompendo a saída de R7):
        # Aqui executamos R1..R7 via núcleo de 7 rodadas sem falha e corrompemos a saída de R7 (simulando
        # falha transitória durante R7), e alimentamos R8 (rodada final redundante).
        status_r7, state_after_r7 = _call_c_core(lib, in_state, rk_full[: 8 * W], rc_full[:7], 7)
        assert status_r7 == 0
        corrupted_r7 = state_after_r7.copy()
        corrupted_r7[0] ^= 0x0001  # falha ocorrida em R7 antes da bifurcação de R8

        # Rodada R8 isolada (passando rk_8_only = [0..0, rk[8]] e rc[7])
        rk_r8_only = np.concatenate([np.zeros(W, dtype=np.uint16), rk_full[8 * W : 9 * W]])
        rc_r8_only = np.array([rc_full[7]], dtype=np.uint16)
        status_r8_bypass, out_r8_corrupted = _call_c_core(
            lib, corrupted_r7, rk_r8_only, rc_r8_only, 1, fault_word=-1, fault_mask=0
        )
        print(
            f"[DFA LIMITE ENTRE CHAMADAS] status_r8={status_r8_bypass} (esperado 0), "
            f"out_corrompida != out_limpa: {not np.array_equal(out_r8_corrupted, out_clean)}"
        )
        assert status_r8_bypass == 0, (
            "Limite declarado: estado corrompido entre chamadas é aceito como entrada legítima "
            "(fora do modelo do Anti-DFA; ver especificação §2.4)"
        )
        assert not np.array_equal(out_r8_corrupted, out_clean)

        # Mesmo bypass em Python (usando as mesmas chaves/constantes de rounds=8):
        from rsd_s_v5_hardened import _single_round_v5  # noqa: E402

        state_py = np.bitwise_xor(in_state, rk_full[:W])
        for r_idx in range(1, 8):
            state_py = _single_round_v5(state_py, int(rc_full[r_idx - 1]), rk_full[r_idx * W : (r_idx + 1) * W])
        assert np.array_equal(state_py, state_after_r7)
        state_py_corrupted = state_py.copy()
        state_py_corrupted[0] ^= 0x0001
        # Rodada R8 em Python compara state_a_in == state_b_in (ambos recebem state_py_corrupted)
        py_out_corrupted = _single_round_v5(state_py_corrupted, int(rc_full[7]), rk_full[8 * W : 9 * W])
        assert np.array_equal(py_out_corrupted, out_r8_corrupted)

    def test_06_concurrency_data_race_tsan_cache_size_and_avx2_objdump(self) -> None:
        """
        1. Compila harness C com -fsanitize=thread e 16 pthreads simultâneas chamando rsd_s_v5_core_ct
           para detectar o data race real em CAUCHY_INIT / CAUCHY_MDS / CAUCHY_BIT_BASIS.
        2. Verifica sizeof(CAUCHY_BIT_BASIS) == 32768 bytes (32 KB L1D).
        3. Inspeciona assembly de rsd_s_v5_core_ct via objdump -d para verificar limpeza de ymm.
        """
        BUILD_DIR.mkdir(parents=True, exist_ok=True)
        harness_c = BUILD_DIR / "tsan_race_harness.c"
        harness_bin = BUILD_DIR / "tsan_race_harness"
        harness_c.write_text(
            """
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

int rsd_s_v5_core_ct(const uint16_t *in_state, const uint16_t *rk_flat, const uint16_t *rc,
                     int rounds, int fault_word, uint16_t fault_mask, uint16_t *out_state);

static void *worker(void *arg) {
    (void)arg;
    uint16_t in_s[32] = {1};
    uint16_t rk[9 * 32] = {0};
    uint16_t rc[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint16_t out_s[32] = {0};
    rsd_s_v5_core_ct(in_s, rk, rc, 8, -1, 0, out_s);
    return NULL;
}

int main(void) {
    pthread_t th[16];
    for (int i = 0; i < 16; ++i) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < 16; ++i) pthread_join(th[i], NULL);
    return 0;
}
""",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "gcc",
                "-O1",
                "-g",
                "-fsanitize=thread",
                str(harness_c),
                str(C_SRC),
                "-lpthread",
                "-o",
                str(harness_bin),
            ],
            check=True,
        )
        proc = subprocess.run(
            ["setarch", "x86_64", "-R", str(harness_bin)],
            capture_output=True,
            text=True,
            check=False,
        )
        tsan_log = proc.stderr + proc.stdout
        race_detected = "ThreadSanitizer: data race" in tsan_log
        print(f"[TSAN DATA RACE] exit={proc.returncode}, race_detected={race_detected}")
        if race_detected:
            for line in tsan_log.splitlines()[:15]:
                print("  TSAN:", line)
        assert proc.returncode == 0 and not race_detected, (
            "RT-F2-02 corrigido: TSan não deve detectar data race em init_cauchy_mds()"
        )

        # Verifica tamanho exato de CAUCHY_BIT_BASIS[32][16][32] * sizeof(uint16_t)
        cauchy_bit_basis_bytes = 32 * 16 * 32 * 2
        assert cauchy_bit_basis_bytes == 32768
        print(f"[CACHE FOOTPRINT] sizeof(CAUCHY_BIT_BASIS) = {cauchy_bit_basis_bytes} bytes (32 KB L1D)")

        # Inspeção de assembly via objdump -d
        so_path = _ensure_c_lib()
        asm_proc = subprocess.run(
            ["objdump", "-d", str(so_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        asm_text = asm_proc.stdout
        # Extrai seção da função rsd_s_v5_core_ct
        in_fn = False
        fn_lines: list[str] = []
        for line in asm_text.splitlines():
            if "<rsd_s_v5_core_ct>:" in line:
                in_fn = True
                continue
            if in_fn:
                if line.strip() == "" or (line.endswith(">:") and "<" in line):
                    break
                fn_lines.append(line)
        fn_asm = "\n".join(fn_lines)
        uses_ymm = "ymm" in fn_asm
        ret_indices = [idx for idx, ln in enumerate(fn_lines) if "\tret" in ln or ln.strip().endswith("ret")]
        assert len(ret_indices) >= 1, "Função deve conter instrução ret"
        main_ret_idx = ret_indices[0]
        pre_ret_window = "\n".join(fn_lines[max(0, main_ret_idx - 15) : main_ret_idx])
        has_vzeroupper_before_ret = "vzeroupper" in pre_ret_window
        clears_xmm_before_ret = ("vzeroall" in pre_ret_window) or (
            "vpxor" in pre_ret_window and ("xmm" in pre_ret_window or "ymm" in pre_ret_window)
        )
        print(
            f"[OBJDUMP AVX2] fn_lines={len(fn_lines)}, uses_ymm={uses_ymm}, "
            f"has_vzeroupper_before_ret={has_vzeroupper_before_ret}, "
            f"clears_xmm_before_ret={clears_xmm_before_ret}"
        )
        assert uses_ymm, "Núcleo compilado com -mavx2 deve usar registradores ymm"
        assert has_vzeroupper_before_ret, "Compilador emite vzeroupper antes do ret principal (limpa apenas bits 128..255)"
        assert not clears_xmm_before_ret, (
            "Confirmado: rsd_s_v5_core_ct NÃO emite vzeroall/vpxor para zerar xmm0..xmm15 (bits 0..127) antes do ret"
        )

    def test_07_python_folding_timing_welch_and_2to1_collision(self) -> None:
        """
        1. Mede vazamento de timing (teste t de Welch, ordem aleatorizada) em _unpadded_z65537_to_bytes64:
           - Cenário (a) pior caso: 0/32 vs 32/32 palavras == 65536.
           - Cenário (b) realista: 0/32 vs 1/32 palavra == 65536.
        2. Demonstra colisão 2-para-1 estrutural na função isolada _unpadded_z65537_to_bytes64 (fixado s_priv_bytes),
           ressaltando que no BandlimitedDualKeyEngine completo entradas (x, y) distintas geram s_priv_bytes distintos.
        """
        s_priv_bytes = b"\x77" * 64
        n_sess = 1001
        vec_0 = np.full(W, 12345, dtype=np.int64)
        vec_1 = np.full(W, 12345, dtype=np.int64)
        vec_1[0] = 65536
        vec_32 = np.full(W, 65536, dtype=np.int64)

        for _ in range(300):
            _unpadded_z65537_to_bytes64(vec_0, s_priv_bytes, n_sess)
            _unpadded_z65537_to_bytes64(vec_1, s_priv_bytes, n_sess)
            _unpadded_z65537_to_bytes64(vec_32, s_priv_bytes, n_sess)

        rng = np.random.default_rng(707)
        n_trials = 1500

        def _measure_randomized(vec_a: np.ndarray, vec_b: np.ndarray) -> tuple[float, float, float, float]:
            order = rng.permutation(np.array([0] * n_trials + [1] * n_trials))
            ta: list[float] = []
            tb: list[float] = []
            for cls_id in order:
                v = vec_a if cls_id == 0 else vec_b
                t0 = time.perf_counter_ns()
                _unpadded_z65537_to_bytes64(v, s_priv_bytes, n_sess)
                dt = float(time.perf_counter_ns() - t0)
                if cls_id == 0:
                    ta.append(dt)
                else:
                    tb.append(dt)
            t_stat, p_val = stats.ttest_ind(np.array(tb), np.array(ta), equal_var=False)
            return float(np.mean(ta)), float(np.mean(tb)), float(t_stat), float(p_val)

        m0_a, m32, t_worst, p_worst = _measure_randomized(vec_0, vec_32)
        m0_b, m1, t_real, p_real = _measure_randomized(vec_0, vec_1)
        print(
            f"[TIMING FOLDING WORST 0/32 vs 32/32] mean0={m0_a:.1f} ns, mean32={m32:.1f} ns, "
            f"Welch t={t_worst:.2f}, p={p_worst:.2e}"
        )
        print(
            f"[TIMING FOLDING REALISTIC 0/32 vs 1/32] mean0={m0_b:.1f} ns, mean1={m1:.1f} ns, "
            f"Welch t={t_real:.2f}, p={p_real:.2e}"
        )
        assert abs(t_worst) < 4.5, f"RT-F2-04 mitigado: |t_worst| esperado < 4.5, obtido {t_worst:.2f}"
        assert abs(t_real) < 4.5, f"RT-F2-04 mitigado: |t_real| esperado < 4.5, obtido {t_real:.2f}"

        # Colisão 2-para-1 na função isolada _unpadded_z65537_to_bytes64 (fixado s_priv_bytes)
        vec_a = np.zeros(W, dtype=np.int64)
        vec_a[0] = 65536
        fallback_0 = int.from_bytes(
            shake_256(
                b"RSD-S-V5|DUALKEY|" + b"FOLD16|V5.2|" + n_sess.to_bytes(8, "big") + s_priv_bytes
            ).digest(2),
            "big",
        )
        vec_b = np.zeros(W, dtype=np.int64)
        vec_b[0] = fallback_0
        assert not np.array_equal(vec_a, vec_b)

        bytes_a = _unpadded_z65537_to_bytes64(vec_a, s_priv_bytes, n_sess)
        bytes_b = _unpadded_z65537_to_bytes64(vec_b, s_priv_bytes, n_sess)
        assert bytes_a == bytes_b, "Colisão 2-para-1 confirmada em y_pub_bytes (64B) para s_priv_bytes fixo"

        z_a = b"".join(int(v).to_bytes(3, "big") for v in vec_a)
        z_b = b"".join(int(v).to_bytes(3, "big") for v in vec_b)
        dig_a = sha256(b"RSD-S-V5|DUALKEY|dual_key_stochastic_hardened" + z_a).digest()
        dig_b = sha256(b"RSD-S-V5|DUALKEY|dual_key_stochastic_hardened" + z_b).digest()
        assert z_a != z_b and dig_a != dig_b
        print(
            f"[FOLDING 2-TO-1 COLLISION] Em função isolada (s_priv_bytes fixo), vec_a[0]=65536 colide com "
            f"vec_b[0]={fallback_0} em 64B, mas 96B/SHA256 distinguem."
        )

    def test_08_api_s_priv_exposure_and_boundary_fuzzing(self) -> None:
        """
        1. Valida mitigação de RT-F2-03: BandlimitedDualKeyEngine.refactor_public_output
           NÃO expõe s_priv_state no retorno público padrão, e expõe apenas com include_private_debug=True.
        2. Executa fuzzing de fronteira em x, y, n_sess, rounds, output_bytes, s, mode e _unpadded_z65537_to_bytes64.
        """
        engine = BandlimitedDualKeyEngine()
        s_valid = b"\x88" * 32
        res = engine.refactor_public_output(123, 456, s_valid, 1)
        assert "s_priv_state" not in res, "RT-F2-03 mitigado: retorno público não deve expor s_priv_state"
        res_debug = engine.refactor_public_output(123, 456, s_valid, 1, include_private_debug=True)
        expected_s_priv = diffuse_rsd_s_v5_pre_sha(123, 456, s_valid, 1)
        assert "s_priv_state" in res_debug and np.array_equal(res_debug["s_priv_state"], expected_s_priv)
        print("[API RT-F2-03 MITIGADO] refactor_public_output omite 's_priv_state' por padrão; disponível apenas via include_private_debug=True!")

        # Boundary fuzzing (casos inválidos e válidos)
        checks = 0
        invalid_field_cases = [
            (-1, ValueError),
            (P_CURVE25519, ValueError),
            (P_CURVE25519 + 12345, ValueError),
            (True, TypeError),
            (False, TypeError),
            (1.5, TypeError),
            ("123", TypeError),
        ]
        for bad_val, exc_type in invalid_field_cases:
            with pytest.raises(exc_type):
                diffuse_rsd_s_v5(bad_val, 0, s_valid, 0)  # type: ignore[arg-type]
            checks += 1
            with pytest.raises(exc_type):
                diffuse_rsd_s_v5(0, bad_val, s_valid, 0)  # type: ignore[arg-type]
            checks += 1

        invalid_sess_cases = [
            (-1, ValueError),
            (2**64, ValueError),
            (True, TypeError),
            ("0", TypeError),
        ]
        for bad_sess, exc_type in invalid_sess_cases:
            with pytest.raises(exc_type):
                diffuse_rsd_s_v5(1, 2, s_valid, bad_sess)  # type: ignore[arg-type]
            checks += 1

        invalid_rounds_cases = [
            (0, ValueError),
            (-1, ValueError),
            (256, ValueError),
            (True, TypeError),
        ]
        for bad_r, exc_type in invalid_rounds_cases:
            with pytest.raises(exc_type):
                diffuse_rsd_s_v5(1, 2, s_valid, 0, rounds=bad_r)  # type: ignore[arg-type]
            checks += 1

        for bad_out in (0, 16, 31, 63, 128):
            with pytest.raises(ValueError):
                diffuse_rsd_s_v5(1, 2, s_valid, 0, output_bytes=bad_out)
            checks += 1

        for bad_key, exc_type in ((b"\x00" * 31, ValueError), (b"\x00" * 33, ValueError), ("abc", TypeError)):
            with pytest.raises(exc_type):
                diffuse_rsd_s_v5(1, 2, bad_key, 0)  # type: ignore[arg-type]
            checks += 1

        with pytest.raises(ValueError):
            engine.refactor_public_output(1, 2, s_valid, 0, mode="invalid_mode")  # type: ignore[arg-type]
        checks += 1

        # Fronteiras válidas
        assert len(diffuse_rsd_s_v5(0, P_CURVE25519 - 1, s_valid, 0, rounds=1, output_bytes=32)) == 32
        checks += 1
        assert len(diffuse_rsd_s_v5(P_CURVE25519 - 1, 0, s_valid, 2**64 - 1, rounds=255, output_bytes=64)) == 64
        checks += 1

        # verify_public_output válido vs inválido
        assert engine.verify_public_output(123, 456, s_valid, 1, res["y_pub_bytes"]) is True  # type: ignore[arg-type]
        checks += 1
        assert engine.verify_public_output(123, 456, s_valid, 1, b"\x00" * 64) is False
        checks += 1

        # _unpadded_z65537_to_bytes64 com entradas fora de Z_65537 (RT-F2-04: rejeição explícita com ValueError)
        neg_vec = np.zeros(W, dtype=np.int64)
        neg_vec[0] = -1
        with pytest.raises(ValueError):
            _unpadded_z65537_to_bytes64(neg_vec, b"\x00" * 64, 0)
        checks += 1
        over_vec = np.zeros(W, dtype=np.int64)
        over_vec[0] = 65537
        with pytest.raises(ValueError):
            _unpadded_z65537_to_bytes64(over_vec, b"\x00" * 64, 0)
        checks += 1

        # Fronteiras da API C (rounds inválidos, NULL, fault_word=32)
        lib = _load_c_lib()
        rk_full, rc_full = _prepare_key_schedule(s=s_valid, n_sess=1, rounds=8)
        in_st = fragment_full_v5(1, 2)
        rc0, _ = _call_c_core(lib, in_st, rk_full, rc_full, 0)
        assert rc0 == -1
        checks += 1
        rc256, _ = _call_c_core(lib, in_st, rk_full, rc_full, 256)
        assert rc256 == -1
        checks += 1
        out_dummy = np.zeros(W, dtype=np.uint16)
        rc_null = lib.rsd_s_v5_core_ct(
            None,
            rk_full.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            rc_full.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            8,
            -1,
            0,
            out_dummy.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
        )
        assert rc_null == -1
        checks += 1
        rc_fw32, _ = _call_c_core(lib, in_st, rk_full, rc_full, 8, fault_word=32, fault_mask=0xFFFF)
        assert rc_fw32 == 0
        checks += 1

        print(f"[BOUNDARY FUZZING] {checks}/{checks} casos de fronteira (inválidos, válidos e API C) verificados.")
