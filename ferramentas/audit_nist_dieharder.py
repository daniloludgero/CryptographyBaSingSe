#!/usr/bin/env python3
"""
ferramentas/audit_nist_dieharder.py

Implementação autônoma, rigorosa e estatisticamente fiel dos 10 testes centrais
da suíte NIST SP 800-22 Rev 1a para avaliação da primitiva RSD-S v4.

Não requer SciPy. Implementa expansões em série e frações contínuas de alta
precisão (critério de convergência 1e-15) para a função gama incompleta
superior regularizada Q(s, x) e para a distribuição normal padrão Phi(x).

Suporta geração de fluxos de bits:
- Pré-SHA: estado SPN interno puro de 512 bits (32 palavras x 16 bits).
- Pós-SHA: digest de saída de 256 bits (SHA-256).
- Análise de rodadas reduzidas (1, 2 ou 4 rodadas).
- Exportação para arquivo binário cru compatível com Dieharder / NIST STS.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Callable

import numpy as np

# Configura caminhos do repositório
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "implementacao"))

from rsd_s_v4_final import (  # noqa: E402
    diffuse_rsd_s_rounds,
    diffuse_rsd_s_rounds_PRE_SHA,
    get_base_inversion_sbox,
    derive_keys,
    round_constant,
    fragment_full,
    _expand_key_words,
    _hash_state,
    W,
    B,
    P_CURVE25519,
)
from mds_bitmatrix import mds_bit_rows  # noqa: E402


# ==============================================================================
# 1. FUNÇÕES NUMÉRICAS AUTÔNOMAS DE ALTA PRECISÃO (Sem dependência de SciPy)
# ==============================================================================

def gammaincc(s: float, x: float) -> float:
    """
    Função Gama Incompleta Superior Regularizada Q(s, x) = Gamma(s, x) / Gamma(s).
    
    Complemento da CDF qui-quadrado para graus de liberdade nu = 2*s:
        p-valor = Q(nu / 2, chi2 / 2)
        
    Implementação bifurcada:
    - Para x < s + 1: expansão em série para P(s, x) e retorno de 1.0 - P(s, x).
    - Para x >= s + 1: fração contínua de Lentz modificada para Q(s, x).
    """
    if x < 0.0 or s <= 0.0:
        raise ValueError(f"Argumentos inválidos para gammaincc: s={s}, x={x}")
    if x == 0.0:
        return 1.0

    if x < s + 1.0:
        # Expansão em série de Pearson para P(s, x)
        sum_val = 1.0 / s
        term = 1.0 / s
        for n in range(1, 1000):
            term = term * x / (s + n)
            sum_val += term
            if abs(term) < abs(sum_val) * 1e-15:
                break
        log_factor = -x + s * math.log(x) - math.lgamma(s)
        p = math.exp(log_factor) * sum_val
        q = 1.0 - p
        return max(0.0, min(1.0, q))
    else:
        # Fração contínua de Lentz modificada para Q(s, x)
        TINY = 1e-30
        b = x + 1.0 - s
        c = 1.0 / TINY
        d = 1.0 / b
        h = d
        for i in range(1, 1000):
            an = -i * (i - s)
            b += 2.0
            d = an * d + b
            if abs(d) < TINY:
                d = TINY
            c = b + an / c
            if abs(c) < TINY:
                c = TINY
            d = 1.0 / d
            del_val = d * c
            h *= del_val
            if abs(del_val - 1.0) < 1e-15:
                break
        log_factor = -x + s * math.log(x) - math.lgamma(s)
        q = math.exp(log_factor) * h
        return max(0.0, min(1.0, q))


def normal_cdf(x: float) -> float:
    """Distribuição Normal Padrão Acumulada Phi(x) = 0.5 * (1 + erf(x / sqrt(2)))."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def normal_erfc(x: float) -> float:
    """Complementar erfc(x / sqrt(2)) correspondente a 2 * (1 - Phi(x))."""
    return math.erfc(x / math.sqrt(2.0))


# ==============================================================================
# 2. MOTOR BOLEANO ACELERADO BIT-MATRIX (Bit-Exact com RSD-S v4)
# ==============================================================================

_MDS_BIT_MATRIX_U64: np.ndarray | None = None


def get_mds_bit_matrix_u64() -> np.ndarray:
    """Gera matriz booleana 512x8 uint64 correspondente à MDS Cauchy 32x32."""
    global _MDS_BIT_MATRIX_U64
    if _MDS_BIT_MATRIX_U64 is None:
        rows = mds_bit_rows()
        mat = np.zeros((512, 8), dtype=np.uint64)
        for i, sources in enumerate(rows):
            for s in sources:
                mat[i, s // 64] |= np.uint64(1 << (s % 64))
        mat.flags.writeable = False
        _MDS_BIT_MATRIX_U64 = mat
    return _MDS_BIT_MATRIX_U64


def fast_state_to_u64(state: np.ndarray) -> np.ndarray:
    u64 = np.zeros(8, dtype=np.uint64)
    for i in range(32):
        u64[i // 4] |= np.uint64(int(state[i]) << ((i % 4) * 16))
    return u64


def fast_u64_to_state(parities: np.ndarray) -> np.ndarray:
    state = np.zeros(32, dtype=np.uint64)
    for i in range(32):
        val = 0
        for b in range(16):
            if parities[i * 16 + b]:
                val |= (1 << b)
        state[i] = val
    return state


def fast_diffuse_state(x: int, y: int, s: bytes, n_sess: int, rounds: int) -> np.ndarray:
    """Difusão 100% bit-exact com _diffuse_state, otimizada via bit-matrix."""
    state = fragment_full(x, y)
    keys = derive_keys(s, n_sess, rounds)
    state ^= _expand_key_words(keys[0], W)
    base_sbox = get_base_inversion_sbox()
    mat_u64 = get_mds_bit_matrix_u64()

    for r in range(1, rounds + 1):
        rc = round_constant(s, n_sess, r)
        state = base_sbox[state] ^ rc

        # MDS bit-matrix
        x_u64 = fast_state_to_u64(state)
        anded = mat_u64 & x_u64
        acc = (
            anded[:, 0] ^ anded[:, 1] ^ anded[:, 2] ^ anded[:, 3] ^
            anded[:, 4] ^ anded[:, 5] ^ anded[:, 6] ^ anded[:, 7]
        )
        acc ^= (acc >> np.uint64(32))
        acc ^= (acc >> np.uint64(16))
        acc ^= (acc >> np.uint64(8))
        acc ^= (acc >> np.uint64(4))
        acc ^= (acc >> np.uint64(2))
        acc ^= (acc >> np.uint64(1))
        parities = (acc & np.uint64(1)).astype(np.uint8)
        state = fast_u64_to_state(parities)

        state ^= _expand_key_words(keys[r], W)

    return state


# ==============================================================================
# 3. GERADOR DE FLUXOS DE BITS (PRE-SHA E POST-SHA)
# ==============================================================================

def generate_bitstream(
    mode: str,
    rounds: int = 4,
    length: int = 1_000_000,
    key: bytes | None = None,
    x0: int = 0x123456789ABCDEF,
    y0: int = 0xFEDCBA987654321,
) -> np.ndarray:
    """
    Gera um bitstream contínuo de tamanho exato 'length' bits.
    
    mode: 'pre_sha' (512 bits por chamada) ou 'post_sha' (256 bits por chamada).
    """
    if mode not in ("pre_sha", "post_sha"):
        raise ValueError(f"Modo desconhecido: {mode}")
    if key is None:
        key = b"RSD_S_V4_NIST_AUDIT_KEY_2026_M1!"  # exatamente 32 bytes

    chunks: list[np.ndarray] = []
    total_bits = 0
    n_sess = 0
    shifts_16 = np.arange(15, -1, -1, dtype=np.uint16)

    while total_bits < length:
        state = fast_diffuse_state(x0, y0, key, n_sess, rounds)
        if mode == "pre_sha":
            words = state.astype(np.uint16)
            bits_chunk = ((words[:, None] >> shifts_16) & 1).astype(np.uint8).ravel()
        else:
            digest = _hash_state(state)
            bits_chunk = np.unpackbits(np.frombuffer(digest, dtype=np.uint8))
        chunks.append(bits_chunk)
        total_bits += len(bits_chunk)
        n_sess += 1

    return np.concatenate(chunks)[:length]


def export_binary_file(bits: np.ndarray, file_path: Path | str) -> None:
    """Exporta bitstream no formato binário cru (8 bits por byte, big-endian)."""
    p = Path(file_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Empacota múltiplos de 8
    pad_len = (8 - (len(bits) % 8)) % 8
    if pad_len != 0:
        bits = np.pad(bits, (0, pad_len), "constant", constant_values=0)
    byte_vals = np.packbits(bits)
    p.write_bytes(byte_vals.tobytes())


# ==============================================================================
# 4. OS 10 TESTES DO NIST SP 800-22 Rev 1a
# ==============================================================================

@dataclass
class NistTestResult:
    test_id: int
    name: str
    statistic: float
    p_value: float
    degrees_of_freedom: int | None
    passed: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def test_monobit(bits: np.ndarray) -> NistTestResult:
    """NIST SP 800-22 §2.1: Frequency (Monobit) Test."""
    n = len(bits)
    s_n = int(np.sum(2 * bits.astype(np.int64) - 1))
    s_obs = abs(s_n) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2.0))
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=1,
        name="Frequency (Monobit)",
        statistic=s_obs,
        p_value=p_value,
        degrees_of_freedom=None,
        passed=passed,
        details={"S_n": s_n, "n": n, "proportion_ones": float(np.mean(bits))},
    )


def test_block_frequency(bits: np.ndarray, block_size: int = 128) -> NistTestResult:
    """NIST SP 800-22 §2.2: Frequency Test within a Block."""
    n = len(bits)
    m = block_size
    N = n // m
    if N == 0:
        raise ValueError(f"Sequência muito curta ({n}) para bloco de tamanho {m}")
    
    blocks = bits[: N * m].reshape((N, m))
    proportions = np.mean(blocks, axis=1)
    chi2 = float(4.0 * m * np.sum((proportions - 0.5) ** 2))
    p_value = gammaincc(N / 2.0, chi2 / 2.0)
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=2,
        name="Block Frequency",
        statistic=chi2,
        p_value=p_value,
        degrees_of_freedom=N,
        passed=passed,
        details={"M": m, "N_blocks": N, "chi2": chi2},
    )


def test_runs(bits: np.ndarray) -> NistTestResult:
    """NIST SP 800-22 §2.3: Runs Test."""
    n = len(bits)
    pi = float(np.mean(bits))
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return NistTestResult(
            test_id=3,
            name="Runs",
            statistic=0.0,
            p_value=0.0,
            degrees_of_freedom=None,
            passed=False,
            details={"pi": pi, "tau": tau, "pre_test_failed": True},
        )
    
    # Conta transições V_n = 1 + sum(bits[k] != bits[k+1])
    diffs = np.count_nonzero(bits[:-1] != bits[1:])
    v_n = diffs + 1
    numerator = abs(v_n - 2.0 * n * pi * (1.0 - pi))
    denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    p_value = math.erfc(numerator / denominator)
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=3,
        name="Runs",
        statistic=float(v_n),
        p_value=p_value,
        degrees_of_freedom=None,
        passed=passed,
        details={"V_n": int(v_n), "pi": pi},
    )


def test_longest_run_of_ones(bits: np.ndarray, block_size: int = 128) -> NistTestResult:
    """NIST SP 800-22 §2.4: Test for the Longest Run of Ones in a Block."""
    n = len(bits)
    m = block_size  # M = 128, K = 5 (6 bins)
    k_bins = 5
    n_blocks = n // m
    if n_blocks == 0:
        raise ValueError("Sequência muito curta para Longest Run (M=128)")
    
    pi_values = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
    counts = np.zeros(6, dtype=np.int64)

    for i in range(n_blocks):
        block = bits[i * m : (i + 1) * m]
        # Determina o maior bloco contíguo de 1s
        max_run = 0
        curr_run = 0
        for bit in block:
            if bit == 1:
                curr_run += 1
                if curr_run > max_run:
                    max_run = curr_run
            else:
                curr_run = 0
        
        if max_run <= 4:
            counts[0] += 1
        elif max_run == 5:
            counts[1] += 1
        elif max_run == 6:
            counts[2] += 1
        elif max_run == 7:
            counts[3] += 1
        elif max_run == 8:
            counts[4] += 1
        else:  # >= 9
            counts[5] += 1

    expected = n_blocks * np.array(pi_values)
    chi2 = float(np.sum(((counts - expected) ** 2) / expected))
    p_value = gammaincc(k_bins / 2.0, chi2 / 2.0)
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=4,
        name="Longest Run of Ones",
        statistic=chi2,
        p_value=p_value,
        degrees_of_freedom=k_bins,
        passed=passed,
        details={"bins": counts.tolist(), "expected": expected.tolist(), "chi2": chi2},
    )


def _binary_matrix_rank_32(rows: list[int]) -> int:
    """Eliminação Gaussiana sobre GF(2) para matriz 32x32."""
    rank = 0
    mat = list(rows)
    for col in range(32):
        mask = 1 << (31 - col)
        pivot = -1
        for r in range(rank, 32):
            if mat[r] & mask:
                pivot = r
                break
        if pivot >= 0:
            mat[rank], mat[pivot] = mat[pivot], mat[rank]
            pivot_row = mat[rank]
            for r in range(32):
                if r != rank and (mat[r] & mask):
                    mat[r] ^= pivot_row
            rank += 1
    return rank


def test_binary_matrix_rank(bits: np.ndarray, m: int = 32, q: int = 32) -> NistTestResult:
    """NIST SP 800-22 §2.5: Binary Matrix Rank Test."""
    n = len(bits)
    mat_size = m * q  # 1024 bits
    n_matrices = n // mat_size
    if n_matrices == 0:
        raise ValueError(f"Sequência muito curta ({n}) para matrizes {m}x{q}")
    
    f_m = 0      # rank = 32
    f_m_1 = 0    # rank = 31
    f_rem = 0    # rank <= 30

    for i in range(n_matrices):
        sub = bits[i * mat_size : (i + 1) * mat_size]
        rows: list[int] = []
        for r in range(32):
            row_bits = sub[r * 32 : (r + 1) * 32]
            val = 0
            for b in row_bits:
                val = (val << 1) | int(b)
            rows.append(val)
        
        rk = _binary_matrix_rank_32(rows)
        if rk == 32:
            f_m += 1
        elif rk == 31:
            f_m_1 += 1
        else:
            f_rem += 1

    p_32 = 0.2888
    p_31 = 0.5776
    p_rem = 0.1336
    e_32 = n_matrices * p_32
    e_31 = n_matrices * p_31
    e_rem = n_matrices * p_rem

    chi2 = float(
        ((f_m - e_32) ** 2) / e_32 +
        ((f_m_1 - e_31) ** 2) / e_31 +
        ((f_rem - e_rem) ** 2) / e_rem
    )
    # df = 2, Q(1, chi2/2) = exp(-chi2/2)
    p_value = math.exp(-chi2 / 2.0)
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=5,
        name="Binary Matrix Rank",
        statistic=chi2,
        p_value=p_value,
        degrees_of_freedom=2,
        passed=passed,
        details={"n_matrices": n_matrices, "F_32": f_m, "F_31": f_m_1, "F_rem": f_rem, "chi2": chi2},
    )


def test_spectral_dft(bits: np.ndarray) -> NistTestResult:
    """NIST SP 800-22 §2.6: Discrete Fourier Transform (Spectral) Test."""
    n = len(bits)
    x = 2 * bits.astype(np.float64) - 1.0
    s_fft = np.fft.fft(x)
    modulus = np.abs(s_fft[: n // 2])
    threshold = math.sqrt(math.log(1.0 / 0.05) * n)
    n0 = 0.95 * (n / 2.0)
    n1 = float(np.count_nonzero(modulus < threshold))
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    p_value = math.erfc(abs(d) / math.sqrt(2.0))
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=6,
        name="Spectral (DFT)",
        statistic=d,
        p_value=p_value,
        degrees_of_freedom=None,
        passed=passed,
        details={"N0": n0, "N1": n1, "d": d, "threshold": threshold},
    )


def test_non_overlapping_template(
    bits: np.ndarray,
    template_size: int = 9,
    block_size: int = 1024,
) -> NistTestResult:
    """NIST SP 800-22 §2.7: Non-overlapping Template Matching Test."""
    n = len(bits)
    m = template_size
    block_len = block_size
    n_blocks = n // block_len
    if n_blocks == 0:
        raise ValueError("Sequência muito curta para template matching")
    
    # Template não-periódico de 9 bits padrão NIST: '000000001'
    target = np.array([0, 0, 0, 0, 0, 0, 0, 0, 1], dtype=np.uint8)
    mu = (block_len - m + 1.0) / (2.0 ** m)
    var = block_len * (1.0 / (2.0 ** m) - (2.0 * m - 1.0) / (2.0 ** (2 * m)))

    w_counts: list[int] = []
    for i in range(n_blocks):
        blk = bits[i * block_len : (i + 1) * block_len]
        cnt = 0
        idx = 0
        while idx <= block_len - m:
            if np.array_equal(blk[idx : idx + m], target):
                cnt += 1
                idx += m
            else:
                idx += 1
        w_counts.append(cnt)

    chi2 = float(sum(((w - mu) ** 2) / var for w in w_counts))
    p_value = gammaincc(n_blocks / 2.0, chi2 / 2.0)
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=7,
        name="Non-overlapping Template",
        statistic=chi2,
        p_value=p_value,
        degrees_of_freedom=n_blocks,
        passed=passed,
        details={"template": "000000001", "N_blocks": n_blocks, "mu": mu, "chi2": chi2},
    )


def test_approximate_entropy(bits: np.ndarray, m: int = 5) -> NistTestResult:
    """NIST SP 800-22 §2.12: Approximate Entropy Test."""
    n = len(bits)
    if n < 100:
        raise ValueError("Tamanho mínimo de 100 bits para ApEn")

    def _compute_phi(k: int) -> float:
        aug = np.concatenate([bits, bits[: k - 1]])
        val = 0
        for j in range(k):
            val = (val << 1) | int(aug[j])
        mask = (1 << k) - 1
        counts = np.zeros(1 << k, dtype=np.int64)
        counts[val] += 1
        for j in range(k, n + k - 1):
            val = ((val << 1) & mask) | int(aug[j])
            counts[val] += 1
        probs = counts[counts > 0] / float(n)
        return float(np.sum(probs * np.log(probs)))

    phi_m = _compute_phi(m)
    phi_m1 = _compute_phi(m + 1)
    apen = phi_m - phi_m1
    chi2 = float(2.0 * n * (math.log(2.0) - apen))
    # df = 2^(m-1), parâmetro gama = 2^(m-2)
    p_value = gammaincc(2.0 ** (m - 2), chi2 / 2.0)
    passed = p_value >= 0.01
    return NistTestResult(
        test_id=8,
        name="Approximate Entropy",
        statistic=chi2,
        p_value=p_value,
        degrees_of_freedom=2 ** (m - 1),
        passed=passed,
        details={"m": m, "ApEn": apen, "chi2": chi2},
    )


def test_cumulative_sums(bits: np.ndarray) -> NistTestResult:
    """NIST SP 800-22 §2.13: Cumulative Sums (Cusum) Test."""
    n = len(bits)
    x = 2 * bits.astype(np.int64) - 1
    
    # Forward walk
    s_fwd = np.cumsum(x)
    z_fwd = int(np.max(np.abs(s_fwd)))

    # Backward walk
    s_bwd = np.cumsum(x[::-1])
    z_bwd = int(np.max(np.abs(s_bwd)))

    def _calc_p_cusum(z: int) -> float:
        if z == 0:
            return 1.0
        k_start1 = int(math.floor((-n / z + 1.0) / 4.0))
        k_end1 = int(math.floor((n / z - 1.0) / 4.0))
        sum1 = sum(
            normal_cdf((4.0 * k + 1.0) * z / math.sqrt(n)) -
            normal_cdf((4.0 * k - 1.0) * z / math.sqrt(n))
            for k in range(k_start1, k_end1 + 1)
        )

        k_start2 = int(math.floor((-n / z - 3.0) / 4.0))
        k_end2 = int(math.floor((n / z - 1.0) / 4.0))
        sum2 = sum(
            normal_cdf((4.0 * k + 3.0) * z / math.sqrt(n)) -
            normal_cdf((4.0 * k + 1.0) * z / math.sqrt(n))
            for k in range(k_start2, k_end2 + 1)
        )
        return max(0.0, min(1.0, 1.0 - sum1 + sum2))

    p_fwd = _calc_p_cusum(z_fwd)
    p_bwd = _calc_p_cusum(z_bwd)
    p_min = min(p_fwd, p_bwd)
    passed = (p_fwd >= 0.01) and (p_bwd >= 0.01)

    return NistTestResult(
        test_id=9,
        name="Cumulative Sums",
        statistic=float(max(z_fwd, z_bwd)),
        p_value=p_min,
        degrees_of_freedom=None,
        passed=passed,
        details={
            "z_forward": z_fwd,
            "p_forward": p_fwd,
            "z_backward": z_bwd,
            "p_backward": p_bwd,
        },
    )


def test_serial(bits: np.ndarray, m: int = 3) -> NistTestResult:
    """NIST SP 800-22 §2.11: Serial Test."""
    n = len(bits)
    if m < 2:
        raise ValueError("m deve ser >= 2 para o Serial Test")

    def _psi_sq(k: int) -> float:
        if k == 0:
            return 0.0
        aug = np.concatenate([bits, bits[: k - 1]])
        val = 0
        for j in range(k):
            val = (val << 1) | int(aug[j])
        mask = (1 << k) - 1
        counts = np.zeros(1 << k, dtype=np.int64)
        counts[val] += 1
        for j in range(k, n + k - 1):
            val = ((val << 1) & mask) | int(aug[j])
            counts[val] += 1
        return float((2.0 ** k / n) * np.sum(counts.astype(np.float64) ** 2) - n)

    psi_m = _psi_sq(m)
    psi_m1 = _psi_sq(m - 1)
    psi_m2 = _psi_sq(m - 2) if m >= 3 else 0.0

    del_psi = psi_m - psi_m1
    del2_psi = psi_m - 2.0 * psi_m1 + psi_m2

    # p1 = Q(2^(m-2), del_psi / 2)
    # p2 = Q(2^(m-3), del2_psi / 2)
    p1 = gammaincc(2.0 ** (m - 2), del_psi / 2.0)
    p2 = gammaincc(2.0 ** (m - 3), del2_psi / 2.0)
    passed = (p1 >= 0.01) and (p2 >= 0.01)
    p_min = min(p1, p2)

    return NistTestResult(
        test_id=10,
        name="Serial Test",
        statistic=del_psi,
        p_value=p_min,
        degrees_of_freedom=2 ** (m - 1),
        passed=passed,
        details={
            "m": m,
            "nabla_psi": del_psi,
            "p_value_1": p1,
            "nabla2_psi": del2_psi,
            "p_value_2": p2,
        },
    )


# ==============================================================================
# 5. EXECUÇÃO INTEGRADA DA BATERIA NIST
# ==============================================================================

def run_nist_suite(bits: np.ndarray) -> list[NistTestResult]:
    """Executa os 10 testes do NIST SP 800-22 sequencialmente."""
    results = [
        test_monobit(bits),
        test_block_frequency(bits, block_size=128),
        test_runs(bits),
        test_longest_run_of_ones(bits, block_size=128),
        test_binary_matrix_rank(bits, m=32, q=32),
        test_spectral_dft(bits),
        test_non_overlapping_template(bits, template_size=9, block_size=1024),
        test_approximate_entropy(bits, m=5),
        test_cumulative_sums(bits),
        test_serial(bits, m=3),
    ]
    return results


def print_suite_report(title: str, results: list[NistTestResult], length: int) -> None:
    print("\n" + "=" * 78)
    print(f" NIST SP 800-22 REV 1A — AUDITORIA ESTATÍSTICA: {title}")
    print(f" Comprimento do Fluxo: {length:,} bits | Limiar de Aceitação: alpha = 0.01")
    print("=" * 78)
    print(f"{'#':<3} | {'Nome do Teste':<26} | {'Estatística':<12} | {'P-Valor':<10} | {'Status'}")
    print("-" * 78)

    passed_count = 0
    for r in results:
        status_str = "PASSOU" if r.passed else "FALHOU"
        print(f"{r.test_id:<3} | {r.name:<26} | {r.statistic:<12.4f} | {r.p_value:<10.6f} | {status_str}")
        if r.passed:
            passed_count += 1

    print("-" * 78)
    pass_rate = (passed_count / len(results)) * 100.0
    print(f"TOTAL: {passed_count}/{len(results)} testes aprovados ({pass_rate:.1f}% de aprovação)")
    print("=" * 78)


# ==============================================================================
# 6. INTERFACE CLI
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auditoria Formal NIST SP 800-22 Rev 1a para BaSingSe (RSD-S v4)"
    )
    parser.add_argument(
        "--mode",
        choices=["pre_sha", "post_sha", "both"],
        default="both",
        help="Modo de extração de bits: pre_sha (estado 512b), post_sha (saída 256b) ou both.",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        choices=[1, 2, 4],
        default=4,
        help="Número de rodadas da primitiva RSD-S (padrão: 4).",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=1_000_000,
        help="Quantidade de bits a avaliar (padrão: 1.000.000 bits).",
    )
    parser.add_argument(
        "--export-binary",
        type=str,
        default=None,
        help="Caminho opcional para exportar os bits em binário cru para o Dieharder.",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default=str(REPO_ROOT / "resultados" / "nist_sp800_22_results.json"),
        help="Caminho para salvar o relatório JSON consolidado.",
    )

    args = parser.parse_args()

    modes_to_run = ["pre_sha", "post_sha"] if args.mode == "both" else [args.mode]
    consolidated_report: dict[str, Any] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rounds": args.rounds,
        "bitstream_length": args.length,
        "modes": {},
    }

    for mode in modes_to_run:
        label = f"RSD-S v4 ({args.rounds} Rodadas) — {mode.upper()}"
        print(f"\n[+] Gerando bitstream de {args.length:,} bits para {label}...")
        t0 = time.time()
        bits = generate_bitstream(mode=mode, rounds=args.rounds, length=args.length)
        gen_time = time.time() - t0
        print(f"[+] Geração concluída em {gen_time:.2f}s ({len(bits):,} bits).")

        if args.export_binary:
            export_path = f"{args.export_binary}_{mode}.bin"
            export_binary_file(bits, export_path)
            print(f"[+] Arquivo binário exportado para: {export_path}")

        print(f"[+] Executando os 10 testes do NIST SP 800-22...")
        t1 = time.time()
        test_results = run_nist_suite(bits)
        suite_time = time.time() - t1
        print(f"[+] Testes concluídos em {suite_time:.2f}s.")

        print_suite_report(label, test_results, args.length)

        consolidated_report["modes"][mode] = {
            "generation_time_s": gen_time,
            "suite_time_s": suite_time,
            "pass_count": sum(1 for r in test_results if r.passed),
            "total_tests": len(test_results),
            "tests": [r.to_dict() for r in test_results],
        }

    # Salva relatório consolidado em JSON
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(consolidated_report, indent=2), encoding="utf-8")
        print(f"\n[+] Relatório consolidado gravado com sucesso em: {out_path}")


if __name__ == "__main__":
    main()
