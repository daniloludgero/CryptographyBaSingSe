"""
Harness reutilizável de métricas criptográficas e ataques endurecidos (R5).

Projetado para ser agnóstico à primitiva PRP (parametrizado por `block_bytes` e
`word_bits`), permitindo avaliar tanto o núcleo RSD-S v5.1 (`block_bytes=64`,
`word_bits=16`) em 1R..8R quanto baselines como AES (`block_bytes=16`,
`word_bits=8`) em M_R5_2 com exatamente as mesmas funções.
"""
from __future__ import annotations

import ctypes
import hashlib
import math
import subprocess
import sys
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "implementacao") not in sys.path:
    sys.path.insert(0, str(ROOT / "implementacao"))

from rsd_s_v5_hardened import (  # noqa: E402
    M_CAUCHY_32,
    W,
    _domain_tag,
    derive_keys_v5,
    expand_key_words_v5,
    round_constant_v5,
    sbox_v5_eval,
)
from mds_real import gf_mult  # noqa: E402


@runtime_checkable
class PRPPrimitive(Protocol):
    name: str
    block_bytes: int
    word_bits: int
    rounds: int

    def eval_block(self, pt: bytes) -> bytes: ...


def load_rsd_c_core(build_dir: Path = Path("/tmp/r5_build")) -> ctypes.CDLL:
    """Compila `implementacao/c_core/rsd_s_v5_ct.c` com flags estritas e carrega a .so."""
    build_dir = Path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    src = ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"
    so_path = build_dir / "lib_rsd_s_v5_r5.so"

    need_build = (not so_path.exists()) or (src.stat().st_mtime > so_path.stat().st_mtime)
    if need_build:
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
                str(src),
                "-o",
                str(so_path),
            ],
            check=True,
        )

    lib = ctypes.CDLL(str(so_path))
    p_u16 = ctypes.POINTER(ctypes.c_uint16)
    lib.rsd_s_v5_core_ct.argtypes = [
        p_u16,          # in_state[32]
        p_u16,          # rk_flat[(rounds+1)*32]
        p_u16,          # rc[rounds]
        ctypes.c_int,   # rounds
        ctypes.c_int,   # fault_word (-1 = none)
        ctypes.c_uint16,# fault_mask
        p_u16,          # out_state[32]
    ]
    lib.rsd_s_v5_core_ct.restype = ctypes.c_int

    lib.rsd_s_v5_verify_wipe_ct.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
    lib.rsd_s_v5_verify_wipe_ct.restype = ctypes.c_int
    return lib


class RSDKeyedV5:
    """
    Wrapper do núcleo C99 constant-time do RSD-S v5.1 com truncamento real de rodadas
    a partir da agenda completa de `schedule_rounds` (padrão 8R).
    """

    def __init__(
        self,
        lib: ctypes.CDLL,
        s: bytes,
        n_sess: int,
        rounds: int = 8,
        schedule_rounds: int = 8,
        with_sha: bool = False,
        base_block: bytes | None = None,
    ) -> None:
        if not 1 <= rounds <= schedule_rounds:
            raise ValueError(f"rounds ({rounds}) deve estar em 1..schedule_rounds ({schedule_rounds})")
        self.lib = lib
        self.s = s
        self.n_sess = n_sess
        self.rounds = rounds
        self.schedule_rounds = schedule_rounds
        self.with_sha = with_sha

        self.word_bits = 16
        self.n_words = W
        self.block_bytes = 32 if with_sha else 64
        self.in_block_bytes = 64
        self.name = f"RSD-S v5.1 ({rounds}R{' + SHA-256' if with_sha else ' core'})"

        keys = derive_keys_v5(s, n_sess, schedule_rounds)
        rk_full = np.concatenate([expand_key_words_v5(k, W) for k in keys]).astype(np.uint16)
        rc_full = np.array(
            [round_constant_v5(s, n_sess, r, schedule_rounds) for r in range(1, schedule_rounds + 1)],
            dtype=np.uint16,
        )

        # Truncamento real da instância schedule_rounds
        self.rk = np.ascontiguousarray(rk_full[: (rounds + 1) * W], dtype=np.uint16)
        self.rc = np.ascontiguousarray(rc_full[:rounds], dtype=np.uint16)
        self.dom = _domain_tag(n_sess, schedule_rounds)

        self._out_buf = np.zeros(W, dtype=np.uint16)
        p_u16 = ctypes.POINTER(ctypes.c_uint16)
        self._p_rk = self.rk.ctypes.data_as(p_u16)
        self._p_rc = self.rc.ctypes.data_as(p_u16)
        self._p_out = self._out_buf.ctypes.data_as(p_u16)
        self._core_fn = self.lib.rsd_s_v5_core_ct

        if base_block is not None:
            if len(base_block) != 64:
                raise ValueError("base_block deve ter 64 bytes")
            self.default_base_block = base_block
        else:
            # Base determinística por chave/sessão via SHAKE256 caso não fornecida explicitamente
            self.default_base_block = hashlib.shake_256(b"R5_DEFAULT_BASE|" + s).digest(64)

    def eval_words(self, arr_u16: np.ndarray) -> np.ndarray:
        """Avalia 1 estado (shape (32,)) ou lote (shape (N, 32)) de uint16 no núcleo C."""
        arr = np.asarray(arr_u16, dtype=np.uint16)
        p_u16 = ctypes.POINTER(ctypes.c_uint16)
        core = self._core_fn
        p_rk, p_rc, rounds = self._p_rk, self._p_rc, self.rounds

        if arr.ndim == 1:
            if arr.shape != (W,):
                raise ValueError(f"Esperado shape ({W},), obtido {arr.shape}")
            c_in = np.ascontiguousarray(arr, dtype=np.uint16)
            rc = core(c_in.ctypes.data_as(p_u16), p_rk, p_rc, rounds, -1, 0, self._p_out)
            if rc != 0:
                raise RuntimeError(f"rsd_s_v5_core_ct retornou erro {rc}")
            return self._out_buf.copy()

        if arr.ndim == 2 and arr.shape[1] == W:
            n = arr.shape[0]
            out = np.empty((n, W), dtype=np.uint16)
            c_arr = np.ascontiguousarray(arr, dtype=np.uint16)
            p_out_row = self._p_out
            out_buf = self._out_buf
            for idx in range(n):
                row_ptr = c_arr[idx].ctypes.data_as(p_u16)
                rc = core(row_ptr, p_rk, p_rc, rounds, -1, 0, p_out_row)
                if rc != 0:
                    raise RuntimeError(f"rsd_s_v5_core_ct retornou erro {rc}")
                out[idx] = out_buf
            return out

        raise ValueError(f"Shape inválido para eval_words: {arr.shape}")

    def eval_block(self, pt: bytes) -> bytes:
        """Avalia um bloco de 64 bytes (big-endian >u2 por palavra)."""
        if len(pt) != 64:
            raise ValueError(f"pt deve ter 64 bytes, obtido {len(pt)}")
        in_words = np.frombuffer(pt, dtype=">u2").astype(np.uint16)
        out_words = self.eval_words(in_words)
        raw = out_words.astype(">u2").tobytes()
        if self.with_sha:
            return hashlib.sha256(self.dom + raw).digest()
        return raw

    def eval_nbits(self, i: int, n_bits: int, base_block: bytes | None = None) -> int:
        """
        Avalia entrada de `n_bits` bits sobre um bloco base aleatório de 64 bytes
        (sem `y=12345` fixo), retornando os `n_bits` bits mais significativos da saída.
        """
        base = self.default_base_block if base_block is None else base_block
        pt = _inject_nbits_into_block(base, i, n_bits)
        out = self.eval_block(pt)
        return int.from_bytes(out[:4], "big") >> (32 - n_bits)


# ---------------------------------------------------------------------------
# Helpers genéricos de conversão bloco <-> palavras
# ---------------------------------------------------------------------------

def _inject_nbits_into_block(base_block: bytes, val: int, n_bits: int) -> bytes:
    """Faz XOR de `val` (n_bits) nos primeiros `n_bits` bits de `base_block`."""
    prefix_bytes = (n_bits + 7) // 8
    shift = prefix_bytes * 8 - n_bits
    orig = int.from_bytes(base_block[:prefix_bytes], "big")
    patched = orig ^ ((val & ((1 << n_bits) - 1)) << shift)
    return patched.to_bytes(prefix_bytes, "big") + base_block[prefix_bytes:]


def _blocks_to_words(blocks: list[bytes] | np.ndarray, word_bits: int) -> np.ndarray:
    """Converte lista de blocos `bytes` em matriz (N, n_words) de uint16/uint8."""
    if isinstance(blocks, np.ndarray):
        raw = blocks.tobytes()
        n = blocks.shape[0]
    else:
        n = len(blocks)
        raw = b"".join(blocks)
    if word_bits == 16:
        arr = np.frombuffer(raw, dtype=">u2").astype(np.uint16)
        return arr.reshape(n, -1)
    if word_bits == 8:
        arr = np.frombuffer(raw, dtype=np.uint8)
        return arr.reshape(n, -1)
    raise ValueError(f"word_bits não suportado: {word_bits}")


def _eval_batch_words(prim: PRPPrimitive, in_words: np.ndarray) -> np.ndarray:
    """Avalia um lote (N, n_words) usando `eval_words` se disponível, ou `eval_block`."""
    if hasattr(prim, "eval_words") and getattr(prim, "with_sha", False) is False:
        return prim.eval_words(in_words)
    dt = ">u2" if prim.word_bits == 16 else np.uint8
    n = in_words.shape[0]
    in_bytes = in_words.astype(dt).tobytes()
    bsize = prim.block_bytes
    eval_fn = prim.eval_block
    outs = [eval_fn(in_bytes[i * bsize : (i + 1) * bsize]) for i in range(n)]
    return _blocks_to_words(outs, prim.word_bits)


def _eval_batch_blocks(prim: PRPPrimitive, pts: list[bytes]) -> np.ndarray:
    """Avalia lista de blocos `bytes` retornando array uint8 de shape (N, block_bytes)."""
    if hasattr(prim, "eval_words") and getattr(prim, "with_sha", False) is False and prim.word_bits == 16:
        in_w = np.frombuffer(b"".join(pts), dtype=">u2").astype(np.uint16).reshape(len(pts), -1)
        out_w = prim.eval_words(in_w)
        return np.frombuffer(out_w.astype(">u2").tobytes(), dtype=np.uint8).reshape(len(pts), prim.block_bytes)
    eval_fn = prim.eval_block
    outs = b"".join(eval_fn(p) for p in pts)
    return np.frombuffer(outs, dtype=np.uint8).reshape(len(pts), len(outs) // len(pts))


# ---------------------------------------------------------------------------
# 1. Ataque Integral / Square (Lambda-set)
# ---------------------------------------------------------------------------

def attack_integral_square(
    prim: PRPPrimitive,
    active_word: int = 0,
    trials: int = 1,
    rng: np.random.Generator | None = None,
) -> dict:
    """
    Executa ataque Integral / Square (Lambda-set de 2^word_bits entradas) mantendo
    todas as outras palavras com valor base aleatório fixo por trial.
    """
    if rng is None:
        rng = np.random.default_rng()
    word_bits = prim.word_bits
    n_words = (prim.in_block_bytes * 8 if hasattr(prim, "in_block_bytes") else prim.block_bytes * 8) // word_bits
    n_vals = 1 << word_bits
    dt = np.uint16 if word_bits == 16 else np.uint8

    zero_counts = []
    consistent_mask = None

    for _ in range(trials):
        base_bytes = rng.bytes(n_words * (word_bits // 8))
        base_words = np.frombuffer(base_bytes, dtype=">u2" if word_bits == 16 else np.uint8).astype(dt)
        batch = np.tile(base_words, (n_vals, 1))
        batch[:, active_word] = np.arange(n_vals, dtype=dt)

        out_words = _eval_batch_words(prim, batch)
        xor_sum = np.bitwise_xor.reduce(out_words, axis=0)
        is_zero = xor_sum == 0
        zero_counts.append(int(np.sum(is_zero)))
        if consistent_mask is None:
            consistent_mask = is_zero
        else:
            consistent_mask &= is_zero

    out_n_words = (prim.block_bytes * 8) // word_bits
    consistent_zeros = int(np.sum(consistent_mask)) if consistent_mask is not None else 0
    return {
        "word_bits": word_bits,
        "out_words": out_n_words,
        "trials": trials,
        "zero_xor_words_per_trial": zero_counts,
        "min_zero_xor_words": min(zero_counts),
        "max_zero_xor_words": max(zero_counts),
        "consistent_zero_xor_words": consistent_zeros,
        "detected": consistent_zeros > 0 and (consistent_zeros == out_n_words or trials >= 2 or word_bits >= 16),
        "full_state_balanced": consistent_zeros == out_n_words,
    }


# ---------------------------------------------------------------------------
# 2. Ataque Diferencial & Diferencial Truncado
# ---------------------------------------------------------------------------

def attack_differential(
    prim: PRPPrimitive,
    n_pairs: int = 4096,
    active_word: int = 0,
    rng: np.random.Generator | None = None,
) -> dict:
    """
    Ataque diferencial e diferencial truncado com entradas aleatórias completas
    (512 bits no RSD-S, 128 bits no AES) e delta fixo em 1 palavra.
    Mede:
      - max_bit_bias_z: viés máximo de bit individual em (ct1 ^ ct2)
      - word_diff_collisions & word_diff_coll_z: colisões de diferença na palavra 0 vs RO
      - truncated_active_words_mean / min: contagem de palavras ativas na saída
      - hw_mean / hw_chi2_z: desvio do peso de Hamming de (ct1 ^ ct2) vs Binomial(B, 0.5)
    """
    if rng is None:
        rng = np.random.default_rng()
    in_bytes = prim.in_block_bytes if hasattr(prim, "in_block_bytes") else prim.block_bytes
    word_bytes = prim.word_bits // 8
    n_in_words = in_bytes // word_bytes

    # Delta fixo de 1 palavra não-nula aleatória
    delta_words = np.zeros(n_in_words, dtype=np.uint16 if prim.word_bits == 16 else np.uint8)
    d_val = int(rng.integers(1, 1 << prim.word_bits))
    delta_words[active_word] = d_val
    delta_bytes = delta_words.astype(">u2" if prim.word_bits == 16 else np.uint8).tobytes()
    delta_arr = np.frombuffer(delta_bytes, dtype=np.uint8)

    pt1_arr = np.frombuffer(rng.bytes(n_pairs * in_bytes), dtype=np.uint8).reshape(n_pairs, in_bytes)
    pt2_arr = np.bitwise_xor(pt1_arr, delta_arr)

    pts1 = [pt1_arr[i].tobytes() for i in range(n_pairs)]
    pts2 = [pt2_arr[i].tobytes() for i in range(n_pairs)]

    ct1 = _eval_batch_blocks(prim, pts1)
    ct2 = _eval_batch_blocks(prim, pts2)
    diff_bytes = np.bitwise_xor(ct1, ct2)

    # (a) Viés máximo por bit de saída
    diff_bits = np.unpackbits(diff_bytes, axis=1)
    bit_ones = np.sum(diff_bits, axis=0)
    expected_ones = n_pairs / 2.0
    sd_ones = math.sqrt(n_pairs) / 2.0
    bit_z = np.abs(bit_ones - expected_ones) / sd_ones
    max_bit_bias_z = float(np.max(bit_z))

    # (b) Diferencial truncado: palavras ativas
    out_n_words = (prim.block_bytes * 8) // prim.word_bits
    diff_words = _blocks_to_words(diff_bytes, prim.word_bits)
    active_counts = np.sum(diff_words != 0, axis=1)
    active_mean = float(np.mean(active_counts))
    active_min = int(np.min(active_counts))

    # (c) Colisões diferenciais na palavra 0 (e máximo entre palavras)
    # Em 1R, dy0 assume ~2^(word_bits-1) valores => 2x mais colisões que RO!
    pair_comb = n_pairs * (n_pairs - 1) / 2.0
    expected_coll = pair_comb / float(1 << prim.word_bits)
    sd_coll = math.sqrt(max(expected_coll * (1.0 - 1.0 / (1 << prim.word_bits)), 1e-9))
    max_coll_z = 0.0
    max_coll_count = 0
    for w_idx in range(min(out_n_words, 8)):
        _, counts = np.unique(diff_words[:, w_idx], return_counts=True)
        coll = int(np.sum(counts * (counts - 1) // 2))
        z_c = (coll - expected_coll) / sd_coll
        if abs(z_c) > abs(max_coll_z):
            max_coll_z = float(z_c)
            max_coll_count = coll

    # (d) Peso de Hamming de diff_bytes vs Binomial(out_bits, 0.5)
    out_bits = prim.block_bytes * 8
    hw = np.sum(diff_bits, axis=1)
    hw_mean = float(np.mean(hw))
    # Teste de variância / média do HW
    hw_mean_z = (hw_mean - out_bits / 2.0) / math.sqrt((out_bits / 4.0) / n_pairs)

    flagged = (max_bit_bias_z > 5.5) or (abs(max_coll_z) > 5.0) or (abs(hw_mean_z) > 5.0)
    return {
        "n_pairs": n_pairs,
        "max_bit_bias_z": round(max_bit_bias_z, 3),
        "word_diff_collisions": max_coll_count,
        "word_diff_coll_expected": round(expected_coll, 2),
        "word_diff_coll_z": round(max_coll_z, 3),
        "truncated_active_words_mean": round(active_mean, 4),
        "truncated_active_words_min": active_min,
        "hw_mean": round(hw_mean, 3),
        "hw_mean_z": round(hw_mean_z, 3),
        "detected": flagged,
    }


# ---------------------------------------------------------------------------
# 3. Ataque Linear / Walsh
# ---------------------------------------------------------------------------

def _solve_gf2_linear(A: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Resolve A * x = b em GF(2) via eliminação gaussiana."""
    n = A.shape[0]
    M = np.hstack([A.astype(np.uint8), b.reshape(n, 1).astype(np.uint8)])
    row = 0
    pivots = []
    for col in range(n):
        candidates = np.nonzero(M[row:, col])[0]
        if candidates.size == 0:
            continue
        piv = row + int(candidates[0])
        if piv != row:
            M[[row, piv]] = M[[piv, row]]
        others = np.nonzero(M[:, col])[0]
        others = others[others != row]
        if others.size > 0:
            M[others] ^= M[row]
        pivots.append((row, col))
        row += 1
        if row == n:
            break
    x = np.zeros(n, dtype=np.uint8)
    for r, c in pivots:
        x[c] = M[r, n]
    return x


def build_rsd_1r_linear_masks(n_masks: int = 8, active_word: int = 0, seed: int = 42) -> list[tuple[bytes, bytes]]:
    """
    Constrói máscaras lineares estruturais (Gamma_in, Gamma_out) para o RSD-S v5.1
    isolando exatamente 1 S-box na rodada 1:
      - Gamma_in não-nula apenas na palavra `active_word` (valor alpha)
      - Gamma_out = (M_bin^T)^{-1} * (e_{active_word} * beta)
    com (alpha, beta) de alta correlação (|c| >= 2^-7) na S-box v5.
    """
    # 1. Tabela da S-box v5 em GF(2^16) e busca de pares (alpha, beta) com |corr| >= 2^-7
    sbox_lut = np.array([sbox_v5_eval(u) for u in range(1 << 16)], dtype=np.uint16)
    u_arr = np.arange(1 << 16, dtype=np.uint16)
    parity16 = np.array([bin(x).count("1") & 1 for x in range(1 << 16)], dtype=np.uint8)

    rng = np.random.default_rng(seed)
    good_pairs: list[tuple[int, int]] = []
    # Amostra determinística até coletar n_masks pares com |corr| >= 2^-7 (0.0078125)
    while len(good_pairs) < n_masks:
        alpha = int(rng.integers(1, 1 << 16))
        beta = int(rng.integers(1, 1 << 16))
        in_p = parity16[u_arr & alpha]
        out_p = parity16[sbox_lut & beta]
        corr = abs(2.0 * float(np.sum(in_p == out_p)) / 65536.0 - 1.0)
        if corr >= (1.0 / 128.0):
            good_pairs.append((alpha, beta))

    # 2. Construir matriz binária M_bin (512 x 512) de M_CAUCHY_32 (big-endian >u2)
    # Em cada palavra de 16 bits big-endian, bit_pos 0 é o MSB (1 << 15) e bit_pos 15 é o LSB (1 << 0)
    M_bin = np.zeros((512, 512), dtype=np.uint8)
    for j in range(W):
        for b_in in range(16):
            val_in = 1 << (15 - b_in)
            col = j * 16 + b_in
            for i in range(W):
                prod = gf_mult(int(M_CAUCHY_32[i, j]), val_in)
                for b_out in range(16):
                    M_bin[i * 16 + b_out, col] = (prod >> (15 - b_out)) & 1

    # Inverter M_bin^T uma vez resolvendo para os 16 vetores unitários da palavra `active_word`
    MT = M_bin.T.copy()
    basis_out = np.zeros((16, 512), dtype=np.uint8)
    for b in range(16):
        e_vec = np.zeros(512, dtype=np.uint8)
        e_vec[active_word * 16 + b] = 1
        basis_out[b] = _solve_gf2_linear(MT, e_vec)

    masks: list[tuple[bytes, bytes]] = []
    for alpha, beta in good_pairs:
        g_in = np.zeros(512, dtype=np.uint8)
        g_out = np.zeros(512, dtype=np.uint8)
        for b in range(16):
            if (alpha >> (15 - b)) & 1:
                g_in[active_word * 16 + b] = 1
            if (beta >> (15 - b)) & 1:
                g_out ^= basis_out[b]
        masks.append((np.packbits(g_in).tobytes(), np.packbits(g_out).tobytes()))
    return masks


def attack_linear_walsh(
    prim: PRPPrimitive,
    n_samples: int = 16384,
    n_masks: int = 64,
    structured_masks: list[tuple[bytes, bytes]] | None = None,
    rng: np.random.Generator | None = None,
) -> dict:
    """
    Aproximação linear com entradas aleatórias completas (`in_bytes`).
    Inclui máscaras de palavra única/bit único, máscaras aleatórias e, opcionalmente,
    `structured_masks` (ex.: máscaras (M^T)^{-1} isolando 1 S-box em 1R).
    """
    if rng is None:
        rng = np.random.default_rng()
    in_bytes = prim.in_block_bytes if hasattr(prim, "in_block_bytes") else prim.block_bytes
    out_bytes = prim.block_bytes

    pt_arr = np.frombuffer(rng.bytes(n_samples * in_bytes), dtype=np.uint8).reshape(n_samples, in_bytes)
    pts = [pt_arr[i].tobytes() for i in range(n_samples)]
    ct_arr = _eval_batch_blocks(prim, pts)

    # Construir pares (mask_in, mask_out)
    masks_in_list = []
    masks_out_list = []
    if structured_masks:
        for m_in, m_out in structured_masks:
            masks_in_list.append(np.frombuffer(m_in, dtype=np.uint8))
            masks_out_list.append(np.frombuffer(m_out, dtype=np.uint8))

    rand_in = np.frombuffer(rng.bytes(n_masks * in_bytes), dtype=np.uint8).reshape(n_masks, in_bytes).copy()
    rand_out = np.frombuffer(rng.bytes(n_masks * out_bytes), dtype=np.uint8).reshape(n_masks, out_bytes).copy()
    for idx in range(min(16, n_masks)):
        rand_in[idx].fill(0)
        rand_out[idx].fill(0)
        rand_in[idx, idx % in_bytes] = 1 << (idx % 8)
        rand_out[idx, idx % out_bytes] = 1 << ((idx * 3) % 8)

    for idx in range(n_masks):
        masks_in_list.append(rand_in[idx])
        masks_out_list.append(rand_out[idx])

    masks_in = np.stack(masks_in_list, axis=0)
    masks_out = np.stack(masks_out_list, axis=0)
    total_masks = masks_in.shape[0]

    # Tabela de paridade de byte (popcount & 1)
    parity_lut = np.array([bin(b).count("1") & 1 for b in range(256)], dtype=np.uint8)

    max_abs_corr = 0.0
    max_z = 0.0
    sqrt_n = math.sqrt(n_samples)

    for m_idx in range(total_masks):
        # Usa apenas os bytes onde a máscara é não-nula para acelerar muito em n_samples grandes
        nz_in = np.nonzero(masks_in[m_idx])[0]
        nz_out = np.nonzero(masks_out[m_idx])[0]
        if nz_in.size == 0:
            in_par = np.zeros(n_samples, dtype=np.uint8)
        else:
            in_par = np.bitwise_xor.reduce(
                parity_lut[np.bitwise_and(pt_arr[:, nz_in], masks_in[m_idx, nz_in])], axis=1
            )
        if nz_out.size == 0:
            out_par = np.zeros(n_samples, dtype=np.uint8)
        else:
            out_par = np.bitwise_xor.reduce(
                parity_lut[np.bitwise_and(ct_arr[:, nz_out], masks_out[m_idx, nz_out])], axis=1
            )
        eq = int(np.sum(in_par == out_par))
        corr = (2.0 * float(eq) / n_samples) - 1.0
        z = abs(corr) * sqrt_n
        if z > max_z:
            max_z = z
            max_abs_corr = abs(corr)

    return {
        "n_samples": n_samples,
        "n_masks": total_masks,
        "noise_floor_inv_sqrt_n": round(1.0 / sqrt_n, 6),
        "max_abs_corr": round(max_abs_corr, 6),
        "max_z": round(max_z, 3),
        "detected": max_z > 5.0,
    }


# ---------------------------------------------------------------------------
# 4. Ataque Algébrico / Higher-Order Differential (ANF via Transformada de Möbius)
# ---------------------------------------------------------------------------

def _mobius_transform_gf2(truth_table: np.ndarray, n_vars: int) -> np.ndarray:
    """Transformada rápida de Möbius em GF(2)^n_vars (vetorizada em NumPy)."""
    anf = truth_table.astype(np.uint8).copy()
    for i in range(n_vars):
        step = 1 << i
        anf = anf.reshape(-1, 2 * step)
        anf[:, step:] ^= anf[:, :step]
        anf = anf.reshape(-1)
    return anf


def attack_algebraic_anf(
    prim: PRPPrimitive,
    active_word: int = 0,
    n_out_bits: int = 16,
    rng: np.random.Generator | None = None,
) -> dict:
    """
    Calcula a Forma Normal Algébrica (ANF) univariada por palavra (em GF(2)^word_bits)
    sobre um Lambda-set completo de 2^word_bits entradas com as demais palavras aleatórias.
    """
    if rng is None:
        rng = np.random.default_rng()
    word_bits = prim.word_bits
    in_bytes = prim.in_block_bytes if hasattr(prim, "in_block_bytes") else prim.block_bytes
    n_in_words = in_bytes // (word_bits // 8)
    n_vals = 1 << word_bits
    dt = np.uint16 if word_bits == 16 else np.uint8

    base_bytes = rng.bytes(in_bytes)
    base_words = np.frombuffer(base_bytes, dtype=">u2" if word_bits == 16 else np.uint8).astype(dt)
    batch = np.tile(base_words, (n_vals, 1))
    batch[:, active_word] = np.arange(n_vals, dtype=dt)

    out_words = _eval_batch_words(prim, batch)
    # Pré-computar peso de Hamming dos índices 0..2^word_bits - 1
    idx = np.arange(n_vals, dtype=np.uint32)
    hw_idx = np.zeros(n_vals, dtype=np.uint8)
    for b in range(word_bits):
        hw_idx += ((idx >> b) & 1).astype(np.uint8)

    max_deg = 0
    deg_max_possible = word_bits
    saturated_bits = 0
    out_w0 = out_words[:, 0]

    tested_bits = min(n_out_bits, word_bits)
    for b in range(tested_bits):
        tt = (out_w0 >> b) & 1
        anf = _mobius_transform_gf2(tt, word_bits)
        nonzero_hw = hw_idx[anf != 0]
        deg = int(np.max(nonzero_hw)) if nonzero_hw.size > 0 else 0
        if deg > max_deg:
            max_deg = deg
        if anf[-1] != 0:
            saturated_bits += 1

    return {
        "word_bits": word_bits,
        "tested_out_bits": tested_bits,
        "max_algebraic_degree": max_deg,
        "full_degree_bound": deg_max_possible,
        "saturated_top_monomial_bits": saturated_bits,
        "non_saturated_detected": max_deg < deg_max_possible,
    }


# ---------------------------------------------------------------------------
# 5. QROM-analog endurecido (sem y=12345 fixo; entradas aleatórias)
# ---------------------------------------------------------------------------

def _qrom_table_stats(T: np.ndarray, n: int, with_simon: bool) -> dict:
    N = 1 << n
    img = int(np.unique(T).size)
    # Escolhe alvo aleatório da imagem usando primeiro elemento (ou determinístico)
    ystar = T[0]
    mult = int(np.sum(T == ystar))
    out = {
        "collisions_N_minus_image": N - img,
        "preimage_multiplicity": mult,
    }
    if with_simon:
        idx = np.arange(N)
        best = 0
        for s in range(1, N):
            m = int(np.sum(T == T[idx ^ s]))
            if m > best:
                best = m
        out["simon_max_xor_period_matches"] = best
    return out


def attack_qrom_analog(
    prim_factory: Callable[[bytes, bytes], PRPPrimitive],
    n_bits_list: tuple[int, ...] = (10, 12, 14, 16),
    k_keys: int = 8,
    k_ro: int = 40,
    flag_z: float = 4.0,
    rng: np.random.Generator | None = None,
) -> dict:
    """
    Avalia colisões, multiplicidade de pré-imagem e periodicidade XOR de Simon
    sobre tabelas n-bit com bloco base aleatório completo por chave (sem y=12345 fixo).
    `prim_factory(key_bytes, base_block_bytes)` deve retornar um `PRPPrimitive` com `eval_nbits`.
    """
    if rng is None:
        rng = np.random.default_rng()
    results = {}
    all_flagged: set[str] = set()

    for n in n_bits_list:
        N = 1 << n
        simon = n <= 12
        ro_rows = [
            _qrom_table_stats(rng.integers(0, N, size=N, dtype=np.int64), n, simon)
            for _ in range(k_ro)
        ]
        mu = {k: float(np.mean([r[k] for r in ro_rows])) for k in ro_rows[0]}
        sd = {k: float(np.std([r[k] for r in ro_rows], ddof=1)) + 1e-12 for k in ro_rows[0]}

        prim_rows = []
        for _ in range(k_keys):
            key = rng.bytes(32)
            # Primeiro instancia para saber in_block_bytes
            dummy_base = rng.bytes(64)
            prim = prim_factory(key, dummy_base)
            in_b = prim.in_block_bytes if hasattr(prim, "in_block_bytes") else prim.block_bytes
            base_block = rng.bytes(in_b)
            if hasattr(prim, "eval_nbits"):
                T = np.fromiter((prim.eval_nbits(i, n, base_block=base_block) for i in range(N)), dtype=np.int64, count=N)
            else:
                T = np.fromiter(
                    (int.from_bytes(prim.eval_block(_inject_nbits_into_block(base_block, i, n))[:4], "big") >> (32 - n)
                     for i in range(N)),
                    dtype=np.int64,
                    count=N,
                )
            prim_rows.append(_qrom_table_stats(T, n, simon))

        z = {
            k: round(
                (float(np.mean([r[k] for r in prim_rows])) - mu[k])
                / (sd[k] * math.sqrt(1.0 / k_keys + 1.0 / k_ro)),
                2,
            )
            for k in mu
        }
        flagged = [k for k, v in z.items() if abs(v) > flag_z]
        all_flagged.update(flagged)
        results[f"n={n}"] = {
            "ro_mean": {k: round(v, 3) for k, v in mu.items()},
            "ro_std": {k: round(v, 3) for k, v in sd.items()},
            "prim_mean": {k: round(float(np.mean([r[k] for r in prim_rows])), 3) for k in mu},
            "z": z,
            "flagged": flagged,
        }

    return {
        "by_n": results,
        "flagged_tests": sorted(all_flagged),
        "distinguished_from_RO": bool(all_flagged),
    }


# ---------------------------------------------------------------------------
# 6. Avalanche e Uniformidade
# ---------------------------------------------------------------------------

def measure_avalanche(
    prim: PRPPrimitive,
    n_samples: int = 1000,
    rng: np.random.Generator | None = None,
) -> dict:
    """Mede fração de bits alterados na saída ao inverter 1 bit aleatório na entrada completa."""
    if rng is None:
        rng = np.random.default_rng()
    in_bytes = prim.in_block_bytes if hasattr(prim, "in_block_bytes") else prim.block_bytes
    in_bits = in_bytes * 8
    flips = np.empty(n_samples, dtype=np.float64)

    pts1 = []
    pts2 = []
    for _ in range(n_samples):
        b = bytearray(rng.bytes(in_bytes))
        pts1.append(bytes(b))
        bit_pos = int(rng.integers(0, in_bits))
        b[bit_pos >> 3] ^= 1 << (bit_pos & 7)
        pts2.append(bytes(b))

    ct1 = _eval_batch_blocks(prim, pts1)
    ct2 = _eval_batch_blocks(prim, pts2)
    diff = np.bitwise_xor(ct1, ct2)
    out_bits = ct1.shape[1] * 8
    hw = np.sum(np.unpackbits(diff, axis=1), axis=1)
    flips = hw / float(out_bits)

    return {
        "mean_flip_fraction": round(float(np.mean(flips)), 5),
        "std": round(float(np.std(flips)), 5),
    }


def measure_uniformity(
    prim: PRPPrimitive,
    n_samples: int = 65536,
    byte_idx: int = 0,
    rng: np.random.Generator | None = None,
) -> dict:
    """Teste chi² em 256 bins no byte `byte_idx` da saída com entradas aleatórias."""
    if rng is None:
        rng = np.random.default_rng()
    in_bytes = prim.in_block_bytes if hasattr(prim, "in_block_bytes") else prim.block_bytes
    raw_in = rng.bytes(n_samples * in_bytes)
    pts = [raw_in[i * in_bytes : (i + 1) * in_bytes] for i in range(n_samples)]
    ct = _eval_batch_blocks(prim, pts)
    counts = np.bincount(ct[:, byte_idx], minlength=256)
    chi2, p_val = stats.chisquare(counts)
    return {
        "chi2": round(float(chi2), 2),
        "p_value": round(float(p_val), 4),
    }
