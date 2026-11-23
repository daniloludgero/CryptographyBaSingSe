#!/usr/bin/env python3
"""
testes/lote_a_lattice_cryptanalysis.py

Round 2 — Lote A: Lattice Cryptanalysis (LLL/Kannan/CVP), NIST SP 800-22 on raw y_pub_bytes,
Related-Key & Nonce-Reuse Attacks, and Formal KEM/PKE vs PRF/Commitment Verification
for implementacao/bandlimited_dual_key.py.
"""

from __future__ import annotations

import json
import math
import sys
import time
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "implementacao"))
sys.path.insert(0, str(REPO_ROOT / "ferramentas"))

from bandlimited_dual_key import (  # noqa: E402
    BandlimitedDualKeyEngine,
    BandlimitedKernelSpec,
    Q_FERMAT,
    _derive_dual_key_noise,
)
from rsd_s_v5_hardened import W  # noqa: E402
from audit_nist_dieharder import run_nist_suite  # noqa: E402


# ==============================================================================
# Modular Linear Algebra over Z_q (q = 65537)
# ==============================================================================

def mod_mat_inv(A: np.ndarray, mod: int = Q_FERMAT) -> np.ndarray:
    n = A.shape[0]
    M = np.hstack([A.astype(np.int64) % mod, np.eye(n, dtype=np.int64)])
    for col in range(n):
        piv = col
        while piv < n and M[piv, col] % mod == 0:
            piv += 1
        if piv == n:
            raise ValueError("Matrix is singular mod q")
        if piv != col:
            M[[col, piv]] = M[[piv, col]]
        inv_p = pow(int(M[col, col]), mod - 2, mod)
        M[col] = (M[col] * inv_p) % mod
        for row in range(n):
            if row != col and M[row, col] != 0:
                M[row] = (M[row] - M[row, col] * M[col]) % mod
    return M[:, n:]


def mod_mat_rank_and_det(A: np.ndarray, mod: int = Q_FERMAT) -> tuple[int, int]:
    n, m = A.shape
    M = (A.astype(np.int64) % mod).copy()
    rank = 0
    det = 1
    for col in range(m):
        piv = rank
        while piv < n and M[piv, col] % mod == 0:
            piv += 1
        if piv == n:
            det = 0
            continue
        if piv != rank:
            M[[rank, piv]] = M[[piv, rank]]
            det = (-det) % mod
        piv_val = int(M[rank, col])
        det = (det * piv_val) % mod
        inv_p = pow(piv_val, mod - 2, mod)
        for row in range(rank + 1, n):
            if M[row, col] != 0:
                factor = (M[row, col] * inv_p) % mod
                M[row, col:] = (M[row, col:] - factor * M[rank, col:]) % mod
        rank += 1
    if n != m:
        det = 0
    return rank, det


def center_mod(v: np.ndarray, q: int = Q_FERMAT) -> np.ndarray:
    v_mod = v.astype(np.int64) % q
    half = q // 2
    return np.where(v_mod > half, v_mod - q, v_mod)


# ==============================================================================
# LLL Lattice Reduction + Kannan Embedding (Float64 Gram-Schmidt + Integer Basis)
# ==============================================================================

def lll_reduce(basis: np.ndarray, delta: float = 0.99, max_iter: int = 15000) -> np.ndarray:
    """
    Standard LLL lattice basis reduction on integer row vectors.
    Uses float64 Gram-Schmidt orthogonalization with incremental updates on swap.
    """
    B = basis.astype(np.int64).copy()
    n, m = B.shape

    def _update_row(i: int, Bf: np.ndarray, ortho: np.ndarray, mu: np.ndarray, norm_sq: np.ndarray) -> None:
        v = Bf[i].copy()
        for j in range(i):
            if norm_sq[j] > 1e-12:
                mu[i, j] = float(np.dot(Bf[i], ortho[j]) / norm_sq[j])
                v = v - mu[i, j] * ortho[j]
            else:
                mu[i, j] = 0.0
        ortho[i] = v
        norm_sq[i] = float(np.dot(v, v))

    Bf = B.astype(np.float64)
    ortho = np.zeros((n, m), dtype=np.float64)
    mu = np.zeros((n, n), dtype=np.float64)
    norm_sq = np.zeros(n, dtype=np.float64)
    for i in range(n):
        _update_row(i, Bf, ortho, mu, norm_sq)

    k = 1
    it = 0
    while k < n and it < max_iter:
        it += 1
        # Size reduction
        for j in range(k - 1, -1, -1):
            if abs(mu[k, j]) > 0.5:
                q_ij = int(round(mu[k, j]))
                if q_ij != 0:
                    B[k] = B[k] - q_ij * B[j]
                    Bf[k] = B[k].astype(np.float64)
                    mu[k, : j + 1] -= q_ij * mu[j, : j + 1]
                    mu[k, j] -= q_ij

        # Lovasz condition
        if norm_sq[k] >= (delta - mu[k, k - 1] ** 2) * norm_sq[k - 1]:
            k += 1
        else:
            B[[k, k - 1]] = B[[k - 1, k]]
            Bf[[k, k - 1]] = Bf[[k - 1, k]]
            for row_idx in range(k - 1, n):
                _update_row(row_idx, Bf, ortho, mu, norm_sq)
            k = max(k - 1, 1)

    return B


def kannan_embedding_attack(
    A: np.ndarray, b: np.ndarray, q: int = Q_FERMAT, embed_weight: int = 1
) -> dict[str, object]:
    """
    Kannan's embedding for b = (A @ s + e) mod q (where A is m x d).
    Row lattice basis of dimension (m + d + 1) x (m + d + 1):
        [ q * I_m   |  0    | 0 ]
        [ A^T       |  I_d  | 0 ]
        [ b^T       |  0    | M ]
    Target short vector: (k*q + s^T A^T - b^T, s^T, -M) = (-e^T, s^T, -M).
    """
    m, d = A.shape
    dim = m + d + 1
    L = np.zeros((dim, dim), dtype=np.int64)
    L[:m, :m] = q * np.eye(m, dtype=np.int64)
    L[m : m + d, :m] = A.T % q
    L[m : m + d, m : m + d] = np.eye(d, dtype=np.int64)
    L[m + d, :m] = b % q
    L[m + d, m + d] = embed_weight

    t0 = time.perf_counter()
    L_red = lll_reduce(L, delta=0.99)
    elapsed = time.perf_counter() - t0

    norms = np.linalg.norm(L_red.astype(np.float64), axis=1)
    min_norm = float(np.min(norms))

    # Gaussian Heuristic for (m+d+1)-dim lattice with det = q^m * embed_weight
    det_log = m * math.log(q) + math.log(max(embed_weight, 1))
    gh = math.sqrt(dim / (2.0 * math.pi * math.e)) * math.exp(det_log / dim)

    # Check if any row has |last_coord| == embed_weight and recovers s
    recovered_s = None
    for row in L_red:
        if abs(int(row[-1])) == embed_weight:
            sign = -1 if int(row[-1]) == embed_weight else 1
            cand_s = (sign * row[m : m + d]) % q
            cand_e = center_mod((b - A @ cand_s) % q, q)
            if recovered_s is None or np.linalg.norm(cand_e) < np.linalg.norm(
                center_mod((b - A @ recovered_s) % q, q)
            ):
                recovered_s = cand_s

    return {
        "dim": dim,
        "elapsed_s": elapsed,
        "lll_min_norm": min_norm,
        "gaussian_heuristic": gh,
        "recovered_s": recovered_s,
    }


# ==============================================================================
# Objective 1: Lattice Reduction & Kannan/CVP Experiments
# ==============================================================================

def run_objective_1_lattice(engine: BandlimitedDualKeyEngine) -> dict[str, object]:
    print("\n[Objective 1] Lattice Reduction & Kannan/CVP Attacks...")
    B = engine.B_matrix
    rank_B, det_B = mod_mat_rank_and_det(B, Q_FERMAT)
    B_inv = mod_mat_inv(B, Q_FERMAT)

    # 1A. Positive Control: small-noise LWE (s, e in {-3..3}) on sub-dimensions d=8, 12, 16
    rng = np.random.default_rng(20261122)
    controls = []
    for d in (6, 8, 12):
        A_sub = B[:d, :d]
        s_small = rng.integers(-3, 4, size=d, dtype=np.int64) % Q_FERMAT
        e_small = rng.integers(-3, 4, size=d, dtype=np.int64)
        b_small = (A_sub @ s_small + e_small) % Q_FERMAT
        res = kannan_embedding_attack(A_sub, b_small, Q_FERMAT, embed_weight=1)
        ok = res["recovered_s"] is not None and bool(np.array_equal(res["recovered_s"], s_small))
        controls.append({
            "dim_d": d,
            "lattice_dim": res["dim"],
            "lll_min_norm": res["lll_min_norm"],
            "gaussian_heuristic": res["gaussian_heuristic"],
            "recovered_exact": ok,
            "elapsed_s": res["elapsed_s"],
        })
        print(f"  [Control Small-Noise d={d}] recovered={ok}, min_norm={res['lll_min_norm']:.2f}, GH={res['gaussian_heuristic']:.2f}")

    # 1B. Actual hardened dual-key: uniform e_priv in Z_65537, S_priv in [0, 65535]
    key = bytes(range(32))
    out_hard = engine.refactor_public_output(123456789, 987654321, key, 1, mode="dual_key_stochastic_hardened", include_private_debug=True)
    s_priv = out_hard["s_priv_state"].astype(np.int64)
    y_pub = out_hard["y_pub_vector"].astype(np.int64)
    e_priv = _derive_dual_key_noise(key, 1, dim=W, q_mod=Q_FERMAT)

    # Verify equation Y_pub == (B @ S_priv + e_priv) mod q
    assert np.array_equal(y_pub, (B @ s_priv + e_priv) % Q_FERMAT)

    # Measure true vector norm vs Gaussian Heuristic in Kannan embedding
    hardened_tests = []
    for d in (6, 8, 12):
        A_sub = B[:d, :d]
        s_sub = s_priv[:d]
        # Note: even if attacker knew the remaining (32-d) coordinates of S_priv,
        # the sub-system b_sub = (A_sub @ s_sub + e_sub) mod q has uniform e_sub!
        e_sub = e_priv[:d]
        b_sub = (A_sub @ s_sub + e_sub) % Q_FERMAT
        true_vec = np.concatenate([center_mod(-e_sub, Q_FERMAT), center_mod(s_sub, Q_FERMAT), [1]])
        true_norm = float(np.linalg.norm(true_vec.astype(np.float64)))
        res = kannan_embedding_attack(A_sub, b_sub, Q_FERMAT, embed_weight=1)
        ok = res["recovered_s"] is not None and bool(np.array_equal(res["recovered_s"], s_sub))
        hardened_tests.append({
            "dim_d": d,
            "lattice_dim": res["dim"],
            "true_target_norm": true_norm,
            "lll_min_norm": res["lll_min_norm"],
            "gaussian_heuristic": res["gaussian_heuristic"],
            "true_norm_to_gh_ratio": true_norm / res["gaussian_heuristic"],
            "recovered_exact": ok,
            "elapsed_s": res["elapsed_s"],
        })
        print(
            f"  [Hardened Uniform-Noise d={d}] recovered={ok}, true_norm={true_norm:.1f}, "
            f"GH={res['gaussian_heuristic']:.1f} (ratio={true_norm/res['gaussian_heuristic']:.1f}x), "
            f"lll_min={res['lll_min_norm']:.1f}"
        )

    # Full 32-dim theoretical Kannan norm vs GH
    true_full_vec = np.concatenate([center_mod(-e_priv, Q_FERMAT), center_mod(s_priv, Q_FERMAT), [1]])
    true_full_norm = float(np.linalg.norm(true_full_vec.astype(np.float64)))
    dim_full = 2 * W + 1
    gh_full = math.sqrt(dim_full / (2.0 * math.pi * math.e)) * (Q_FERMAT ** (W / dim_full))

    # 1C. Check uniformity of e_priv over 1,000 sessions (32,000 samples in Z_65537)
    e_samples = np.concatenate([_derive_dual_key_noise(key, i + 1, dim=W, q_mod=Q_FERMAT) for i in range(1000)])
    # Bin into 64 buckets to check chi-square uniformity
    hist, _ = np.histogram(e_samples, bins=64, range=(0, Q_FERMAT))
    expected_per_bin = len(e_samples) / 64.0
    chi2_e = float(np.sum((hist - expected_per_bin) ** 2 / expected_per_bin))

    # 1D. Linear raw mode exact inversion
    out_raw = engine.refactor_public_output(123456789, 987654321, key, 1, mode="linear_bandlimited_raw", include_private_debug=True)
    s_rec_raw = (B_inv @ out_raw["y_pub_vector"]) % Q_FERMAT
    raw_broken = bool(np.array_equal(s_rec_raw, out_raw["s_priv_state"].astype(np.int64)))

    return {
        "B_matrix_rank_mod_q": int(rank_B),
        "B_matrix_det_mod_q": int(det_B),
        "B_matrix_invertible": rank_B == W and det_B != 0,
        "raw_mode_exact_inversion_broken": raw_broken,
        "positive_control_small_noise_lwe": controls,
        "hardened_uniform_noise_kannan_lll": hardened_tests,
        "full_32d_true_target_norm": true_full_norm,
        "full_32d_gaussian_heuristic": gh_full,
        "full_32d_true_to_gh_ratio": true_full_norm / gh_full,
        "e_priv_uniformity_check": {
            "n_elements": int(len(e_samples)),
            "mean": float(np.mean(e_samples)),
            "expected_mean": (Q_FERMAT - 1) / 2.0,
            "std": float(np.std(e_samples)),
            "expected_std": math.sqrt((Q_FERMAT**2 - 1) / 12.0),
            "chi2_64bins": chi2_e,
        },
    }


# ==============================================================================
# Objective 2: NIST SP 800-22 on Raw y_pub_bytes
# ==============================================================================

def run_objective_2_nist(engine: BandlimitedDualKeyEngine, target_bits: int = 1_000_000) -> dict[str, object]:
    print(f"\n[Objective 2] NIST SP 800-22 on Raw y_pub_bytes ({target_bits:,} bits)...")
    key = b"LOTE_A_NIST_AUDIT_KEY_2026_V5!!!"
    x0, y0 = 0x123456789ABCDEF, 0xFEDCBA987654321

    raw_bytes_chunks: list[bytes] = []
    raw_linear_chunks: list[bytes] = []
    packed16_chunks: list[bytes] = []
    digest256_chunks: list[bytes] = []

    n_calls_needed = math.ceil(target_bits / (96 * 8))
    for i in range(n_calls_needed):
        r_h = engine.refactor_public_output(x0, y0, key, i + 1, mode="dual_key_stochastic_hardened")
        raw_bytes_chunks.append(r_h["y_pub_bytes"])
        digest256_chunks.append(r_h["y_pub_digest_256"])
        # Also collect 16-bit masked words (rejecting v == 65536) for root-cause ablation
        vec = r_h["y_pub_vector"]
        masked = [int(v).to_bytes(2, "big") for v in vec if int(v) < 65536]
        packed16_chunks.append(b"".join(masked))

        r_l = engine.refactor_public_output(x0, y0, key, i + 1, mode="linear_bandlimited_raw")
        raw_linear_chunks.append(r_l["y_pub_bytes"])

    # Continue generating digest256 and packed16 if needed to reach target_bits
    idx = n_calls_needed
    while sum(len(c) for c in packed16_chunks) * 8 < target_bits:
        idx += 1
        r_h = engine.refactor_public_output(x0, y0, key, idx, mode="dual_key_stochastic_hardened")
        vec = r_h["y_pub_vector"]
        packed16_chunks.append(b"".join(int(v).to_bytes(2, "big") for v in vec if int(v) < 65536))

    while sum(len(c) for c in digest256_chunks) * 8 < target_bits:
        idx += 1
        r_h = engine.refactor_public_output(x0, y0, key, idx, mode="dual_key_stochastic_hardened")
        digest256_chunks.append(r_h["y_pub_digest_256"])

    def bytes_to_bits(data: bytes, n_bits: int) -> np.ndarray:
        arr = np.frombuffer(data, dtype=np.uint8)
        bits = np.unpackbits(arr)[:n_bits]
        return bits

    streams = {
        "raw_y_pub_bytes_hardened": bytes_to_bits(b"".join(raw_bytes_chunks), target_bits),
        "raw_y_pub_bytes_linear": bytes_to_bits(b"".join(raw_linear_chunks), target_bits),
        "y_pub_16bit_unpadded_hardened": bytes_to_bits(b"".join(packed16_chunks), target_bits),
        "y_pub_digest_256_hardened": bytes_to_bits(b"".join(digest256_chunks), target_bits),
    }

    nist_results = {}
    for name, bits in streams.items():
        ones_ratio = float(np.mean(bits))
        res_list = run_nist_suite(bits)
        passes = sum(1 for r in res_list if r.passed)
        total = len(res_list)
        nist_results[name] = {
            "length_bits": int(len(bits)),
            "ones_proportion": ones_ratio,
            "passes": passes,
            "total": total,
            "pass_rate": passes / total,
            "tests": [
                {
                    "test_id": r.test_id,
                    "name": r.name,
                    "statistic": float(r.statistic),
                    "p_value": float(r.p_value),
                    "passed": bool(r.passed),
                }
                for r in res_list
            ],
        }
        print(f"  [{name}] ones={ones_ratio:.4f} | passed={passes}/{total}")

    return nist_results


# ==============================================================================
# Objective 3: Related-Key & Nonce-Reuse Attacks
# ==============================================================================

def run_objective_3_related_key(engine: BandlimitedDualKeyEngine) -> dict[str, object]:
    print("\n[Objective 3] Related-Key & Nonce-Reuse Attacks...")
    B = engine.B_matrix
    B_inv = mod_mat_inv(B, Q_FERMAT)
    rng = np.random.default_rng(20261123)

    # 3A. Related-Key Bit-Flip (HD=1) and Arithmetic (+1) on s
    n_pairs = 500
    hd_e_bitflip = []
    hd_y_bitflip = []
    hd_e_arith = []
    hd_y_arith = []
    diff_y_mod_zero_count = 0

    for i in range(n_pairs):
        s1 = rng.bytes(32)
        # Single bit flip in byte 0 LSB
        s2_bf = bytearray(s1)
        s2_bf[i % 32] ^= 1 << (i % 8)
        s2_bf = bytes(s2_bf)
        # Arithmetic +1 mod 2^256
        s2_ar = ((int.from_bytes(s1, "big") + 1) % (1 << 256)).to_bytes(32, "big")

        x = int.from_bytes(rng.bytes(32), "big") % (2**255 - 19)
        y = int.from_bytes(rng.bytes(32), "big") % (2**255 - 19)

        r1 = engine.refactor_public_output(x, y, s1, i + 1, mode="dual_key_stochastic_hardened")
        r2_bf = engine.refactor_public_output(x, y, s2_bf, i + 1, mode="dual_key_stochastic_hardened")
        r2_ar = engine.refactor_public_output(x, y, s2_ar, i + 1, mode="dual_key_stochastic_hardened")

        e1 = _derive_dual_key_noise(s1, i + 1, dim=W, q_mod=Q_FERMAT)
        e2_bf = _derive_dual_key_noise(s2_bf, i + 1, dim=W, q_mod=Q_FERMAT)
        e2_ar = _derive_dual_key_noise(s2_ar, i + 1, dim=W, q_mod=Q_FERMAT)

        # Bitwise Hamming distance on 16-bit masked values
        hd_e_bf = sum((int(a) ^ int(b)).bit_count() for a, b in zip(e1, e2_bf)) / (W * 16.0)
        hd_e_a = sum((int(a) ^ int(b)).bit_count() for a, b in zip(e1, e2_ar)) / (W * 16.0)
        hd_y_bf = sum((int(a) ^ int(b)).bit_count() for a, b in zip(r1["y_pub_vector"], r2_bf["y_pub_vector"])) / (W * 16.0)
        hd_y_a = sum((int(a) ^ int(b)).bit_count() for a, b in zip(r1["y_pub_vector"], r2_ar["y_pub_vector"])) / (W * 16.0)

        hd_e_bitflip.append(hd_e_bf)
        hd_e_arith.append(hd_e_a)
        hd_y_bitflip.append(hd_y_bf)
        hd_y_arith.append(hd_y_a)

        if np.any(((r1["y_pub_vector"] - r2_bf["y_pub_vector"]) % Q_FERMAT) == 0):
            diff_y_mod_zero_count += 1

    # 3B. CRITICAL: Same (s, n_sess) reused on different (x1, y1) != (x2, y2)
    s_fixed = bytes(range(32))
    n_sess_reused = 42
    nonce_reuse_success = 0
    nonce_reuse_trials = 20
    for t in range(nonce_reuse_trials):
        x1 = int.from_bytes(rng.bytes(32), "big") % (2**255 - 19)
        y1 = int.from_bytes(rng.bytes(32), "big") % (2**255 - 19)
        x2 = int.from_bytes(rng.bytes(32), "big") % (2**255 - 19)
        y2 = int.from_bytes(rng.bytes(32), "big") % (2**255 - 19)

        out1 = engine.refactor_public_output(x1, y1, s_fixed, n_sess_reused, mode="dual_key_stochastic_hardened", include_private_debug=True)
        out2 = engine.refactor_public_output(x2, y2, s_fixed, n_sess_reused, mode="dual_key_stochastic_hardened", include_private_debug=True)

        delta_y = (out1["y_pub_vector"] - out2["y_pub_vector"]) % Q_FERMAT
        delta_s_recovered = (B_inv @ delta_y) % Q_FERMAT
        delta_s_true = (out1["s_priv_state"].astype(np.int64) - out2["s_priv_state"].astype(np.int64)) % Q_FERMAT

        if np.array_equal(delta_s_recovered, delta_s_true):
            nonce_reuse_success += 1

    print(f"  [Related-Key HD=1] mean bit-HD(e_priv)={np.mean(hd_e_bitflip):.4f}, mean bit-HD(Y_pub)={np.mean(hd_y_bitflip):.4f}")
    print(f"  [Related-Key +1]   mean bit-HD(e_priv)={np.mean(hd_e_arith):.4f}, mean bit-HD(Y_pub)={np.mean(hd_y_arith):.4f}")
    print(f"  [Nonce-Reuse Attack (same s, n_sess)] Delta S_priv exact recovery: {nonce_reuse_success}/{nonce_reuse_trials}")

    # 3C. Related spectral matrices B_{K_1} vs B_{K_2}
    eng2 = BandlimitedDualKeyEngine(BandlimitedKernelSpec(T=1001.0, alpha=0.5, grid_points=256))
    rank_diff, det_diff = mod_mat_rank_and_det((B - eng2.B_matrix) % Q_FERMAT, Q_FERMAT)

    return {
        "related_key_bitflip_hd1": {
            "n_pairs": n_pairs,
            "e_priv_bit_hd_mean": float(np.mean(hd_e_bitflip)),
            "y_pub_bit_hd_mean": float(np.mean(hd_y_bitflip)),
        },
        "related_key_arith_plus1": {
            "n_pairs": n_pairs,
            "e_priv_bit_hd_mean": float(np.mean(hd_e_arith)),
            "y_pub_bit_hd_mean": float(np.mean(hd_y_arith)),
        },
        "nonce_reuse_differential_cancellation": {
            "trials": nonce_reuse_trials,
            "exact_delta_s_priv_recovered": nonce_reuse_success,
            "recovery_rate": nonce_reuse_success / nonce_reuse_trials,
            "root_cause": "_derive_dual_key_noise(s, n_sess) is independent of (x, y); reusing (s, n_sess) cancels e_priv in Y_pub(x1,y1) - Y_pub(x2,y2) mod q.",
        },
        "spectral_matrix_diff_rank_mod_q": int(rank_diff),
    }


# ==============================================================================
# Objective 4: Empirical Verification of KEM/PKE Impossibility
# ==============================================================================

def run_objective_4_kem_refutation(engine: BandlimitedDualKeyEngine) -> dict[str, object]:
    print("\n[Objective 4] KEM/PKE vs PRF/Commitment Verification...")
    B = engine.B_matrix
    key = bytes(range(32))
    out = engine.refactor_public_output(111, 222, key, 1, mode="dual_key_stochastic_hardened", include_private_debug=True)
    y_pub = out["y_pub_vector"].astype(np.int64)
    s_priv = out["s_priv_state"].astype(np.int64)

    # Attempt Regev-style inner product decapsulation:
    # Suppose pk = (B, y_pub). Sender picks random r in {0,1}^32 and bit m in {0,1}:
    # u = B^T r mod q, v = <r, y_pub> + m * floor(q/2) mod q.
    # Receiver with s_priv computes v - <s_priv, u> = <r, y_pub - B s_priv> + m*floor(q/2) = <r, e_priv> + m*floor(q/2) mod q.
    # In standard LWE, <r, e_priv> is small, so rounding recovers m.
    # Here, e_priv is UNIFORM in Z_q, so <r, e_priv> is UNIFORM in Z_q -> ~50% bit error rate (random coin flip)!
    rng = np.random.default_rng(20261124)
    trials = 1000
    correct = 0
    for _ in range(trials):
        r = rng.integers(0, 2, size=W, dtype=np.int64)
        m_bit = int(rng.integers(0, 2))
        u = (B.T @ r) % Q_FERMAT
        v = (int(np.dot(r, y_pub)) + m_bit * (Q_FERMAT // 2)) % Q_FERMAT
        diff = (v - int(np.dot(s_priv, u))) % Q_FERMAT
        # Decode: closer to 0 -> 0, closer to q/2 -> 1
        dist_0 = min(diff, Q_FERMAT - diff)
        dist_half = abs(diff - Q_FERMAT // 2)
        m_dec = 0 if dist_0 < dist_half else 1
        if m_dec == m_bit:
            correct += 1

    acc = correct / trials
    print(f"  [Regev-style PKE/KEM decapsulation test] accuracy={acc:.4f} (expected 0.5000 = pure random guessing)")

    return {
        "regev_style_kem_decapsulation_accuracy": acc,
        "supports_kem_or_pke": False,
        "supported_primitives": ["Keyed PRF (with fixed/unique n_sess)", "Symmetric Verifiable Commitment"],
        "impossibility_reason": (
            "e_priv is uniform in Z_65537^32, so I(S_priv; Y_pub | B) = 0 (exact OTP mask in Z_q^32). "
            "There is no small-noise region for rounding/decapsulation, and B_{K_j} is a public invertible matrix with no trapdoor."
        ),
    }


def main() -> None:
    spec = BandlimitedKernelSpec(T=1000.0, alpha=0.5, grid_points=256)
    engine = BandlimitedDualKeyEngine(spec)

    results = {
        "metadata": {
            "target": "implementacao/bandlimited_dual_key.py",
            "q_mod": Q_FERMAT,
            "dim": W,
            "spec": {"T": spec.T, "alpha": spec.alpha, "grid_points": spec.grid_points},
        },
        "objective_1_lattice_kannan_cvp": run_objective_1_lattice(engine),
        "objective_2_nist_sp800_22_y_pub": run_objective_2_nist(engine, target_bits=1_000_000),
        "objective_3_related_key_and_nonce_reuse": run_objective_3_related_key(engine),
        "objective_4_kem_pke_refutation": run_objective_4_kem_refutation(engine),
    }

    out_json = REPO_ROOT / "resultados" / "v5_sandbox" / "lote_a_lattice_report.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nSaved raw JSON results to: {out_json}")


if __name__ == "__main__":
    main()
