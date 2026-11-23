"""
M_R5_2 — Baseline AES-128 / AES-256 (NIST FIPS 197) vs RSD-S v5.1.

Valida os vetores oficiais NIST FIPS 197 (Apêndices B, C.1 e C.3), executa
exatamente o mesmo harness de métricas (`testes/r5_metrics_harness.py`) em
rodadas reduzidas e completas do AES-128 (10R) e AES-256 (14R), e compara
throughput (por chamada ctypes e em lote de 10.000 blocos) contra RSD-S v5.1 (8R).
"""
from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "testes") not in sys.path:
    sys.path.insert(0, str(ROOT / "testes"))

from r5_metrics_harness import (  # noqa: E402
    RSDKeyedV5,
    attack_algebraic_anf,
    attack_differential,
    attack_integral_square,
    attack_linear_walsh,
    attack_qrom_analog,
    load_rsd_c_core,
    measure_avalanche,
    measure_uniformity,
)

RESULTS_JSON = Path("/tmp/r5_build/r5_m2_results.json")


def load_aes_c_core(build_dir: Path = Path("/tmp/r5_build")) -> ctypes.CDLL:
    """Compila `testes/aes_prp_baseline.c` com flags estritas e carrega a .so."""
    build_dir = Path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    src = ROOT / "testes" / "aes_prp_baseline.c"
    so_path = build_dir / "lib_aes_prp_baseline.so"

    need_build = (not so_path.exists()) or (src.stat().st_mtime > so_path.stat().st_mtime)
    if need_build:
        subprocess.run(
            [
                "gcc",
                "-O3",
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
    p_u8 = ctypes.POINTER(ctypes.c_uint8)

    lib.aes_key_expand.argtypes = [p_u8, ctypes.c_int, p_u8]
    lib.aes_key_expand.restype = ctypes.c_int

    lib.aes_encrypt_block_rounds.argtypes = [
        p_u8,
        p_u8,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        p_u8,
    ]
    lib.aes_encrypt_block_rounds.restype = ctypes.c_int

    lib.aes_encrypt_batch_rounds.argtypes = [
        p_u8,
        ctypes.c_size_t,
        p_u8,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        p_u8,
    ]
    lib.aes_encrypt_batch_rounds.restype = ctypes.c_int
    return lib


class AESKeyedPRP:
    """
    Wrapper do núcleo C99 AES-128 / AES-256 compatível com `PRPPrimitive`
    de `testes/r5_metrics_harness.py`.
    """

    def __init__(
        self,
        lib: ctypes.CDLL,
        key: bytes,
        rounds: int | None = None,
        final_no_mixcolumns: bool = True,
    ) -> None:
        if len(key) == 16:
            self.key_bits = 128
            max_rounds = 10
            rk_bytes = 176
        elif len(key) == 32:
            self.key_bits = 256
            max_rounds = 14
            rk_bytes = 240
        else:
            raise ValueError(f"Chave AES deve ter 16 ou 32 bytes, obtido {len(key)}")

        if rounds is None:
            rounds = max_rounds
        if not 1 <= rounds <= max_rounds:
            raise ValueError(f"rounds ({rounds}) deve estar em 1..{max_rounds}")

        self.lib = lib
        self.key = key
        self.rounds = rounds
        self.max_rounds = max_rounds
        self.final_no_mixcolumns = 1 if final_no_mixcolumns else 0

        self.block_bytes = 16
        self.in_block_bytes = 16
        self.word_bits = 8
        self.name = f"AES-{self.key_bits} ({rounds}R)"

        p_u8 = ctypes.POINTER(ctypes.c_uint8)
        self._key_buf = (ctypes.c_uint8 * len(key)).from_buffer_copy(key)
        self._rk_buf = (ctypes.c_uint8 * rk_bytes)()
        rc = lib.aes_key_expand(
            ctypes.cast(self._key_buf, p_u8),
            self.key_bits,
            ctypes.cast(self._rk_buf, p_u8),
        )
        if rc != 0:
            raise RuntimeError(f"aes_key_expand retornou erro {rc}")

        self._in_buf = (ctypes.c_uint8 * 16)()
        self._out_buf = (ctypes.c_uint8 * 16)()
        self._p_rk = ctypes.cast(self._rk_buf, p_u8)
        self._p_in = ctypes.cast(self._in_buf, p_u8)
        self._p_out = ctypes.cast(self._out_buf, p_u8)
        self._enc_fn = lib.aes_encrypt_block_rounds
        self._batch_fn = lib.aes_encrypt_batch_rounds

    def eval_block(self, pt: bytes) -> bytes:
        if len(pt) != 16:
            raise ValueError(f"pt deve ter 16 bytes, obtido {len(pt)}")
        ctypes.memmove(self._in_buf, pt, 16)
        rc = self._enc_fn(
            self._p_in,
            self._p_rk,
            self.key_bits,
            self.rounds,
            self.final_no_mixcolumns,
            self._p_out,
        )
        if rc != 0:
            raise RuntimeError(f"aes_encrypt_block_rounds retornou erro {rc}")
        return bytes(self._out_buf)

    def eval_batch(self, pts_arr: np.ndarray) -> np.ndarray:
        """Avalia lote (N, 16) uint8 diretamente em C via aes_encrypt_batch_rounds."""
        arr = np.ascontiguousarray(pts_arr, dtype=np.uint8)
        if arr.ndim != 2 or arr.shape[1] != 16:
            raise ValueError(f"Shape inválido para eval_batch: {arr.shape}")
        n = arr.shape[0]
        out = np.empty((n, 16), dtype=np.uint8)
        p_u8 = ctypes.POINTER(ctypes.c_uint8)
        rc = self._batch_fn(
            arr.ctypes.data_as(p_u8),
            n,
            self._p_rk,
            self.key_bits,
            self.rounds,
            self.final_no_mixcolumns,
            out.ctypes.data_as(p_u8),
        )
        if rc != 0:
            raise RuntimeError(f"aes_encrypt_batch_rounds retornou erro {rc}")
        return out


@pytest.fixture(scope="module")
def aes_lib():
    return load_aes_c_core()


@pytest.fixture(scope="module")
def rsd_lib():
    return load_rsd_c_core()


@pytest.fixture(scope="module")
def fixed_key_32() -> bytes:
    return bytes.fromhex("00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef")


def test_fips_197_official_vectors(aes_lib):
    """Validação obrigatória 100% dos vetores oficiais NIST FIPS 197 (Apêndices B, C.1 e C.3)."""
    # Apêndice B (AES-128)
    k_b = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt_b = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    ct_b = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    assert AESKeyedPRP(aes_lib, k_b, rounds=10).eval_block(pt_b) == ct_b

    # Apêndice C.1 (AES-128)
    k_c1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt_c1 = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct_c1 = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert AESKeyedPRP(aes_lib, k_c1, rounds=10).eval_block(pt_c1) == ct_c1

    # Apêndice C.3 (AES-256)
    k_c3 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt_c3 = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct_c3 = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert AESKeyedPRP(aes_lib, k_c3, rounds=14).eval_block(pt_c3) == ct_c3


def test_m2_integral_square_aes128_and_aes256(aes_lib, fixed_key_32):
    """Ataque Integral/Square (trials=4): AES-128 e AES-256 detectados em 1R..3R, não em 4R+."""
    rng = np.random.default_rng(2026112210)
    k128 = fixed_key_32[:16]
    k256 = fixed_key_32

    for key, rounds_list in [(k128, [1, 2, 3, 4, 5, 10]), (k256, [1, 2, 3, 4, 5, 14])]:
        for r in rounds_list:
            prim = AESKeyedPRP(aes_lib, key, rounds=r, final_no_mixcolumns=True)
            res = attack_integral_square(prim, active_word=0, trials=4, rng=rng)
            if r <= 3:
                assert res["consistent_zero_xor_words"] == 16
                assert res["full_state_balanced"] is True
                assert res["detected"] is True
            else:
                assert res["consistent_zero_xor_words"] == 0
                assert res["full_state_balanced"] is False
                assert res["detected"] is False

    # Verificar comportamento idêntico com final_no_mixcolumns=0 em 1R..4R
    for key in (k128, k256):
        for r in (1, 2, 3, 4):
            prim = AESKeyedPRP(aes_lib, key, rounds=r, final_no_mixcolumns=False)
            res = attack_integral_square(prim, active_word=0, trials=4, rng=rng)
            if r <= 3:
                assert res["consistent_zero_xor_words"] == 16
                assert res["detected"] is True
            else:
                assert res["consistent_zero_xor_words"] == 0
                assert res["detected"] is False


def test_m2_full_suite_and_throughput_comparison(aes_lib, rsd_lib, fixed_key_32):
    """
    Executa todas as métricas do harness em AES-128 e AES-256, compara throughput
    contra RSD-S v5.1 e salva o resumo JSON em `/tmp/r5_build/r5_m2_results.json`.
    """
    rng = np.random.default_rng(2026112220)
    k128 = fixed_key_32[:16]
    k256 = fixed_key_32

    results: dict = {
        "aes128": {
            "integral": {},
            "integral_with_mc": {},
            "differential": {},
            "linear": {},
            "algebraic_anf": {},
            "qrom_analog": {},
            "avalanche": {},
            "uniformity": {},
        },
        "aes256": {
            "integral": {},
            "integral_with_mc": {},
            "differential": {},
            "linear": {},
            "algebraic_anf": {},
            "qrom_analog": {},
            "avalanche": {},
            "uniformity": {},
        },
    }

    configs = [
        ("aes128", k128, [1, 2, 3, 4, 5, 10], [1, 2, 3, 4, 10], 10),
        ("aes256", k256, [1, 2, 3, 4, 5, 14], [1, 2, 3, 4, 14], 14),
    ]

    for label, key, int_rounds, full_suite_rounds, max_r in configs:
        # 1. Integral / Square (final_no_mixcolumns=True)
        for r in int_rounds:
            prim = AESKeyedPRP(aes_lib, key, rounds=r, final_no_mixcolumns=True)
            results[label]["integral"][str(r)] = attack_integral_square(
                prim, active_word=0, trials=4, rng=rng
            )

        # 1b. Integral / Square (final_no_mixcolumns=False) em 1R..4R
        for r in (1, 2, 3, 4):
            prim = AESKeyedPRP(aes_lib, key, rounds=r, final_no_mixcolumns=False)
            results[label]["integral_with_mc"][str(r)] = attack_integral_square(
                prim, active_word=0, trials=4, rng=rng
            )

        # 2. Diferencial, Linear, Avalanche, Uniformidade
        for r in full_suite_rounds:
            prim = AESKeyedPRP(aes_lib, key, rounds=r, final_no_mixcolumns=True)
            results[label]["differential"][str(r)] = attack_differential(
                prim, n_pairs=4096, active_word=0, rng=rng
            )
            results[label]["linear"][str(r)] = attack_linear_walsh(
                prim, n_samples=16384, n_masks=64, rng=rng
            )
            results[label]["avalanche"][str(r)] = measure_avalanche(
                prim, n_samples=1000, rng=rng
            )
            results[label]["uniformity"][str(r)] = measure_uniformity(
                prim, n_samples=65536, byte_idx=0, rng=rng
            )

        # 3. Algébrico ANF em 1R..4R
        for r in (1, 2, 3, 4):
            prim = AESKeyedPRP(aes_lib, key, rounds=r, final_no_mixcolumns=True)
            results[label]["algebraic_anf"][str(r)] = attack_algebraic_anf(
                prim, active_word=0, n_out_bits=8, rng=rng
            )

        # 4. QROM-analog em 1R..4R e rodada completa
        key_len = len(key)
        for r in full_suite_rounds:
            def factory(k: bytes, _base: bytes, _r=r, _kl=key_len):
                return AESKeyedPRP(aes_lib, k[:_kl], rounds=_r, final_no_mixcolumns=True)

            results[label]["qrom_analog"][str(r)] = attack_qrom_analog(
                factory,
                n_bits_list=(10, 12, 14, 16),
                k_keys=4,
                k_ro=40,
                flag_z=4.0,
                rng=rng,
            )

        # Asserções de integridade para rodada completa
        assert results[label]["differential"][str(max_r)]["detected"] is False
        assert results[label]["linear"][str(max_r)]["detected"] is False
        assert results[label]["qrom_analog"][str(max_r)]["distinguished_from_RO"] is False
        assert 0.45 <= results[label]["avalanche"][str(max_r)]["mean_flip_fraction"] <= 0.55
        assert results[label]["uniformity"][str(max_r)]["p_value"] > 0.001

        # Em 1R, diferencial deve detectar fortemente (1 byte ativo -> 4 bytes ativos ou 1 byte ativo, colisões altas)
        assert results[label]["differential"]["1"]["detected"] is True
        # Em 1R, ANF tem grau 7 (< 8)
        assert results[label]["algebraic_anf"]["1"]["max_algebraic_degree"] == 7
        assert results[label]["algebraic_anf"]["1"]["non_saturated_detected"] is True

    # 5. Benchmark de Throughput: AES-128 (10R), AES-256 (14R) vs RSD-S v5.1 (8R)
    n_bench_single = 10_000
    n_bench_batch = 10_000

    aes128_full = AESKeyedPRP(aes_lib, k128, rounds=10, final_no_mixcolumns=True)
    aes256_full = AESKeyedPRP(aes_lib, k256, rounds=14, final_no_mixcolumns=True)
    rsd_full = RSDKeyedV5(rsd_lib, fixed_key_32, n_sess=1, rounds=8, schedule_rounds=8, with_sha=False)

    pt16 = rng.bytes(16)
    pt64 = rng.bytes(64)
    batch16 = np.frombuffer(rng.bytes(n_bench_batch * 16), dtype=np.uint8).reshape(n_bench_batch, 16)
    batch64_words = np.frombuffer(rng.bytes(n_bench_batch * 64), dtype=">u2").astype(np.uint16).reshape(n_bench_batch, 32)

    # Aquecimento
    for _ in range(100):
        aes128_full.eval_block(pt16)
        aes256_full.eval_block(pt16)
        rsd_full.eval_block(pt64)

    def bench_single(fn, arg, n: int, bsize: int) -> dict:
        t0 = time.perf_counter()
        for _ in range(n):
            fn(arg)
        dt = time.perf_counter() - t0
        us_per_call = (dt / n) * 1e6
        mb_per_s = (n * bsize) / (dt * 1024.0 * 1024.0)
        return {
            "n_calls": n,
            "block_bytes": bsize,
            "elapsed_s": round(dt, 4),
            "us_per_call": round(us_per_call, 3),
            "throughput_mb_s": round(mb_per_s, 3),
        }

    def bench_batch(fn, arg, n: int, bsize: int) -> dict:
        t0 = time.perf_counter()
        fn(arg)
        dt = time.perf_counter() - t0
        us_per_block = (dt / n) * 1e6
        mb_per_s = (n * bsize) / (dt * 1024.0 * 1024.0)
        return {
            "n_blocks": n,
            "block_bytes": bsize,
            "elapsed_s": round(dt, 5),
            "us_per_block": round(us_per_block, 4),
            "throughput_mb_s": round(mb_per_s, 3),
        }

    throughput = {
        "single_eval_block": {
            "aes128_10r": bench_single(aes128_full.eval_block, pt16, n_bench_single, 16),
            "aes256_14r": bench_single(aes256_full.eval_block, pt16, n_bench_single, 16),
            "rsd_s_v51_8r": bench_single(rsd_full.eval_block, pt64, n_bench_single, 64),
        },
        "batch_10000_blocks": {
            "aes128_10r_c_batch": bench_batch(aes128_full.eval_batch, batch16, n_bench_batch, 16),
            "aes256_14r_c_batch": bench_batch(aes256_full.eval_batch, batch16, n_bench_batch, 16),
            "rsd_s_v51_8r_eval_words": bench_batch(rsd_full.eval_words, batch64_words, n_bench_batch, 64),
        },
    }
    results["throughput"] = throughput

    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\n[M_R5_2] Resultados salvos em:", RESULTS_JSON)
    print("[M_R5_2] Throughput:", json.dumps(throughput, indent=2))
