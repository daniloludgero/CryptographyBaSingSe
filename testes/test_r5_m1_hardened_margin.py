"""
M_R5_1 — Bateria endurecida em 1R..8R do RSD-S v5.1 (núcleo C AVX2 constant-time)
para detectar RSD 2R e medir o alcance máximo e a margem de segurança por ataque.
"""
from __future__ import annotations

import json
import sys
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
    build_rsd_1r_linear_masks,
    load_rsd_c_core,
    measure_avalanche,
    measure_uniformity,
)

RESULTS_JSON = Path("/tmp/r5_build/r5_m1_results.json")


@pytest.fixture(scope="module")
def c_lib():
    return load_rsd_c_core()


@pytest.fixture(scope="module")
def fixed_key() -> bytes:
    # Chave determinística de teste de 32 bytes para reprodutibilidade dos testes
    return bytes.fromhex("00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef")


@pytest.fixture(scope="module")
def rsd_1r_linear_masks():
    return build_rsd_1r_linear_masks(n_masks=8, active_word=0, seed=42)


def _max_reached_round(round_flags: dict[int, bool]) -> int:
    reached = [r for r, flag in round_flags.items() if flag]
    return max(reached) if reached else 0


def test_m1_integral_square_detects_1r_2r_and_margin(c_lib, fixed_key):
    """Integral/Square (Lambda-set 2^16, trials=2) deve detectar 1R e 2R deterministicamente (32/32 XOR==0)."""
    rng = np.random.default_rng(2026112201)
    res_by_round = {}
    for r in range(1, 9):
        prim = RSDKeyedV5(c_lib, fixed_key, n_sess=1, rounds=r, schedule_rounds=8, with_sha=False)
        res = attack_integral_square(prim, active_word=0, trials=2, rng=rng)
        res_by_round[r] = res

    assert res_by_round[1]["consistent_zero_xor_words"] == 32
    assert res_by_round[1]["full_state_balanced"] is True
    assert res_by_round[2]["consistent_zero_xor_words"] == 32
    assert res_by_round[2]["full_state_balanced"] is True

    for r in range(3, 9):
        assert res_by_round[r]["full_state_balanced"] is False
        assert res_by_round[r]["consistent_zero_xor_words"] < 32

    max_r = _max_reached_round({r: v["detected"] for r, v in res_by_round.items()})
    assert max_r == 2


def test_m1_differential_and_truncated_1r_to_8r(c_lib, fixed_key):
    """Diferencial & Diferencial Truncado (entradas aleatórias 512-bit) em 1R..8R."""
    rng = np.random.default_rng(2026112202)
    res_by_round = {}
    for r in range(1, 9):
        prim = RSDKeyedV5(c_lib, fixed_key, n_sess=1, rounds=r, schedule_rounds=8, with_sha=False)
        res = attack_differential(prim, n_pairs=4096, active_word=0, rng=rng)
        res_by_round[r] = res

    # 1R deve ser fortemente detectado (colisões diferenciais na palavra ~2x RO => z >> 5)
    assert res_by_round[1]["detected"] is True
    assert abs(res_by_round[1]["word_diff_coll_z"]) > 5.0
    # 8R completo não deve ser distinguido
    assert res_by_round[8]["detected"] is False


def test_m1_linear_walsh_1r_to_8r(c_lib, fixed_key, rsd_1r_linear_masks):
    """Linear/Walsh com máscaras estruturais (M^T)^{-1} de 1 S-box e N=524288 em 1R..8R."""
    rng = np.random.default_rng(2026112203)
    res_by_round = {}
    for r in range(1, 9):
        prim = RSDKeyedV5(c_lib, fixed_key, n_sess=1, rounds=r, schedule_rounds=8, with_sha=False)
        res = attack_linear_walsh(
            prim,
            n_samples=524_288,
            n_masks=32,
            structured_masks=rsd_1r_linear_masks,
            rng=rng,
        )
        res_by_round[r] = res

    # 1R deve ser detectado pelas máscaras estruturais (corr >= 2^-7 => z >= 5.66)
    assert res_by_round[1]["detected"] is True
    # 8R não deve apresentar viés linear estatisticamente significativo
    assert res_by_round[8]["detected"] is False


def test_m1_algebraic_anf_degree_1r_to_4r(c_lib, fixed_key):
    """ANF via Transformada de Möbius 16-bit: grau 15 em 1R/2R vs saturação 16 em 3R/4R."""
    rng = np.random.default_rng(2026112204)
    res_by_round = {}
    for r in range(1, 5):
        prim = RSDKeyedV5(c_lib, fixed_key, n_sess=1, rounds=r, schedule_rounds=8, with_sha=False)
        res = attack_algebraic_anf(prim, active_word=0, n_out_bits=16, rng=rng)
        res_by_round[r] = res

    assert res_by_round[1]["max_algebraic_degree"] == 15
    assert res_by_round[1]["saturated_top_monomial_bits"] == 0
    assert res_by_round[2]["max_algebraic_degree"] == 15
    assert res_by_round[2]["saturated_top_monomial_bits"] == 0

    assert res_by_round[3]["max_algebraic_degree"] == 16
    assert res_by_round[3]["saturated_top_monomial_bits"] > 0
    assert res_by_round[4]["max_algebraic_degree"] == 16
    assert res_by_round[4]["saturated_top_monomial_bits"] > 0


def test_m1_qrom_analog_hardened_and_collect_full_report(c_lib, fixed_key, rsd_1r_linear_masks):
    """
    Executa QROM-analog endurecido (n=10,12,14,16 sem y=12345 fixo) e consolida
    todas as métricas 1R..8R em JSON para o relatório M_R5_1.
    """
    rng = np.random.default_rng(2026112205)

    # 1. QROM-analog em 1R..8R
    qrom_by_round = {}
    for r in range(1, 9):
        def fac(k_bytes, base_b, _r=r):
            return RSDKeyedV5(c_lib, k_bytes, n_sess=1, rounds=_r, schedule_rounds=8, with_sha=False, base_block=base_b)

        qrom_by_round[r] = attack_qrom_analog(
            fac,
            n_bits_list=(10, 12, 14, 16),
            k_keys=4,
            k_ro=40,
            flag_z=4.0,
            rng=rng,
        )

    # 8R não pode ser distinguido de RO
    assert qrom_by_round[8]["distinguished_from_RO"] is False

    # 2. Consolidar todas as métricas em 1R..8R com seeds reprodutíveis para o relatório
    summary = {"integral": {}, "differential": {}, "linear": {}, "algebraic_anf": {}, "qrom_analog": qrom_by_round, "avalanche": {}, "uniformity": {}}

    for r in range(1, 9):
        prim = RSDKeyedV5(c_lib, fixed_key, n_sess=1, rounds=r, schedule_rounds=8, with_sha=False)
        summary["integral"][r] = attack_integral_square(prim, active_word=0, trials=2, rng=np.random.default_rng(100 + r))
        summary["differential"][r] = attack_differential(prim, n_pairs=4096, active_word=0, rng=np.random.default_rng(200 + r))
        summary["linear"][r] = attack_linear_walsh(
            prim,
            n_samples=524_288,
            n_masks=32,
            structured_masks=rsd_1r_linear_masks,
            rng=np.random.default_rng(300 + r),
        )
        if r <= 4:
            summary["algebraic_anf"][r] = attack_algebraic_anf(prim, active_word=0, n_out_bits=16, rng=np.random.default_rng(400 + r))
        summary["avalanche"][r] = measure_avalanche(prim, n_samples=1000, rng=np.random.default_rng(500 + r))
        summary["uniformity"][r] = measure_uniformity(prim, n_samples=16384, byte_idx=0, rng=np.random.default_rng(600 + r))

    # Calcular alcance máximo e margem de segurança sobre 8R
    margins = {}
    for atk_name, key_field in (
        ("Integral / Square (Lambda-set 2^16)", "detected"),
        ("Diferencial & Truncado", "detected"),
        ("Linear / Walsh", "detected"),
        ("Algébrico / ANF (grau < 16)", "non_saturated_detected"),
        ("QROM-analog (n=10..16)", "distinguished_from_RO"),
    ):
        src = summary["integral"] if "Integral" in atk_name else (
            summary["differential"] if "Diferencial" in atk_name else (
                summary["linear"] if "Linear" in atk_name else (
                    summary["algebraic_anf"] if "Algébrico" in atk_name else summary["qrom_analog"]
                )
            )
        )
        max_r = _max_reached_round({int(r): bool(v[key_field]) for r, v in src.items()})
        margins[atk_name] = {
            "max_round_detected": max_r,
            "total_rounds": 8,
            "margin_rounds": 8 - max_r,
            "margin_pct": round((8 - max_r) / 8.0 * 100.0, 1),
        }

    summary["margins"] = margins
    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON.write_text(json.dumps(summary, indent=2))
    print("\n=== MARGEM DE SEGURANÇA (8R) ===")
    for k, v in margins.items():
        print(f"  {k}: max_round={v['max_round_detected']}R | margem={v['margin_rounds']}R ({v['margin_pct']}%)")
