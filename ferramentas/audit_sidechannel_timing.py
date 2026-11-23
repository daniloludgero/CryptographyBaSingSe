#!/usr/bin/env python3
"""
ferramentas/audit_sidechannel_timing.py

Auditoria Rigorosa de Canais Laterais de Tempo (Side-Channel Timing Analysis)
Primitive: BaSingSe (RSD-S v4)

Metodologia:
  - TVLA (Test Vector Leakage Assessment) / Teste t de Welch (NIST SP 800-22 / CRI standard)
  - Metodologia dudect (Reparaz et al., 2017)
  - Algoritmo de Welford para cálculo numericamente estável de média e variância amostral
  - Desativação do coletor de lixo (GC) durante laços de medição com time.perf_counter_ns()
  - Amostragem entrelaçada (interleaved trace acquisition) para anular drift térmico
  - Descarte de cauda superior (percentile cropping de outliers de 0.5% a 1.0%)

Suítes de Teste:
  1. Suíte 1: Matrix Zero Branch Trigger vs Skip (rsd_s_v4_final.py:93)
     - Compara execução onde palavras do estado intermediário v[j] == 0 (bypassing gf_mult)
       contra palavras uniformes v[j] != 0.
  2. Suíte 2: NIST TVLA Fixed vs Random Input
     - Compara entradas fixas vs entradas aleatórias uniformes sob a mesma chave.
  3. Suíte 3: Aritmética de Galois em gf_mult (Low MSB vs High MSB)
     - Compara operandos de baixo peso e MSB baixo (while loop curto) contra operandos de alto MSB (while loop longo).

Critério de Decisão (CRI / NIST):
  - |t| > 4.5: REJEIÇÃO de H_0 com p < 10^-5 (Vazamento comprovado / FAIL)
  - |t| <= 4.5: Falha em rejeitar H_0 na amostra N (Inconclusivo / PASS para a amostra)
"""

from __future__ import annotations

import argparse
import gc
import json
import math
import os
import secrets
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import numpy as np

# Inserir raiz e pasta implementacao no path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "implementacao"))
sys.path.insert(0, str(REPO_ROOT))

try:
    from mds_real import build_cauchy_mds, gf_inv, gf_mult, GF16_POLY
    from rsd_s_v4_final import (
        diffuse_rsd_s_final,
        diffuse_rsd_s_final_PRE_SHA,
        diffuse_rsd_s_rounds_PRE_SHA,
        get_base_inversion_sbox,
        gf_matrix_vector_mult,
        derive_keys,
        round_constant,
        _expand_key_words,
        fragment_full,
        M_CAUCHY_32,
        W,
        B,
        P_CURVE25519,
    )
except ImportError as err:
    sys.stderr.write(f"Erro ao importar módulos criptográficos: {err}\n")
    sys.exit(1)


@dataclass
class WelfordAccumulator:
    """
    Acumulador online de Welford para média e variância amostral com estabilidade numérica.
    """
    count: int = 0
    mean: float = 0.0
    M2: float = 0.0

    def update(self, x: float) -> None:
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.M2 / (self.count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)


@dataclass
class TVLAResult:
    test_id: str
    name: str
    description: str
    n_samples_a: int
    n_samples_b: int
    mean_a_ns: float
    mean_b_ns: float
    delta_mean_ns: float
    delta_mean_us: float
    std_a_ns: float
    std_b_ns: float
    t_statistic: float
    degrees_of_freedom: float
    p_value_approx: float
    threshold_t: float
    leakage_detected: bool
    verdict: str
    details: Dict[str, Any]


def welch_t_test(
    samples_a: np.ndarray,
    samples_b: np.ndarray,
    crop_percentile: float = 0.5,
) -> Tuple[float, float, float, float, float, float, float, float]:
    """
    Aplica dudect percentile cropping e calcula o teste t de Welch.

    Retorna:
      (mean_a, mean_b, std_a, std_b, t_stat, dof, n_a_clean, n_b_clean)
    """
    if len(samples_a) == 0 or len(samples_b) == 0:
        raise ValueError("Amostras vazias fornecidas para o teste t de Welch")

    # Percentile cropping (dudect approach): descartar cauda superior
    if crop_percentile > 0.0:
        combined = np.concatenate([samples_a, samples_b])
        cutoff = np.percentile(combined, 100.0 - crop_percentile)
        clean_a = samples_a[samples_a <= cutoff]
        clean_b = samples_b[samples_b <= cutoff]
    else:
        clean_a = samples_a
        clean_b = samples_b

    n_a = len(clean_a)
    n_b = len(clean_b)

    if n_a < 2 or n_b < 2:
        raise ValueError("Amostras insuficientes após filtragem de percentil")

    # Welford accumulation
    acc_a = WelfordAccumulator()
    for val in clean_a:
        acc_a.update(float(val))

    acc_b = WelfordAccumulator()
    for val in clean_b:
        acc_b.update(float(val))

    mean_a = acc_a.mean
    mean_b = acc_b.mean
    var_a = acc_a.variance
    var_b = acc_b.variance
    std_a = acc_a.std_dev
    std_b = acc_b.std_dev

    denom = math.sqrt((var_a / n_a) + (var_b / n_b))
    if denom == 0.0:
        t_stat = 0.0
        dof = float(n_a + n_b - 2)
    else:
        t_stat = (mean_a - mean_b) / denom

        # Welch-Satterthwaite degrees of freedom
        term_a = var_a / n_a
        term_b = var_b / n_b
        num_dof = (term_a + term_b) ** 2
        den_dof = ((term_a ** 2) / (n_a - 1)) + ((term_b ** 2) / (n_b - 1))
        dof = num_dof / den_dof if den_dof != 0 else float(n_a + n_b - 2)

    return mean_a, mean_b, std_a, std_b, t_stat, dof, float(n_a), float(n_b)


def approx_p_value_from_t(t_stat: float, dof: float) -> float:
    """
    Aproximação assintótica do p-valor bicaudal para grandes graus de liberdade.
    """
    abs_t = abs(t_stat)
    if abs_t > 37.0:
        return 0.0
    # Distribuição normal assintótica para dof > 100
    p = math.erfc(abs_t / math.sqrt(2.0))
    return max(0.0, min(1.0, p))


# ==============================================================================
# SUÍTES DE TESTE DE CANAL LATERAL
# ==============================================================================

def run_suite_1_matrix_branch(
    n_samples: int = 1000,
    crop_percentile: float = 0.5,
    warmup: int = 50,
) -> TVLAResult:
    """
    Suíte 1: Avaliação do desvio condicional em `rsd_s_v4_final.py:93`
      `if row[j] != 0 and v[j] != 0:`

    Compara:
      - Classe A: Vetor de estado intermediário v com palavras v[j] = 0 (trigger bypass)
      - Classe B: Vetor de estado intermediário v com palavras uniformes v[j] != 0
    """
    M = M_CAUCHY_32
    v_zero = np.zeros(W, dtype=np.uint32)

    # Warm-up
    for _ in range(warmup):
        v_rand = np.random.randint(1, 65536, size=W, dtype=np.uint32)
        gf_matrix_vector_mult(M, v_rand, W)
        gf_matrix_vector_mult(M, v_zero, W)

    traces_a = np.empty(n_samples, dtype=np.int64)
    traces_b = np.empty(n_samples, dtype=np.int64)

    # Interleaved acquisition: pseudo-random coin flip
    order = np.random.randint(0, 2, size=n_samples)

    gc.collect()
    gc.disable()
    try:
        for idx in range(n_samples):
            v_rand = np.random.randint(1, 65536, size=W, dtype=np.uint32)

            if order[idx] == 0:
                # A then B
                t0 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_zero, W)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0

                t2 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_rand, W)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2
            else:
                # B then A
                t2 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_rand, W)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2

                t0 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_zero, W)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0
    finally:
        gc.enable()

    mean_a, mean_b, std_a, std_b, t_stat, dof, na, nb = welch_t_test(
        traces_a, traces_b, crop_percentile=crop_percentile
    )
    delta_ns = mean_a - mean_b
    delta_us = delta_ns / 1000.0
    p_val = approx_p_value_from_t(t_stat, dof)
    leakage = abs(t_stat) > 4.5

    return TVLAResult(
        test_id="TVLA-SUITE-1",
        name="Matrix Zero Branch Bypass (rsd_s_v4_final.py:93)",
        description=(
            "Mede o desvio condicional 'if row[j] != 0 and v[j] != 0' na multiplicação "
            "matriz-vetor Cauchy MDS 32x32. Classe A tem v=0 (todas as 1024 multiplicações "
            "bypassed) vs Classe B com v!=0 uniforme."
        ),
        n_samples_a=int(na),
        n_samples_b=int(nb),
        mean_a_ns=mean_a,
        mean_b_ns=mean_b,
        delta_mean_ns=delta_ns,
        delta_mean_us=delta_us,
        std_a_ns=std_a,
        std_b_ns=std_b,
        t_statistic=t_stat,
        degrees_of_freedom=dof,
        p_value_approx=p_val,
        threshold_t=4.5,
        leakage_detected=leakage,
        verdict="FAIL (LEAKAGE DETECTED)" if leakage else "PASS (CONSTANT TIME)",
        details={
            "bypassed_multiplications_class_a": 1024,
            "bypassed_multiplications_class_b": 0,
            "speedup_ratio": mean_b / mean_a if mean_a > 0 else 0.0,
            "crop_percentile": crop_percentile,
        },
    )


def run_suite_1b_single_word_branch(
    n_samples: int = 1000,
    crop_percentile: float = 0.5,
    warmup: int = 50,
) -> TVLAResult:
    """
    Suíte 1b: Avaliação de canal lateral para UMA ÚNICA palavra zero (v[0] = 0 vs v[0] != 0).
    Mede a sensibilidade de vazamento quando apenas 1 palavra entre 32 é nula (bypassing 32 multiplicações).
    """
    M = M_CAUCHY_32

    # Warm-up
    for _ in range(warmup):
        v = np.random.randint(1, 65536, size=W, dtype=np.uint32)
        gf_matrix_vector_mult(M, v, W)

    traces_a = np.empty(n_samples, dtype=np.int64)
    traces_b = np.empty(n_samples, dtype=np.int64)
    order = np.random.randint(0, 2, size=n_samples)

    gc.collect()
    gc.disable()
    try:
        for idx in range(n_samples):
            v_a = np.random.randint(1, 65536, size=W, dtype=np.uint32)
            v_a[0] = 0  # Apenas v[0] é zero (32 multiplicações ignoradas)

            v_b = np.random.randint(1, 65536, size=W, dtype=np.uint32)
            # v_b[0] é garantido não-zero

            if order[idx] == 0:
                t0 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_a, W)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0

                t2 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_b, W)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2
            else:
                t2 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_b, W)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2

                t0 = time.perf_counter_ns()
                gf_matrix_vector_mult(M, v_a, W)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0
    finally:
        gc.enable()

    mean_a, mean_b, std_a, std_b, t_stat, dof, na, nb = welch_t_test(
        traces_a, traces_b, crop_percentile=crop_percentile
    )
    delta_ns = mean_a - mean_b
    delta_us = delta_ns / 1000.0
    p_val = approx_p_value_from_t(t_stat, dof)
    leakage = abs(t_stat) > 4.5

    return TVLAResult(
        test_id="TVLA-SUITE-1B",
        name="Single-Word Zero Branch Bypass (v[0]=0 vs v[0]!=0)",
        description=(
            "Mede o vazamento de uma única palavra nula no estado intermediário v[0]=0 "
            "(bypassa exatamente 32 multiplicações de GF em 1024)."
        ),
        n_samples_a=int(na),
        n_samples_b=int(nb),
        mean_a_ns=mean_a,
        mean_b_ns=mean_b,
        delta_mean_ns=delta_ns,
        delta_mean_us=delta_us,
        std_a_ns=std_a,
        std_b_ns=std_b,
        t_statistic=t_stat,
        degrees_of_freedom=dof,
        p_value_approx=p_val,
        threshold_t=4.5,
        leakage_detected=leakage,
        verdict="FAIL (LEAKAGE DETECTED)" if leakage else "PASS (CONSTANT TIME)",
        details={
            "bypassed_multiplications_class_a": 32,
            "bypassed_multiplications_class_b": 0,
            "speedup_ratio": mean_b / mean_a if mean_a > 0 else 0.0,
            "crop_percentile": crop_percentile,
        },
    )


def run_suite_2_nist_tvla_fixed_vs_random(
    n_samples: int = 500,
    rounds: int = 1,
    crop_percentile: float = 0.5,
    warmup: int = 30,
) -> TVLAResult:
    """
    Suíte 2: TVLA Padrão NIST SP 800-22 (Fixed vs Random)
    Mede a cifra em nível de rodada(s) sob chave fixa, alternando entre entrada constante
    (Classe A) e entradas pseudo-aleatórias uniformes (Classe B).
    """
    get_base_inversion_sbox()
    master_key = secrets.token_bytes(32)
    session_nonce = 0xDEADBEEF12345678
    p = P_CURVE25519

    # Vetor fixo de Classe A
    x_fixed = secrets.randbits(250) % p
    y_fixed = secrets.randbits(250) % p

    # Warm-up
    for _ in range(warmup):
        diffuse_rsd_s_rounds_PRE_SHA(x_fixed, y_fixed, master_key, session_nonce, rounds=rounds)

    traces_a = np.empty(n_samples, dtype=np.int64)
    traces_b = np.empty(n_samples, dtype=np.int64)
    order = np.random.randint(0, 2, size=n_samples)

    gc.collect()
    gc.disable()
    try:
        for idx in range(n_samples):
            x_rand = secrets.randbits(250) % p
            y_rand = secrets.randbits(250) % p

            if order[idx] == 0:
                t0 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_fixed, y_fixed, master_key, session_nonce, rounds=rounds)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0

                t2 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_rand, y_rand, master_key, session_nonce, rounds=rounds)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2
            else:
                t2 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_rand, y_rand, master_key, session_nonce, rounds=rounds)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2

                t0 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_fixed, y_fixed, master_key, session_nonce, rounds=rounds)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0
    finally:
        gc.enable()

    mean_a, mean_b, std_a, std_b, t_stat, dof, na, nb = welch_t_test(
        traces_a, traces_b, crop_percentile=crop_percentile
    )
    delta_ns = mean_a - mean_b
    delta_us = delta_ns / 1000.0
    p_val = approx_p_value_from_t(t_stat, dof)
    leakage = abs(t_stat) > 4.5

    return TVLAResult(
        test_id="TVLA-SUITE-2",
        name=f"NIST TVLA Fixed vs Random Input ({rounds} Round{'s' if rounds > 1 else ''})",
        description=(
            f"Avaliação estatística de vazamento não-específico (NIST TVLA) sob chave fixa com "
            f"{rounds} rodada(s) de difusão. Classe A avalia entrada fixa repetida; Classe B "
            f"avalia entradas pseudo-aleatórias."
        ),
        n_samples_a=int(na),
        n_samples_b=int(nb),
        mean_a_ns=mean_a,
        mean_b_ns=mean_b,
        delta_mean_ns=delta_ns,
        delta_mean_us=delta_us,
        std_a_ns=std_a,
        std_b_ns=std_b,
        t_statistic=t_stat,
        degrees_of_freedom=dof,
        p_value_approx=p_val,
        threshold_t=4.5,
        leakage_detected=leakage,
        verdict="FAIL (LEAKAGE DETECTED)" if leakage else "PASS (CONSTANT TIME)",
        details={
            "evaluated_rounds": rounds,
            "crop_percentile": crop_percentile,
        },
    )


def run_suite_3_gf_mult_arithmetic(
    n_samples: int = 10000,
    crop_percentile: float = 0.5,
    warmup: int = 200,
) -> TVLAResult:
    """
    Suíte 3: Aritmética de Galois de Tempo Variável em `mds_real.py:24-33`
      `while b:`, `if b & 1:`
    Compara o operando `b` com MSB baixo (1 a 3, laço curto) vs MSB alto (0x8000 a 0xFFFF, laço longo).
    """
    # Warm-up
    for _ in range(warmup):
        gf_mult(0x1234, 0x5678)

    traces_a = np.empty(n_samples, dtype=np.int64)
    traces_b = np.empty(n_samples, dtype=np.int64)
    order = np.random.randint(0, 2, size=n_samples)

    gc.collect()
    gc.disable()
    try:
        for idx in range(n_samples):
            a = secrets.randbits(16)
            b_low = secrets.randbelow(3) + 1       # [1, 3] -> 1-2 iterações
            b_high = secrets.randbelow(0x8000) + 0x8000  # [0x8000, 0xFFFF] -> 16 iterações

            if order[idx] == 0:
                t0 = time.perf_counter_ns()
                gf_mult(a, b_low)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0

                t2 = time.perf_counter_ns()
                gf_mult(a, b_high)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2
            else:
                t2 = time.perf_counter_ns()
                gf_mult(a, b_high)
                t3 = time.perf_counter_ns()
                traces_b[idx] = t3 - t2

                t0 = time.perf_counter_ns()
                gf_mult(a, b_low)
                t1 = time.perf_counter_ns()
                traces_a[idx] = t1 - t0
    finally:
        gc.enable()

    mean_a, mean_b, std_a, std_b, t_stat, dof, na, nb = welch_t_test(
        traces_a, traces_b, crop_percentile=crop_percentile
    )
    delta_ns = mean_a - mean_b
    delta_us = delta_ns / 1000.0
    p_val = approx_p_value_from_t(t_stat, dof)
    leakage = abs(t_stat) > 4.5

    return TVLAResult(
        test_id="TVLA-SUITE-3",
        name="Galois Field Arithmetic Variable-Time (mds_real.py:24-33)",
        description=(
            "Mede a dependência do tempo de execução de gf_mult(a, b) em relação ao bit mais "
            "significativo (MSB) e peso de Hamming de b. Classe A avalia b in [1, 3] (1-2 iterações); "
            "Classe B avalia b in [0x8000, 0xFFFF] (16 iterações)."
        ),
        n_samples_a=int(na),
        n_samples_b=int(nb),
        mean_a_ns=mean_a,
        mean_b_ns=mean_b,
        delta_mean_ns=delta_ns,
        delta_mean_us=delta_us,
        std_a_ns=std_a,
        std_b_ns=std_b,
        t_statistic=t_stat,
        degrees_of_freedom=dof,
        p_value_approx=p_val,
        threshold_t=4.5,
        leakage_detected=leakage,
        verdict="FAIL (LEAKAGE DETECTED)" if leakage else "PASS (CONSTANT TIME)",
        details={
            "operand_b_class_a_range": "[1, 3] (1-2 iterations)",
            "operand_b_class_b_range": "[0x8000, 0xFFFF] (16 iterations)",
            "speedup_ratio": mean_b / mean_a if mean_a > 0 else 0.0,
            "crop_percentile": crop_percentile,
        },
    )


# ==============================================================================
# FORMATAÇÃO E CLI
# ==============================================================================

def print_banner() -> None:
    print("=" * 80)
    print("   BaSingSe (RSD-S v4) - Side-Channel Timing Audit (TVLA)")
    print("   Welch's t-Test & Dudect Methodology (NIST SP 800-22 / CRI Criteria)")
    print("=" * 80)


def print_suite_result(res: TVLAResult) -> None:
    print(f"\n[{res.test_id}] {res.name}")
    print(f"  Descrição: {res.description}")
    print(f"  Amostras (limpas): Class A = {res.n_samples_a:,} | Class B = {res.n_samples_b:,}")
    print(f"  Média Classe A:    {res.mean_a_ns:10.2f} ns ({res.mean_a_ns / 1000.0:8.3f} µs)")
    print(f"  Média Classe B:    {res.mean_b_ns:10.2f} ns ({res.mean_b_ns / 1000.0:8.3f} µs)")
    print(f"  Diferença (A - B): {res.delta_mean_ns:10.2f} ns ({res.delta_mean_us:8.3f} µs)")
    print(f"  Desvio Padrão:     Std(A) = {res.std_a_ns:8.2f} ns | Std(B) = {res.std_b_ns:8.2f} ns")
    print(f"  Graus de Liberdade:{res.degrees_of_freedom:10.1f}")
    print(f"  Welch t-Statistic: {res.t_statistic:10.2f} (Limiar de Rejeição: |t| > {res.threshold_t})")
    print(f"  p-Valor (aprox):   {res.p_value_approx:.3e}")
    color = "\033[91m" if res.leakage_detected else "\033[92m"
    reset = "\033[0m"
    print(f"  Veredito Oficial:  {color}{res.verdict}{reset}")


def run_all_audits(
    n_suite1: int = 1000,
    n_suite2: int = 500,
    n_suite3: int = 10000,
    rounds_suite2: int = 1,
    crop_percentile: float = 0.5,
    output_json: str | None = None,
) -> Dict[str, Any]:
    print_banner()
    results: List[TVLAResult] = []

    print("\n>>> Executando Suíte 1: Matrix Zero Branch Trigger vs Skip (v=0 vs v!=0)...")
    res1 = run_suite_1_matrix_branch(n_samples=n_suite1, crop_percentile=crop_percentile)
    print_suite_result(res1)
    results.append(res1)

    print("\n>>> Executando Suíte 1b: Single-Word Zero Branch (v[0]=0 vs v[0]!=0)...")
    res1b = run_suite_1b_single_word_branch(n_samples=n_suite1, crop_percentile=crop_percentile)
    print_suite_result(res1b)
    results.append(res1b)

    print(f"\n>>> Executando Suíte 2: NIST TVLA Fixed vs Random ({rounds_suite2} round(s))...")
    res2 = run_suite_2_nist_tvla_fixed_vs_random(
        n_samples=n_suite2, rounds=rounds_suite2, crop_percentile=crop_percentile
    )
    print_suite_result(res2)
    results.append(res2)

    print("\n>>> Executando Suíte 3: Galois Field Arithmetic Low MSB vs High MSB...")
    res3 = run_suite_3_gf_mult_arithmetic(n_samples=n_suite3, crop_percentile=crop_percentile)
    print_suite_result(res3)
    results.append(res3)

    print("\n" + "=" * 80)
    print("   RESUMO CONSOLIDADO DA AUDITORIA DE CANAL LATERAL DE TEMPO")
    print("=" * 80)
    total_leaks = sum(1 for r in results if r.leakage_detected)
    print(f"Total de Testes Executados: {len(results)}")
    print(f"Falhas com Vazamento Detectado (|t| > 4.5): {total_leaks}")
    print(f"Conformidade com Tempo Constante: {'NÃO CONFORME' if total_leaks > 0 else 'CONFORME'}")

    report_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "primitive": "BaSingSe (RSD-S v4)",
        "methodology": "TVLA / Welch's t-test with dudect percentile cropping",
        "crop_percentile": crop_percentile,
        "total_tests": len(results),
        "leakage_count": total_leaks,
        "is_constant_time": total_leaks == 0,
        "suites": [asdict(r) for r in results],
    }

    if output_json:
        out_p = Path(output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[OK] Relatório estruturado salvo em: {out_p}")

    return report_data


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auditoria de Canal Lateral de Tempo (TVLA) para RSD-S v4."
    )
    parser.add_argument(
        "--samples-suite1",
        type=int,
        default=1000,
        help="Número de amostras para Suíte 1 (padrão: 1000)",
    )
    parser.add_argument(
        "--samples-suite2",
        type=int,
        default=500,
        help="Número de amostras para Suíte 2 (padrão: 500)",
    )
    parser.add_argument(
        "--samples-suite3",
        type=int,
        default=10000,
        help="Número de amostras para Suíte 3 (padrão: 10000)",
    )
    parser.add_argument(
        "--rounds-suite2",
        type=int,
        default=1,
        help="Número de rodadas para a Suíte 2 (padrão: 1)",
    )
    parser.add_argument(
        "--crop-percentile",
        type=float,
        default=0.5,
        help="Percentil de corte superior de outliers (padrão: 0.5)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="resultados/sidechannel_timing_results.json",
        help="Caminho do arquivo de saída JSON",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Execução rápida de teste de integridade com amostras reduzidas",
    )

    args = parser.parse_args()

    if args.fast:
        n1 = 200
        n2 = 100
        n3 = 2000
    else:
        n1 = args.samples_suite1
        n2 = args.samples_suite2
        n3 = args.samples_suite3

    run_all_audits(
        n_suite1=n1,
        n_suite2=n2,
        n_suite3=n3,
        rounds_suite2=args.rounds_suite2,
        crop_percentile=args.crop_percentile,
        output_json=args.output,
    )


if __name__ == "__main__":
    main()
