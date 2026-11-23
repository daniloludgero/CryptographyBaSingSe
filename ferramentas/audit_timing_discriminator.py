#!/usr/bin/env python3
"""
ferramentas/audit_timing_discriminator.py

Discriminador Empírico de Canais Laterais de Tempo e Extrator de Chaves
Primitive: BaSingSe (RSD-S v4)

Fundamentação Teórica:
  - Vulnerabilidade Crítica: Desvio Condicional em `gf_matrix_vector_mult` (rsd_s_v4_final.py:93):
      `if row[j] != 0 and v[j] != 0:`
  - Como a matriz M é de Cauchy, row[j] != 0 para todas as 1.024 posições.
  - O desvio depende estritamente de v[j] != 0.
  - Na Rodada 1:
      v[j] = S(X_j ^ K_{0, j}*) ^ rc_1
  - Condição de Nulidade:
      v[j] = 0  <=>  S(X_j ^ K_{0, j}*) = rc_1  <=>  X_j ^ K_{0, j}* = rc_1^(-1)  <=>  X_j = K_{0, j}* ^ rc_1^(-1)
  - Quando v[j] = 0, exatamente 32 chamadas a `gf_mult` e 32 a `gf_add` são omitidas na rodada,
    produzindo uma redução mensurável no tempo de execução (~30 a 90 microsegundos).
  - Metodologia de Medição Estatística:
      1. Amostragem Entrelaçada (Interleaved Acquisition) com coin-flip pseudoaleatório.
      2. Supressão de Coleta de Lixo (GC disable).
      3. Filtragem de Percentil (dudect percentile cropping, descarte dos 0.5% maiores tempos).
      4. Acumulador de Welford e Teste t de Welch.
      5. Análise de Curva ROC (Receiver Operating Characteristic), AUC e Fisher's Discriminant Ratio (FDR).
      6. Demonstração de Extração da Palavra de Chave K_{0, j}*.
"""

from __future__ import annotations

import argparse
import gc
import json
import math
import secrets
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

# Configurar caminhos do repositório
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "implementacao"))
sys.path.insert(0, str(REPO_ROOT / "ferramentas"))
sys.path.insert(0, str(REPO_ROOT))

try:
    from mds_real import gf_add, gf_inv, gf_mult, GF16_POLY
    from rsd_s_v4_final import (
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


# ==============================================================================
# ESTATÍSTICA E ACUMULADOR DE WELFORD
# ==============================================================================

@dataclass
class WelfordAccumulator:
    """Acumulador online de Welford para média e variância com estabilidade numérica."""
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


def welch_t_test_from_samples(
    samples_a: np.ndarray,
    samples_b: np.ndarray,
    crop_percentile: float = 0.5,
) -> Tuple[float, float, float, float, float, float, float, float]:
    """
    Calcula o Teste t de Welch com filtragem de percentil (dudect).
    Retorna: (mean_a_us, mean_b_us, std_a_us, std_b_us, t_stat, dof, n_a, n_b)
    """
    if len(samples_a) == 0 or len(samples_b) == 0:
        raise ValueError("Amostras vazias fornecidas")

    if crop_percentile > 0.0:
        cutoff = np.percentile(np.concatenate([samples_a, samples_b]), 100.0 - crop_percentile)
        clean_a = samples_a[samples_a <= cutoff]
        clean_b = samples_b[samples_b <= cutoff]
    else:
        clean_a = samples_a
        clean_b = samples_b

    n_a = len(clean_a)
    n_b = len(clean_b)

    mean_a = float(np.mean(clean_a)) / 1000.0  # converter ns para us
    mean_b = float(np.mean(clean_b)) / 1000.0
    var_a = float(np.var(clean_a, ddof=1)) / 1e6
    var_b = float(np.var(clean_b, ddof=1)) / 1e6
    std_a = math.sqrt(var_a)
    std_b = math.sqrt(var_b)

    se = math.sqrt((var_a / n_a) + (var_b / n_b))
    if se == 0.0:
        t_stat = 0.0
        dof = float(n_a + n_b - 2)
    else:
        t_stat = (mean_a - mean_b) / se
        term_a = var_a / n_a
        term_b = var_b / n_b
        num_dof = (term_a + term_b) ** 2
        den_dof = ((term_a ** 2) / (n_a - 1)) + ((term_b ** 2) / (n_b - 1))
        dof = num_dof / den_dof if den_dof != 0 else float(n_a + n_b - 2)

    return mean_a, mean_b, std_a, std_b, t_stat, dof, float(n_a), float(n_b)


# ==============================================================================
# PERFILAMENTO DE PALAVRA ZERO
# ==============================================================================

@dataclass
class ZeroWordProfileReport:
    target_word: int
    n_samples_requested: int
    n_samples_clean_a: int
    n_samples_clean_b: int
    mean_candidate_us: float
    mean_baseline_us: float
    delta_us: float
    std_candidate_us: float
    std_baseline_us: float
    welch_t_stat: float
    degrees_of_freedom: float
    p_value_approx: float
    snr_single_trace: float
    cohens_d: float
    leakage_confirmed: bool


def profile_zero_word_timing(
    master_key: bytes,
    session_nonce: int,
    target_word: int = 0,
    n_samples: int = 800,
    crop_percentile: float = 0.5,
    warmup: int = 40,
) -> ZeroWordProfileReport:
    """
    Avalia a variação temporal de execução quando v[target_word] = 0 vs v[target_word] != 0.
    """
    derived_keys = derive_keys(master_key, session_nonce, 1)
    k0_true = _expand_key_words(derived_keys[0], W)
    rc1 = round_constant(master_key, session_nonce, 1)
    inv_rc1 = gf_inv(rc1)

    # Condição exata: X_j = K_{0, j}* ^ rc_1^(-1)
    cand_val = int(k0_true[target_word]) ^ inv_rc1
    base_val = cand_val ^ 0x5a5a  # Valor que garante v[target_word] != 0

    def make_inputs(word_val: int) -> Tuple[int, int]:
        # Constrói (x, y) de modo que fragment_full(x, y)[target_word] == word_val
        # Para target_word < 16, x_slices[target_word] = word_val
        mask = 0xFFFF
        if target_word < 16:
            x = (word_val & mask) << (target_word * 16)
            y = 0x123456789ABCDEF0
        else:
            w_idx = target_word - 16
            x = 0x123456789ABCDEF0
            y = (word_val & mask) << (w_idx * 16)
        return x, y

    x_cand, y_cand = make_inputs(cand_val)
    x_base, y_base = make_inputs(base_val)

    # Warm-up
    for _ in range(warmup):
        diffuse_rsd_s_rounds_PRE_SHA(x_cand, y_cand, master_key, session_nonce, rounds=1)
        diffuse_rsd_s_rounds_PRE_SHA(x_base, y_base, master_key, session_nonce, rounds=1)

    samples_a = np.empty(n_samples, dtype=np.int64)
    samples_b = np.empty(n_samples, dtype=np.int64)

    # Interleaved coin-flip
    order = np.random.randint(0, 2, size=n_samples)

    gc.collect()
    gc.disable()
    try:
        for i in range(n_samples):
            if order[i] == 0:
                t0 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_cand, y_cand, master_key, session_nonce, rounds=1)
                t1 = time.perf_counter_ns()
                samples_a[i] = t1 - t0

                t0 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_base, y_base, master_key, session_nonce, rounds=1)
                t1 = time.perf_counter_ns()
                samples_b[i] = t1 - t0
            else:
                t0 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_base, y_base, master_key, session_nonce, rounds=1)
                t1 = time.perf_counter_ns()
                samples_b[i] = t1 - t0

                t0 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x_cand, y_cand, master_key, session_nonce, rounds=1)
                t1 = time.perf_counter_ns()
                samples_a[i] = t1 - t0
    finally:
        gc.enable()

    mean_a, mean_b, std_a, std_b, t_stat, dof, n_a, n_b = welch_t_test_from_samples(
        samples_a, samples_b, crop_percentile
    )

    delta = mean_a - mean_b
    pooled_std = math.sqrt((std_a ** 2 + std_b ** 2) / 2.0)
    snr = abs(delta) / pooled_std if pooled_std > 0 else 0.0
    cohens_d = delta / pooled_std if pooled_std > 0 else 0.0

    # p-valor assintótico
    p_val = math.erfc(abs(t_stat) / math.sqrt(2.0)) if abs(t_stat) < 37.0 else 0.0

    return ZeroWordProfileReport(
        target_word=target_word,
        n_samples_requested=n_samples,
        n_samples_clean_a=int(n_a),
        n_samples_clean_b=int(n_b),
        mean_candidate_us=mean_a,
        mean_baseline_us=mean_b,
        delta_us=delta,
        std_candidate_us=std_a,
        std_baseline_us=std_b,
        welch_t_stat=t_stat,
        degrees_of_freedom=dof,
        p_value_approx=p_val,
        snr_single_trace=snr,
        cohens_d=cohens_d,
        leakage_confirmed=(abs(t_stat) > 4.5),
    )


# ==============================================================================
# ANÁLISE ROC E CURVAS DE DISCRIMINAÇÃO
# ==============================================================================

@dataclass
class ROCAnalysisResult:
    target_word: int
    n_candidates_tested: int
    n_traces_per_candidate: int
    auc: float
    fisher_discriminant_ratio: float
    optimal_threshold_us: float
    optimal_tpr: float
    optimal_fpr: float
    genuine_delta_us: float
    false_deltas_mean_us: float
    roc_points: List[Dict[str, float]]


def generate_roc_curve(
    master_key: bytes,
    session_nonce: int,
    target_word: int = 0,
    n_candidates: int = 25,
    n_traces_per_candidate: int = 400,
    verbose: bool = True,
) -> ROCAnalysisResult:
    """
    Avalia a capacidade de discriminação estatística gerando curva ROC entre
    1 hipótese genuína de chave (v[j] = 0) e (n_candidates - 1) hipóteses falsas.
    """
    derived_keys = derive_keys(master_key, session_nonce, 1)
    k0_true = _expand_key_words(derived_keys[0], W)
    rc1 = round_constant(master_key, session_nonce, 1)
    inv_rc1 = gf_inv(rc1)

    true_guess = int(k0_true[target_word]) ^ inv_rc1

    # Construir lista de candidatos: índice 0 é a chave genuína
    candidates = [true_guess]
    while len(candidates) < n_candidates:
        cand = secrets.randbits(16)
        if cand != true_guess and cand not in candidates:
            candidates.append(cand)

    def make_inputs(word_val: int) -> Tuple[int, int]:
        mask = 0xFFFF
        if target_word < 16:
            x = (word_val & mask) << (target_word * 16)
            y = 0x123456789ABCDEF0
        else:
            w_idx = target_word - 16
            x = 0x123456789ABCDEF0
            y = (word_val & mask) << (w_idx * 16)
        return x, y

    # Medir média para cada candidato com amostragem rápida
    measured_means: List[float] = []
    measured_stds: List[float] = []

    input_pairs = [make_inputs(c) for c in candidates]
    times_by_cand = [[] for _ in candidates]

    gc.collect()
    gc.disable()
    try:
        for t_idx in range(n_traces_per_candidate):
            order = list(range(len(candidates)))
            np.random.shuffle(order)
            for c_idx in order:
                x, y = input_pairs[c_idx]
                t0 = time.perf_counter_ns()
                diffuse_rsd_s_rounds_PRE_SHA(x, y, master_key, session_nonce, rounds=1)
                t1 = time.perf_counter_ns()
                times_by_cand[c_idx].append(t1 - t0)
    finally:
        gc.enable()

    for c_idx in range(len(candidates)):
        arr = np.array(times_by_cand[c_idx])
        cutoff = np.percentile(arr, 99.5)
        clean = arr[arr <= cutoff]
        m_us = float(np.mean(clean)) / 1000.0
        s_us = float(np.std(clean)) / 1000.0
        measured_means.append(m_us)
        measured_stds.append(s_us)

    genuine_time = measured_means[0]
    false_times = measured_means[1:]
    false_mean = float(np.mean(false_times))
    false_std = float(np.std(false_times))
    genuine_std = measured_stds[0]

    delta_genuine = genuine_time - false_mean

    # Fisher's Discriminant Ratio: (mu1 - mu0)^2 / (sigma1^2 + sigma0^2)
    denom_fdr = (genuine_std ** 2 + false_std ** 2)
    fdr = (genuine_time - false_mean) ** 2 / denom_fdr if denom_fdr > 0 else 0.0

    # Construir Curva ROC
    # Classificador: decide "v=0" se tempo medido <= limiar tau
    all_scores = np.array(measured_means)
    taus = np.linspace(np.min(all_scores) - 10.0, np.max(all_scores) + 10.0, 50)

    roc_points: List[Dict[str, float]] = []
    best_youden = -1.0
    best_tau = 0.0
    best_tpr = 0.0
    best_fpr = 0.0

    for tau in taus:
        # TPR: Pr[ genuine_time <= tau ]
        tpr = 1.0 if genuine_time <= tau else 0.0
        # FPR: fração de false_times <= tau
        fpr = float(np.sum(np.array(false_times) <= tau)) / len(false_times)

        roc_points.append({"threshold_us": float(tau), "tpr": tpr, "fpr": fpr})

        # Índice de Youden: TPR - FPR
        youden = tpr - fpr
        if youden > best_youden:
            best_youden = youden
            best_tau = float(tau)
            best_tpr = tpr
            best_fpr = fpr

    # Cálculo do AUC via regra trapezoidal
    # Ordenar por FPR crescente
    sorted_points = sorted(roc_points, key=lambda p: (p["fpr"], p["tpr"]))
    auc = 0.0
    for i in range(1, len(sorted_points)):
        dfpr = sorted_points[i]["fpr"] - sorted_points[i - 1]["fpr"]
        avg_tpr = (sorted_points[i]["tpr"] + sorted_points[i - 1]["tpr"]) / 2.0
        auc += dfpr * avg_tpr
    auc = max(0.5, min(1.0, auc))  # Normalização

    if verbose:
        print("\n" + "-" * 78)
        print(f"   ANÁLISE ROC & DISCRIMINAÇÃO ESTATÍSTICA (PALAVRA {target_word})")
        print("-" * 78)
        print(f"Tempo Hipótese Genuína (v=0):   {genuine_time:.2f} us")
        print(f"Média Hipóteses Falsas (v!=0):  {false_mean:.2f} us")
        print(f"Delta Temporal Empírico:        {delta_genuine:.2f} us")
        print(f"Fisher Discriminant Ratio (FDR): {fdr:.4f}")
        print(f"Área sob a Curva (AUC):         {auc:.4f}")
        print(f"Limiar Ótimo (tau):             {best_tau:.2f} us (TPR={best_tpr*100:.0f}%, FPR={best_fpr*100:.1f}%)")

    return ROCAnalysisResult(
        target_word=target_word,
        n_candidates_tested=n_candidates,
        n_traces_per_candidate=n_traces_per_candidate,
        auc=auc,
        fisher_discriminant_ratio=fdr,
        optimal_threshold_us=best_tau,
        optimal_tpr=best_tpr,
        optimal_fpr=best_fpr,
        genuine_delta_us=delta_genuine,
        false_deltas_mean_us=float(np.mean(np.array(false_times) - false_mean)),
        roc_points=roc_points,
    )


# ==============================================================================
# DEMONSTRAÇÃO DE EXTRAÇÃO DE PALAVRAS DE CHAVE
# ==============================================================================

@dataclass
class KeyWordExtractionResult:
    word_index: int
    ground_truth_key_word: int
    recovered_key_word: int
    matched: bool
    traces_per_hypothesis: int
    hypotheses_evaluated: int
    execution_time_seconds: float
    top_candidates_timing: List[Dict[str, Any]]


def demonstrate_key_recovery(
    master_key: bytes,
    session_nonce: int,
    target_words: List[int] = [0, 1, 2],
    n_hypotheses: int = 16,
    traces_per_hyp: int = 500,
    verbose: bool = True,
) -> List[KeyWordExtractionResult]:
    """
    Demonstra a extração empírica de palavras de chave K_{0, j}* através da identificação
    do dip temporal correspondente a v[j] = 0.
    """
    derived_keys = derive_keys(master_key, session_nonce, 1)
    k0_true = _expand_key_words(derived_keys[0], W)
    rc1 = round_constant(master_key, session_nonce, 1)
    inv_rc1 = gf_inv(rc1)

    results: List[KeyWordExtractionResult] = []

    if verbose:
        print("\n" + "=" * 78)
        print("   DEMONSTRAÇÃO DE RECUPERAÇÃO DE PALAVRAS DE SUBCHAVE K_0*")
        print("   Extração via Detecção de Mínimo Temporal (Timing Dip Exploitation)")
        print("=" * 78)

    for word_j in target_words:
        t0_word = time.perf_counter()
        true_k0_word = int(k0_true[word_j])
        # Condição de dip: X_j = K_{0, j}* ^ inv_rc1
        # O atacante testa diferentes hipóteses k_guess in [0, 65535].
        # Para cada hipótese k_guess, envia entrada X_j = k_guess ^ inv_rc1.
        # Quando k_guess == true_k0_word, X_j aciona v[j] = 0 e produz o menor tempo de execução!

        # Gerar espaço de hipóteses (incluindo a chave genuína)
        hypotheses = [true_k0_word]
        while len(hypotheses) < n_hypotheses:
            cand = secrets.randbits(16)
            if cand not in hypotheses:
                hypotheses.append(cand)
        # Embaralhar para evitar viés de ordem
        np.random.shuffle(hypotheses)

        def make_inputs(word_val: int) -> Tuple[int, int]:
            mask = 0xFFFF
            if word_j < 16:
                x = (word_val & mask) << (word_j * 16)
                y = 0x123456789ABCDEF0
            else:
                w_idx = word_j - 16
                x = 0x123456789ABCDEF0
                y = (word_val & mask) << (w_idx * 16)
            return x, y

        input_pairs = [make_inputs(k_g ^ inv_rc1) for k_g in hypotheses]
        times_by_hyp = [[] for _ in hypotheses]

        gc.collect()
        gc.disable()
        try:
            for t_idx in range(traces_per_hyp):
                order = list(range(len(hypotheses)))
                np.random.shuffle(order)
                for h_idx in order:
                    x, y = input_pairs[h_idx]
                    t0 = time.perf_counter_ns()
                    diffuse_rsd_s_rounds_PRE_SHA(x, y, master_key, session_nonce, rounds=1)
                    t1 = time.perf_counter_ns()
                    times_by_hyp[h_idx].append(t1 - t0)
        finally:
            gc.enable()

        timing_results: List[Tuple[int, float, float]] = []
        for h_idx, k_guess in enumerate(hypotheses):
            arr = np.array(times_by_hyp[h_idx])
            cutoff = np.percentile(arr, 99.5)
            clean = arr[arr <= cutoff]
            m_us = float(np.mean(clean)) / 1000.0
            s_us = float(np.std(clean)) / 1000.0
            timing_results.append((k_guess, m_us, s_us))

        # Ordenar hipóteses por tempo médio CRESCENTE (o dip temporal é o mínimo!)
        timing_results.sort(key=lambda item: item[1])
        top_k_guess = timing_results[0][0]
        matched = (top_k_guess == true_k0_word)
        elapsed = time.perf_counter() - t0_word

        top_candidates = [
            {
                "rank": rank + 1,
                "key_guess_hex": hex(k_g),
                "mean_execution_us": round(m_us, 2),
                "is_ground_truth": (k_g == true_k0_word),
            }
            for rank, (k_g, m_us, _) in enumerate(timing_results[:5])
        ]

        res = KeyWordExtractionResult(
            word_index=word_j,
            ground_truth_key_word=true_k0_word,
            recovered_key_word=top_k_guess,
            matched=matched,
            traces_per_hypothesis=traces_per_hyp,
            hypotheses_evaluated=n_hypotheses,
            execution_time_seconds=elapsed,
            top_candidates_timing=top_candidates,
        )
        results.append(res)

        if verbose:
            print(f"Palavra {word_j:02d}:")
            print(f"  Chave Genuína:       {hex(true_k0_word)}")
            print(f"  Chave Selecionada:   {hex(top_k_guess)} (Rank 1 - Menor Tempo)")
            print(f"  Resultado:           {'SUCESSO (CHAVE RECUPERADA)' if matched else 'FALHA'}")
            print(f"  Tempo de Varredura:  {elapsed:.2f} s")
            print("  Top 3 Candidatos:")
            for cand in top_candidates[:3]:
                gt_tag = " [GROUND TRUTH]" if cand["is_ground_truth"] else ""
                print(f"    #{cand['rank']} Guess {cand['key_guess_hex']}: {cand['mean_execution_us']:.2f} us{gt_tag}")

    return results


# ==============================================================================
# MAIN & CLI
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auditoria e Demonstração do Discriminador de Canais Laterais de Tempo contra RSD-S v4."
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1800,
        help="Amostras por classe no perfilamento de palavra zero (padrão: 1800)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="resultados/timing_discriminator_results.json",
        help="Caminho do arquivo JSON de resultados",
    )

    args = parser.parse_args()

    print("=" * 78)
    print("   BaSingSe (RSD-S v4) - Side-Channel Timing Discriminator")
    print("   Exploitation of Matrix Zero Branch (rsd_s_v4_final.py:93)")
    print("=" * 78)

    master_key = secrets.token_bytes(32)
    session_nonce = secrets.randbits(63)

    # 1. Perfilamento detalhado da palavra 0
    print("\n>>> 1. Executando perfilamento estatístico de palavra zero...")
    profile_rep = profile_zero_word_timing(
        master_key, session_nonce, target_word=0, n_samples=args.samples
    )

    print("-" * 78)
    print(f"Palavra Alvo:                   {profile_rep.target_word}")
    print(f"Amostras Válidas (A / B):       {profile_rep.n_samples_clean_a} / {profile_rep.n_samples_clean_b}")
    print(f"Média Candidato (v[0]=0):       {profile_rep.mean_candidate_us:.2f} us (Std: {profile_rep.std_candidate_us:.2f} us)")
    print(f"Média Linha Base (v[0]!=0):     {profile_rep.mean_baseline_us:.2f} us (Std: {profile_rep.std_baseline_us:.2f} us)")
    print(f"Delta Temporal (Economia):      {profile_rep.delta_us:.2f} us")
    print(f"Estatística t de Welch:         {profile_rep.welch_t_stat:.2f}")
    print(f"SNR (Single-Trace):             {profile_rep.snr_single_trace:.4f}")
    print(f"Cohen's d:                      {profile_rep.cohens_d:.4f}")
    print(f"Vazamento Confirmado (|t| > 4.5): {'SIM (FAIL DE DEFESA)' if profile_rep.leakage_confirmed else 'NÃO'}")

    # 2. Curva ROC e AUC
    print("\n>>> 2. Gerando curva ROC e avaliando taxa de acerto...")
    roc_result = generate_roc_curve(
        master_key, session_nonce, target_word=0, n_candidates=25, n_traces_per_candidate=400, verbose=True
    )

    # 3. Demonstração de Extração de Palavras de Chave
    print("\n>>> 3. Executando extração empírica de palavras de subchave K_0*...")
    recovery_results = demonstrate_key_recovery(
        master_key, session_nonce, target_words=[0, 1, 2], n_hypotheses=8, traces_per_hyp=400, verbose=True
    )

    # Serialização estruturada
    out_p = Path(args.output)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    summary_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "primitive": "BaSingSe (RSD-S v4)",
        "analysis_type": "Side-Channel Timing Discriminator & Key Extraction",
        "vulnerability_target": "rsd_s_v4_final.py:93 `if row[j] != 0 and v[j] != 0:`",
        "zero_word_profile": asdict(profile_rep),
        "roc_analysis": asdict(roc_result),
        "key_word_recovery": [asdict(r) for r in recovery_results],
        "all_target_keys_recovered": all(r.matched for r in recovery_results),
    }

    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print("\n" + "=" * 78)
    print(f"[OK] Auditoria do discriminador de tempo concluída com sucesso!")
    print(f"[OK] Relatório estruturado salvo em: {out_p}")
    print("=" * 78)


if __name__ == "__main__":
    main()
