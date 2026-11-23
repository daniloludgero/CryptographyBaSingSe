#!/usr/bin/env python3
"""
ferramentas/audit_dfa_simulation.py

Simulação e Verificação Criptanalítica de Ataque por Injeção de Falhas Diferenciais (DFA)
Primitive: BaSingSe (RSD-S v4)

Fundamentação Teórica:
  - Modelo Piret-Quisquater / Biham-Shamir adaptado para SPN sobre GF(2^16).
  - Injeção de falhas de palavra única (ou bit único) na entrada da Rodada 4: S^(3).
  - Estado intermediário após S-box:
      V^(4)_i = S(S^(3)_i) ^ rc_4
  - Propagação linear através da matriz Cauchy MDS 32x32:
      W^(4) = M * V^(4)
  - Adição da chave expandida de rodada:
      Z = W^(4) ^ K_4*
  - Com a injeção da falha delta em uma palavra k:
      S_tilde^(3)_k = S^(3)_k ^ delta
      V_tilde^(4)_k = S(S^(3)_k ^ delta) ^ rc_4
      Delta V^(4)_k = S(S^(3)_k ^ delta) ^ S(S^(3)_k),  Delta V^(4)_i = 0 (i != k)
  - Cancelamento da constante de rodada e da chave de rodada:
      Delta Z = Z_tilde ^ Z = M * Delta V^(4)
  - Inversão Linear via M^(-1):
      D = M^(-1) * Delta Z = Delta V^(4)
      D tem exatamente 1 palavra não-nula no índice k: D_k = Delta V^(4)_k.
  - Resolução Algébrica do S-box (Inversão em GF(2^16)):
      (X ^ delta)^(-1) ^ X^(-1) = D_k  =>  X^2 ^ delta*X ^ delta*D_k^(-1) = 0
      Essa equação quadrática possui no máximo 2 raízes em GF(2^16): {X_0, X_0 ^ delta}.
  - Uma segunda falha delta_2 != delta reduz o conjunto para a raiz única:
      {X_0, X_0 ^ delta} ∩ {X_0, X_0 ^ delta_2} = {X_0}.
  - Com todas as 32 palavras de S^(3) recuperadas (<= 64 falhas):
      W^(4) = M * (S(S^(3)) ^ rc_4)
      K_4* = W^(4) ^ Z  (Chave completa de 512 bits recuperada com 100% de exatidão).
  - Demonstração do Mascaramento pós-SHA-256:
      Delta C = SHA-256(Z_tilde) ^ SHA-256(Z) exibe ~50% de avalanche (~128 bits alterados),
      impedindo a inversão linear direta na saída pública.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import numpy as np

# Configurar path do repositório
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "implementacao"))
sys.path.insert(0, str(REPO_ROOT))

try:
    from mds_real import build_cauchy_mds, gf_inv, gf_mult, gf_add, GF16_POLY
    from rsd_s_v4_final import (
        diffuse_rsd_s_final,
        diffuse_rsd_s_rounds,
        diffuse_rsd_s_rounds_PRE_SHA,
        get_base_inversion_sbox,
        gf_matrix_vector_mult,
        derive_keys,
        round_constant,
        _expand_key_words,
        _hash_state,
        M_CAUCHY_32,
        W,
        B,
        P_CURVE25519,
    )
except ImportError as err:
    sys.stderr.write(f"Erro ao importar primitivas: {err}\n")
    sys.exit(1)


# Cache global para inverso da matriz Cauchy 32x32
_CAUCHY_INV_CACHE: np.ndarray | None = None


def invert_cauchy_matrix(mat: np.ndarray, n: int = W) -> np.ndarray:
    """
    Inverte a matriz de Cauchy sobre GF(2^16) via Eliminação Gauss-Jordan.
    Como a matriz é MDS (Cauchy), ela é garantidamente invertível por construção.
    """
    global _CAUCHY_INV_CACHE
    if _CAUCHY_INV_CACHE is not None and _CAUCHY_INV_CACHE.shape == (n, n):
        return _CAUCHY_INV_CACHE

    A = mat.copy().astype(np.uint32)
    inv = np.eye(n, dtype=np.uint32)

    for col in range(n):
        # Localizar pivô não-nulo
        pivot_row = None
        for r in range(col, n):
            if A[r, col] != 0:
                pivot_row = r
                break
        if pivot_row is None:
            raise ValueError(f"Matriz singular na coluna {col} sobre GF(2^16)")

        if pivot_row != col:
            A[[col, pivot_row]] = A[[pivot_row, col]]
            inv[[col, pivot_row]] = inv[[pivot_row, col]]

        pivot_val = int(A[col, col])
        pivot_inv = gf_inv(pivot_val)

        # Normalizar linha pivô
        for c in range(n):
            A[col, c] = gf_mult(int(A[col, c]), pivot_inv)
            inv[col, c] = gf_mult(int(inv[col, c]), pivot_inv)

        # Eliminar demais linhas
        for r in range(n):
            if r != col and A[r, col] != 0:
                factor = int(A[r, col])
                for c in range(n):
                    A[r, c] ^= gf_mult(factor, int(A[col, c]))
                    inv[r, c] ^= gf_mult(factor, int(inv[col, c]))

    _CAUCHY_INV_CACHE = inv
    return inv


def solve_sbox_differential(
    delta: int, D_k: int, sbox: np.ndarray
) -> Set[int]:
    """
    Resolve a equação diferencial do S-box de inversão:
      S(X ^ delta) ^ S(X) = D_k

    Retorna o conjunto de candidatos X in [0, 65535].
    Pelo Teorema de Multiplicidade Algébrica, |candidatos| <= 2.
    """
    if delta == 0 or D_k == 0:
        return set()

    # Como sbox tem tamanho 65536, vetorização numpy é extremamente veloz (< 1 ms)
    all_x = np.arange(65536, dtype=np.uint32)
    diff = sbox[all_x ^ delta] ^ sbox
    matches = np.where(diff == D_k)[0]
    return set(int(m) for m in matches)


def hamming_weight_bytes(data: bytes) -> int:
    """Calcula o peso de Hamming (número de bits 1) de um buffer de bytes."""
    return sum(bin(b).count("1") for b in data)


@dataclass
class WordRecoveryRecord:
    word_index: int
    fault1_delta: int
    fault1_output_diff: int
    candidates_fault1: List[int]
    fault2_delta: int
    fault2_output_diff: int
    candidates_fault2: List[int]
    recovered_value: int
    ground_truth_value: int
    match: bool


@dataclass
class DFASimulationReport:
    timestamp: str
    target_round: int
    total_words: int
    total_faults_injected: int
    faults_per_word: int
    state_s3_recovered: bool
    round_key_k4_recovered: bool
    key_match_hex: bool
    recovered_k4_hex: str
    ground_truth_k4_hex: str
    post_sha_masking_active: bool
    post_sha_avg_avalanche_pct: float
    post_sha_avg_bit_flips: float
    word_records: List[WordRecoveryRecord]


def run_dfa_round4_attack(
    master_key: bytes | None = None,
    session_nonce: int | None = None,
    x_input: int | None = None,
    y_input: int | None = None,
    verbose: bool = True,
) -> DFASimulationReport:
    """
    Executa a simulação completa do ataque DFA contra a Rodada 4 do RSD-S v4.
    """
    sbox = get_base_inversion_sbox()
    M_inv = invert_cauchy_matrix(M_CAUCHY_32, W)

    if master_key is None:
        master_key = secrets.token_bytes(32)
    if session_nonce is None:
        session_nonce = secrets.randbits(63)
    p = P_CURVE25519
    if x_input is None:
        x_input = secrets.randbits(250) % p
    if y_input is None:
        y_input = secrets.randbits(250) % p

    # 1. Obter estado nominal genuíno (sem falhas)
    # Entrada da rodada 4: S^(3) (saída de 3 rodadas)
    s3_ground_truth = diffuse_rsd_s_rounds_PRE_SHA(x_input, y_input, master_key, session_nonce, rounds=3)
    # Saída nominal pré-SHA: Z (saída de 4 rodadas)
    Z_nominal = diffuse_rsd_s_rounds_PRE_SHA(x_input, y_input, master_key, session_nonce, rounds=4)
    # Saída nominal pós-SHA
    C_nominal = diffuse_rsd_s_rounds(x_input, y_input, master_key, session_nonce, rounds=4)

    # Obter parâmetros de rodada do oráculo (para verificação formal posterior)
    derived_keys = derive_keys(master_key, session_nonce, 4)
    k4_ground_truth = _expand_key_words(derived_keys[4], W)
    rc4 = round_constant(master_key, session_nonce, 4)

    if verbose:
        print("\n" + "=" * 78)
        print("   INICIANDO SIMULAÇÃO DE DIFFERENTIAL FAULT ANALYSIS (DFA) - RODADA 4")
        print("=" * 78)
        print(f"Master Secret Key (hex): {master_key.hex()[:32]}...")
        print(f"Session Nonce:          {hex(session_nonce)}")
        print(f"Pre-SHA Nominal State Z: {Z_nominal[:4]} ... ({len(Z_nominal)} words)")

    recovered_s3 = np.zeros(W, dtype=np.uint32)
    word_records: List[WordRecoveryRecord] = []
    faults_count = 0

    sha_avalanche_flips: List[int] = []

    # 2. Injeção de Falhas palavra por palavra (k = 0 ... 31)
    for word_k in range(W):
        # Falha 1: flip no bit 0 (delta1 = 0x0001)
        delta1 = 0x0001
        faults_count += 1
        s3_fault1 = s3_ground_truth.copy()
        s3_fault1[word_k] = int(s3_fault1[word_k]) ^ delta1

        # Propagação pela rodada 4 no dispositivo sob falha
        v_f1 = sbox[s3_fault1] ^ np.uint32(rc4)
        w_f1 = gf_matrix_vector_mult(M_CAUCHY_32, v_f1, W).astype(np.uint64)
        Z_fault1 = w_f1 ^ k4_ground_truth
        C_fault1 = _hash_state(Z_fault1)

        # Rastrear mascaramento pós-SHA
        diff_sha1 = bytes(a ^ b for a, b in zip(C_nominal, C_fault1))
        sha_avalanche_flips.append(hamming_weight_bytes(diff_sha1))

        # Diferencial pré-SHA observado pelo atacante
        delta_Z1 = (Z_fault1 ^ Z_nominal).astype(np.uint32)

        # Inversão linear com M^(-1)
        D1 = gf_matrix_vector_mult(M_inv, delta_Z1, W)

        # Validação: D1 deve ter suporte unitário (apenas índice word_k != 0)
        active_indices1 = np.where(D1 != 0)[0]
        assert len(active_indices1) == 1 and active_indices1[0] == word_k, (
            f"Erro na inversão Cauchy: esperava índice único {word_k}, obteve {active_indices1}"
        )

        cands1 = solve_sbox_differential(delta1, int(D1[word_k]), sbox)
        assert len(cands1) == 2, f"Erro: esperava 2 candidatos, obteve {len(cands1)}"
        assert int(s3_ground_truth[word_k]) in cands1, "Raiz genuína ausente nos candidatos 1!"

        # Falha 2: flip no bit 1 (delta2 = 0x0002)
        delta2 = 0x0002
        faults_count += 1
        s3_fault2 = s3_ground_truth.copy()
        s3_fault2[word_k] = int(s3_fault2[word_k]) ^ delta2

        v_f2 = sbox[s3_fault2] ^ np.uint32(rc4)
        w_f2 = gf_matrix_vector_mult(M_CAUCHY_32, v_f2, W).astype(np.uint64)
        Z_fault2 = w_f2 ^ k4_ground_truth
        C_fault2 = _hash_state(Z_fault2)

        diff_sha2 = bytes(a ^ b for a, b in zip(C_nominal, C_fault2))
        sha_avalanche_flips.append(hamming_weight_bytes(diff_sha2))

        delta_Z2 = (Z_fault2 ^ Z_nominal).astype(np.uint32)
        D2 = gf_matrix_vector_mult(M_inv, delta_Z2, W)

        cands2 = solve_sbox_differential(delta2, int(D2[word_k]), sbox)
        assert len(cands2) == 2, f"Erro: esperava 2 candidatos, obteve {len(cands2)}"
        assert int(s3_ground_truth[word_k]) in cands2, "Raiz genuína ausente nos candidatos 2!"

        # Interseção unívoca
        intersection = cands1.intersection(cands2)
        assert len(intersection) == 1, (
            f"Falha na unicidade da interseção para palavra {word_k}: {intersection}"
        )
        recovered_val = intersection.pop()
        recovered_s3[word_k] = recovered_val

        record = WordRecoveryRecord(
            word_index=word_k,
            fault1_delta=delta1,
            fault1_output_diff=int(D1[word_k]),
            candidates_fault1=sorted(list(cands1)),
            fault2_delta=delta2,
            fault2_output_diff=int(D2[word_k]),
            candidates_fault2=sorted(list(cands2)),
            recovered_value=recovered_val,
            ground_truth_value=int(s3_ground_truth[word_k]),
            match=(recovered_val == int(s3_ground_truth[word_k])),
        )
        word_records.append(record)

    # 3. Verificação do estado completo S^(3)
    s3_all_matched = bool(np.array_equal(recovered_s3, s3_ground_truth))

    # 4. Reconstrução da Chave Expandida de Rodada K_4*
    # W^(4) = M * (S(S^(3)) ^ rc4)
    v_reconstructed = sbox[recovered_s3] ^ np.uint32(rc4)
    w_reconstructed = gf_matrix_vector_mult(M_CAUCHY_32, v_reconstructed, W).astype(np.uint64)
    # Como Z = W^(4) ^ K_4* => K_4* = W^(4) ^ Z
    recovered_k4 = w_reconstructed ^ Z_nominal

    k4_all_matched = bool(np.array_equal(recovered_k4, k4_ground_truth))

    # Serialização em hex para comparação
    recovered_k4_bytes = b"".join(int(k).to_bytes(2, "little") for k in recovered_k4)
    ground_truth_k4_bytes = b"".join(int(k).to_bytes(2, "little") for k in k4_ground_truth)
    key_match_hex = (recovered_k4_bytes == ground_truth_k4_bytes)

    avg_flips = float(np.mean(sha_avalanche_flips))
    avg_avalanche_pct = (avg_flips / 256.0) * 100.0

    if verbose:
        print("\n" + "-" * 78)
        print("   RESULTADOS DA RECUPERAÇÃO ALGEBRÁICA DE ESTADO E CHAVE")
        print("-" * 78)
        print(f"Total de Palavras Auditadas:            {W}")
        print(f"Total de Falhas Injetadas:             {faults_count} (exatamente 2 por palavra)")
        print(f"Recuperação do Estado S^(3):             {'SUCESSO (100% EXATO)' if s3_all_matched else 'FALHA'}")
        print(f"Recuperação da Chave de Rodada K_4*:    {'SUCESSO (100% EXATO)' if k4_all_matched else 'FALHA'}")
        print(f"Chave K_4* Recuperada (hex):            {recovered_k4_bytes.hex()}")
        print(f"Chave K_4* Genuína    (hex):            {ground_truth_k4_bytes.hex()}")
        print(f"Chaves Idênticas:                       {key_match_hex}")
        print("-" * 78)
        print("   ANÁLISE DE MASCARAMENTO PÓS-SHA-256 (API OFICIAL)")
        print("-" * 78)
        print(f"Média de Bits Invertidos em SHA-256:   {avg_flips:.2f} / 256 bits ({avg_avalanche_pct:.2f}%)")
        print("Impacto Arquitetural: O hash SHA-256 terminal mascara completamente o diferencial")
        print("linear na saída pública, agindo como filtro não-invertível contra DFA ingênuo.")
        print("Contudo, em hardware/ASIC/Smartcard com leitura de registradores internos pré-SHA,")
        print("o DFA é 100% CATASTRÓFICO com <= 64 injeções de falha.")
        print("=" * 78)

    return DFASimulationReport(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        target_round=4,
        total_words=W,
        total_faults_injected=faults_count,
        faults_per_word=2,
        state_s3_recovered=s3_all_matched,
        round_key_k4_recovered=k4_all_matched,
        key_match_hex=key_match_hex,
        recovered_k4_hex=recovered_k4_bytes.hex(),
        ground_truth_k4_hex=ground_truth_k4_bytes.hex(),
        post_sha_masking_active=True,
        post_sha_avg_avalanche_pct=avg_avalanche_pct,
        post_sha_avg_bit_flips=avg_flips,
        word_records=word_records,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulação de Differential Fault Analysis (DFA) contra RSD-S v4."
    )
    parser.add_argument(
        "--tests",
        type=int,
        default=3,
        help="Número de testes independentes com chaves aleatórias distintas (padrão: 3)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="resultados/dfa_simulation_results.json",
        help="Caminho do arquivo de relatório JSON",
    )

    args = parser.parse_args()

    print("=" * 78)
    print("   BaSingSe (RSD-S v4) - Differential Fault Analysis (DFA) Audit")
    print("   Cauchy MDS Linear Inversion & S-Box Differential Solving")
    print("=" * 78)

    reports: List[DFASimulationReport] = []
    for test_idx in range(1, args.tests + 1):
        print(f"\n>>> Executando Teste DFA {test_idx}/{args.tests} com chave mestra aleatória...")
        rep = run_dfa_round4_attack(verbose=True)
        assert rep.state_s3_recovered and rep.round_key_k4_recovered, "Falha na recuperação!"
        reports.append(rep)

    out_p = Path(args.output)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    summary_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "primitive": "BaSingSe (RSD-S v4)",
        "analysis_type": "Differential Fault Analysis (DFA)",
        "target_round": 4,
        "required_faults_total": 64,
        "recovery_rate": 1.0,
        "all_tests_passed": all(r.round_key_k4_recovered for r in reports),
        "post_sha_avalanche_avg_pct": float(np.mean([r.post_sha_avg_avalanche_pct for r in reports])),
        "runs": [asdict(r) for r in reports],
    }

    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print(f"\n[OK] Simulação de DFA concluída com 100% de sucesso!")
    print(f"[OK] Relatório estruturado salvo em: {out_p}")


if __name__ == "__main__":
    main()
