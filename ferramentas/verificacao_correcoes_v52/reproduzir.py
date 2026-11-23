#!/usr/bin/env python3
"""Reproduz as correções da v5.2: o MESMO exploit escrito contra a v5.1 é executado contra
o código v5.1 (histórico) e contra o código v5.2 (atual).

Uso:  python3 ferramentas/verificacao_correcoes_v52/reproduzir.py [arquivo_json_de_saida]
Requisitos: gcc (com -fsanitize=thread), numpy, scipy, pytest. Leva menos de 1 minuto.

Leitura do resultado:
  - Contra a v5.1, cada exploit deve PASSAR (o ataque funciona).
  - Contra a v5.2, os exploits dos achados corrigidos devem FALHAR (o ataque não funciona mais).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

AQUI = Path(__file__).resolve().parent
RAIZ = AQUI.parents[1]
HIST = AQUI / "historico_v5_1"

EXPLOITS = [
    ("RT-F1-01", "Média", "test_03_slide_related_key_symmetric_subspace_key_schedule_and_input_bias",
     "subchave expõe K_r literalmente; metade da subchave reconstruída sem a chave mestra"),
    ("RT-F2-02", "Alta", "test_06_concurrency_data_race_tsan_cache_size_and_avx2_objdump",
     "corrida de dados em init_cauchy_mds() detectada pelo ThreadSanitizer"),
    ("RT-F2-04", "Média", "test_07_python_folding_timing_welch_and_2to1_collision",
     "vazamento de tempo no folding (teste de Welch)"),
    ("RT-F2-03", "Média", "test_08_api_s_priv_exposure_and_boundary_fuzzing",
     "API pública devolve o estado privado s_priv_state"),
]

FALHA_DENTRO = r'''
import sys, json, inspect, numpy as np
sys.path.insert(0, sys.argv[1])
import rsd_s_v5_hardened as H
s=b"\x55"*32; n=4242; x=0x123456789ABCDEF0123456789ABCDEF0; y=0xFEDCBA9876543210FEDCBA9876543210
def flip(st):
    st[0]^=1; return st
if "fault_round" not in inspect.signature(H.diffuse_rsd_s_v5_pre_sha).parameters:
    # v5.1: só existe injeção antes da rodada final. Emula a falha em R1..R7 seguindo o próprio
    # algoritmo da v5.1 (um fluxo até R-1; duplicação apenas na rodada final).
    det = {}
    keys = H.derive_keys_v5(s, n, 8); st0 = np.bitwise_xor(H.fragment_full_v5(x, y), H.expand_key_words_v5(keys[0], 32))
    for r in range(1, 9):
        st = st0.copy()
        for k in range(1, 8):
            if k == r: st[0] ^= 1
            st = H._single_round_v5(st, H.round_constant_v5(s, n, k, 8), H.expand_key_words_v5(keys[k], 32))
        a = st.copy(); b = st.copy()
        if r == 8: a[0] ^= 1
        rc8, rk8 = H.round_constant_v5(s, n, 8, 8), H.expand_key_words_v5(keys[8], 32)
        det[r] = "detectada" if not np.array_equal(H._single_round_v5(a, rc8, rk8), H._single_round_v5(b, rc8, rk8)) else "NAO detectada"
else:
    det = {}
    for r in range(1, 9):
        try:
            H.diffuse_rsd_s_v5_pre_sha(x, y, s, n, rounds=8, fault_injector=flip, fault_round=r); det[r] = "NAO detectada"
        except H.FaultDetectedError:
            det[r] = "detectada"
print(json.dumps(det))
'''


def montar_arvore(destino: Path, versao: str) -> Path:
    arvore = destino / versao
    shutil.copytree(RAIZ / "implementacao", arvore / "implementacao",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "historico_v5_1"))
    (arvore / "testes").mkdir()
    shutil.copy2(HIST / "exploits_v5_1.py", arvore / "testes" / "exploits_v5_1.py")
    if versao == "v5.1":
        shutil.copy2(HIST / "rsd_s_v5_ct.c", arvore / "implementacao" / "c_core" / "rsd_s_v5_ct.c")
        shutil.copy2(HIST / "rsd_s_v5_hardened.py", arvore / "implementacao" / "rsd_s_v5_hardened.py")
        shutil.copy2(HIST / "bandlimited_dual_key.py", arvore / "implementacao" / "bandlimited_dual_key.py")
    return arvore


def rodar_exploit(arvore: Path, teste: str) -> bool:
    shutil.rmtree("/tmp/r5_m4_build", ignore_errors=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-k", teste,
                           "testes/exploits_v5_1.py"], cwd=arvore, capture_output=True, text=True, env=env)
    return proc.returncode == 0


def main() -> int:
    saida = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    resultado: dict = {"exploits": [], "falha_dentro_da_execucao": {}}
    with tempfile.TemporaryDirectory(prefix="rsd_correcoes_") as tmp:
        arvores = {v: montar_arvore(Path(tmp), v) for v in ("v5.1", "v5.2")}
        for ident, sev, teste, descr in EXPLOITS:
            linha = {"id": ident, "severidade": sev, "ataque": descr}
            for v, arv in arvores.items():
                linha[v] = "ataque funciona" if rodar_exploit(arv, teste) else "ataque bloqueado"
            resultado["exploits"].append(linha)
        for v, arv in arvores.items():
            proc = subprocess.run([sys.executable, "-c", FALHA_DENTRO, str(arv / "implementacao")],
                                  capture_output=True, text=True, check=True,
                                  env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            resultado["falha_dentro_da_execucao"][v] = json.loads(proc.stdout)

    print(f"{'Achado':10} {'Sev.':6} {'v5.1':18} {'v5.2':18} Ataque")
    for l in resultado["exploits"]:
        print(f"{l['id']:10} {l['severidade']:6} {l['v5.1']:18} {l['v5.2']:18} {l['ataque']}")
    print("\nRT-F2-01 (Alta): falha transitória injetada DENTRO da execução, por rodada")
    for v, det in resultado["falha_dentro_da_execucao"].items():
        print(f"  {v}: " + ", ".join(f"R{r}={'sim' if d == 'detectada' else 'NÃO'}" for r, d in det.items()))
    if saida:
        saida.parent.mkdir(parents=True, exist_ok=True)
        saida.write_text(json.dumps(resultado, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    ok = all(l["v5.1"] == "ataque funciona" and l["v5.2"] == "ataque bloqueado" for l in resultado["exploits"])
    ok &= all(d == "detectada" for d in resultado["falha_dentro_da_execucao"]["v5.2"].values())
    print("\nCorreções confirmadas." if ok else "\nATENÇÃO: alguma correção não se confirmou.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
