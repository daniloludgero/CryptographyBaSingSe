"""
R4 - Benchmark comparativo (RSD-S v5.1 vs SHA-2/SHA-3/BLAKE2/HMAC) e testes ANÁLOGOS a QROM.

AVISO DE ESCOPO (RESTRICOES_DE_PROJETO.md): isto NÃO é prova em QROM. É um proxy empírico:
  * Trata cada primitiva chaveada como uma função H_k restrita a n bits (n = 10, 12, 14) e a
    compara com um Oráculo Aleatório (RO) ideal usando um ENSEMBLE de RO como referência (z-scores).
  * Testes com relevância quântica: multiplicidade de pré-imagens (Grover), colisões/imagem
    (BHT/CNS), e estrutura de período XOR (Simon / Kuperberg / ataques a Even-Mansour).
  * Controles negativos (linear GF(2), RSD-S de 1 e 2 rodadas) provam que a bateria TEM sensibilidade.
Nenhuma conclusão aqui implica segurança pós-quântica certificada.
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))
from rsd_s_v5_hardened import (  # noqa: E402
    W, derive_keys_v5, expand_key_words_v5, fragment_full_v5, round_constant_v5,
    serialize_state_v5, _domain_tag,
)

BUILD = Path("/tmp/r4_build")
BUILD.mkdir(exist_ok=True)
SO = BUILD / "lib_rsd_r4.so"
RES = ROOT / "resultados" / "v5_sandbox"
RNG = np.random.default_rng(int.from_bytes(os.urandom(8), "big"))
FLAG_Z = 4.0
NS = (10, 12, 14)
K_KEYS = 8
K_RO = 40


def _lib():
    if not SO.exists():
        subprocess.run(["gcc", "-O3", "-mavx2", "-shared", "-fPIC",
                        str(ROOT / "implementacao/c_core/rsd_s_v5_ct.c"), "-o", str(SO)], check=True)
    lib = ctypes.CDLL(str(SO))
    P = ctypes.POINTER(ctypes.c_uint16)
    lib.rsd_s_v5_core_ct.argtypes = [P, P, P, ctypes.c_int, ctypes.c_int, ctypes.c_uint16, P]
    lib.rsd_s_v5_core_ct.restype = ctypes.c_int
    return lib


class RSDKeyed:
    """RSD-S v5.1 com agenda de chaves pré-computada (uma vez por chave); chamadas em lote via C core."""

    def __init__(self, lib, s: bytes, n_sess: int, rounds: int):
        self.lib, self.rounds, self.dom = lib, rounds, _domain_tag(n_sess, rounds)
        keys = derive_keys_v5(s, n_sess, rounds)
        self.rk = np.concatenate([expand_key_words_v5(k, W) for k in keys]).astype(np.uint16)
        self.rc = np.array([round_constant_v5(s, n_sess, r, rounds) for r in range(1, rounds + 1)], dtype=np.uint16)
        self.out = np.zeros(W, dtype=np.uint16)
        P = ctypes.POINTER(ctypes.c_uint16)
        self.p_rk, self.p_rc, self.p_out = (a.ctypes.data_as(P) for a in (self.rk, self.rc, self.out))

    def raw(self, x: int, y: int) -> bytes:
        st = np.ascontiguousarray(fragment_full_v5(x, y).astype(np.uint16))
        rc = self.lib.rsd_s_v5_core_ct(st.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)), self.p_rk, self.p_rc,
                                       self.rounds, -1, 0, self.p_out)
        assert rc == 0
        return serialize_state_v5(self.out)

    def sha(self, raw: bytes) -> bytes:
        return hashlib.sha256(self.dom + raw).digest()


def _xy(i: int) -> tuple[int, int]:
    return i & 0xFFFF, 12345


def _enc(i: int) -> bytes:
    return i.to_bytes(4, "big") + (12345).to_bytes(4, "big")


def _top(b: bytes, n: int) -> int:
    return int.from_bytes(b[:4], "big") >> (32 - n)


# --------- primitivas: fábrica(key)-> f(i, n)-> int(n bits) --------------------------------------
def make_primitives(lib):
    def rsd(rounds, pipeline):
        def fac(key):
            k = RSDKeyed(lib, key, 1, rounds)
            return lambda i, n: _top(k.sha(k.raw(*_xy(i))) if pipeline else k.raw(*_xy(i)), n)
        return fac

    def hmac_f(alg):
        return lambda key: (lambda i, n: _top(hmac.new(key, _enc(i), alg).digest(), n))

    def sha3k(key):
        return lambda i, n: _top(hashlib.sha3_256(key + _enc(i)).digest(), n)

    def blake(key):
        return lambda i, n: _top(hashlib.blake2b(_enc(i), key=key, digest_size=32).digest(), n)

    def shake(key):
        return lambda i, n: _top(hashlib.shake_256(key + _enc(i)).digest(32), n)

    def linear(key):
        rows = np.frombuffer(hashlib.shake_256(b"lin" + key).digest(32 * 4), dtype=np.uint8)
        masks = [int.from_bytes(hashlib.shake_256(b"row%d" % j + key).digest(4), "big") for j in range(32)]
        return lambda i, n: sum((bin(masks[j] & i).count("1") & 1) << (n - 1 - j) for j in range(n))

    return {
        "RSD-S v5.1 (8R + SHA-256)": rsd(8, True),
        "RSD-S v5.1 core cru (8R, sem SHA)": rsd(8, False),
        "CONTROLE RSD-S 1R cru": rsd(1, False),
        "CONTROLE RSD-S 2R cru": rsd(2, False),
        "HMAC-SHA256": hmac_f(hashlib.sha256),
        "HMAC-SHA3-256": hmac_f(hashlib.sha3_256),
        "BLAKE2b (keyed)": blake,
        "SHAKE256(k||m)": shake,
        "SHA3-256(k||m)": sha3k,
        "CONTROLE linear GF(2)": linear,
    }


def table(f, n):
    return np.fromiter((f(i, n) for i in range(1 << n)), dtype=np.int64, count=1 << n)


def ro_table(n):
    return RNG.integers(0, 1 << n, size=1 << n, dtype=np.int64)


def stats_of(T: np.ndarray, n: int, with_simon: bool) -> dict:
    N = 1 << n
    img = len(np.unique(T))
    ystar = T[int(RNG.integers(N))]
    mult = int(np.sum(T == ystar))
    out = {"collisions_N_minus_image": N - img, "preimage_multiplicity": mult}
    if with_simon:
        idx = np.arange(N)
        best = 0
        for s in range(1, N):
            best = max(best, int(np.sum(T == T[idx ^ s])))
        out["simon_max_xor_period_matches"] = best
    return out


def grover_curve(T: np.ndarray, n: int):
    """Statevector exato de Grover sobre a tabela T (alvo y* com multiplicidade M real)."""
    N = 1 << n
    ystar = T[int(RNG.integers(N))]
    mark = T == ystar
    M = int(mark.sum())
    amp = np.full(N, 1 / math.sqrt(N))
    theta = math.asin(math.sqrt(M / N))
    kmax = int(math.pi / (4 * theta) * 1.6) + 1
    best, kbest, dev = 0.0, 0, 0.0
    for k in range(kmax + 1):
        p = float(np.sum(amp[mark] ** 2))
        dev = max(dev, abs(p - math.sin((2 * k + 1) * theta) ** 2))
        if p > best:
            best, kbest = p, k
        amp[mark] *= -1
        amp = 2 * amp.mean() - amp
    return {"M": M, "k_opt": kbest, "k_theory": round(math.pi / (4 * theta) - 0.5), "p_max": best, "max_dev_vs_theory": dev}


def run():
    lib = _lib()
    prims = make_primitives(lib)
    report: dict = {"date": "2026-11-22", "scope": "proxy empírico, NÃO é prova QROM", "bench": {}, "avalanche": {},
                    "uniformity": {}, "tables": {}, "grover": {}, "verdict": {}}
    # ---------------- E1 throughput (Python-loop, mesma convenção para todos) ----------------
    key = os.urandom(32)
    for name, fac in prims.items():
        f = fac(key)
        t = time.perf_counter()
        cnt = 4000
        for i in range(cnt):
            f(i, 16)
        report["bench"][name] = {"us_per_call_py_loop": round((time.perf_counter() - t) / cnt * 1e6, 2)}
    # ---------------- E2 avalanche (core cru 512 bits / hashes 256 bits) ----------------
    def av(name, fac_bits):
        flips = []
        for _ in range(800):
            x, y = int(RNG.integers(65537)), int(RNG.integers(65537))
            b = int(RNG.integers(16))
            a0, a1 = fac_bits(x, y), fac_bits(x ^ (1 << b), y)
            flips.append(bin(int.from_bytes(a0, "big") ^ int.from_bytes(a1, "big")).count("1") / (8 * len(a0)))
        return round(float(np.mean(flips)), 5), round(float(np.std(flips)), 5)

    for name, rounds, pipe in (("RSD-S v5.1 core cru (8R, sem SHA)", 8, False), ("CONTROLE RSD-S 1R cru", 1, False),
                               ("CONTROLE RSD-S 2R cru", 2, False)):
        k = RSDKeyed(lib, key, 1, rounds)
        report["avalanche"][name] = dict(zip(("mean_flip_fraction", "std"), av(name, lambda x, y: k.raw(x, y))))
    report["avalanche"]["HMAC-SHA256"] = dict(zip(("mean_flip_fraction", "std"), av("h", lambda x, y: hmac.new(
        key, x.to_bytes(4, "big") + y.to_bytes(4, "big"), hashlib.sha256).digest())))
    # ---------------- E3 uniformidade (chi² em 256 bins, 2^16 amostras do 1º byte) ----------------
    for name in ("RSD-S v5.1 core cru (8R, sem SHA)", "RSD-S v5.1 (8R + SHA-256)", "CONTROLE RSD-S 1R cru",
                 "HMAC-SHA256", "CONTROLE linear GF(2)"):
        f = prims[name](key)
        v = np.fromiter((f(i, 8) for i in range(1 << 16)), dtype=np.int64, count=1 << 16)
        chi, p = stats.chisquare(np.bincount(v, minlength=256))
        report["uniformity"][name] = {"chi2": round(float(chi), 2), "p_value": round(float(p), 4)}
    # ---------------- E4 tabelas n-bit vs ensemble RO ----------------
    for n in NS:
        simon = n <= 12
        ro = [stats_of(ro_table(n), n, simon) for _ in range(K_RO)]
        mu = {k: float(np.mean([r[k] for r in ro])) for k in ro[0]}
        sd = {k: float(np.std([r[k] for r in ro], ddof=1)) + 1e-12 for k in ro[0]}
        res = {"RO_ensemble_mean": mu, "RO_ensemble_std": sd, "primitives": {}}
        for name, fac in prims.items():
            rows = []
            for _ in range(K_KEYS):
                T = table(fac(os.urandom(32)), n)
                rows.append(stats_of(T, n, simon))
                if n == 12 and name in report["grover"] and len(report["grover"][name]) >= 3:
                    continue
                if n == 12:
                    report["grover"].setdefault(name, []).append(grover_curve(T, n))
            z = {k: round((float(np.mean([r[k] for r in rows])) - mu[k]) / (sd[k] / math.sqrt(K_KEYS)), 2) for k in mu}
            res["primitives"][name] = {"mean": {k: float(np.mean([r[k] for r in rows])) for k in mu}, "z": z,
                                       "flagged": [k for k, v in z.items() if abs(v) > FLAG_Z]}
        report["tables"][f"n={n}"] = res
        print("n =", n, "done", flush=True)
    # ---------------- veredito ----------------
    for name in prims:
        fl = sorted({k for n in NS for k in report["tables"][f"n={n}"]["primitives"][name]["flagged"]})
        report["verdict"][name] = {"flagged_tests": fl, "distinguished_from_RO": bool(fl)}
    return report


def to_md(r: dict) -> str:
    L = ["# R4 — Benchmark RSD-S v5.1 vs SHA/HMAC/BLAKE2 + testes análogos a QROM (2026-11-22)\n",
         "> **Escopo:** proxy empírico. **Não** é prova em QROM, **não** certifica segurança pós-quântica.\n",
         "## 1. Latência (loop Python, n=4000; RSD usa C core AVX2 via ctypes + fragmentação em Python; hashes via hashlib/OpenSSL)\n",
         "| Primitiva | µs/chamada |", "|---|---|"]
    L += [f"| {k} | {v['us_per_call_py_loop']} |" for k, v in r["bench"].items()]
    L += ["\n## 2. Avalanche (flip de 1 bit de entrada, fração de bits de saída alterados; ideal 0.5)\n",
          "| Primitiva | média | σ |", "|---|---|---|"]
    L += [f"| {k} | {v['mean_flip_fraction']} | {v['std']} |" for k, v in r["avalanche"].items()]
    L += ["\n## 3. Uniformidade do 1º byte (χ², 255 g.l., 2^16 amostras)\n", "| Primitiva | χ² | p |", "|---|---|---|"]
    L += [f"| {k} | {v['chi2']} | {v['p_value']} |" for k, v in r["uniformity"].items()]
    L += ["\n## 4. Tabelas H_k de n bits vs ensemble de Oráculo Aleatório (z-scores; |z|>4 = distinguível)\n"]
    for nn, d in r["tables"].items():
        L += [f"### {nn}\nRO: " + ", ".join(f"{k}={v:.3f}" for k, v in d["RO_ensemble_mean"].items()) + "\n",
              "| Primitiva | " + " | ".join(d["RO_ensemble_mean"]) + " | flags |",
              "|---|" + "---|" * (len(d["RO_ensemble_mean"]) + 1)]
        for p, v in d["primitives"].items():
            L.append(f"| {p} | " + " | ".join(f"{v['z'][k]}" for k in d["RO_ensemble_mean"]) + f" | {', '.join(v['flagged']) or '—'} |")
        L.append("")
    L += ["## 5. Grover exato (statevector, n=12) sobre a tabela da primitiva\n",
          "Nota: Grover simulado reproduz sin²((2k+1)θ) por construção; o que distingue primitivas é a multiplicidade M das pré-imagens (seção 4).\n",
          "| Primitiva | M médio | k_opt médio | p_max médio | desvio máx vs teoria |", "|---|---|---|---|---|"]
    for k, v in r["grover"].items():
        L.append(f"| {k} | {np.mean([g['M'] for g in v]):.2f} | {np.mean([g['k_opt'] for g in v]):.1f} | "
                 f"{np.mean([g['p_max'] for g in v]):.4f} | {max(g['max_dev_vs_theory'] for g in v):.1e} |")
    L += ["\n## 6. Veredito\n", "| Primitiva | Distinguível do RO? | Testes sinalizados |", "|---|---|---|"]
    L += [f"| {k} | {'SIM' if v['distinguished_from_RO'] else 'não'} | {', '.join(v['flagged_tests']) or '—'} |"
          for k, v in r["verdict"].items()]
    L += ["\n## 7. Custos quânticos de referência (algébricos, não medidos)\n",
          "| Alvo | Algoritmo | Consultas |", "|---|---|---|",
          "| Pré-imagem, saída 256 b | Grover | ~2^128 (profundidade serial, ver NIST) |",
          "| Pré-imagem, saída 512 b (XOF512) | Grover | ~2^256 |",
          "| Colisão, 256 b | BHT/CNS | ~2^85 consultas (2^{n/3}); trade-off com memória |",
          "| Colisão, 512 b | BHT/CNS | ~2^170 |",
          "| Chave 256 b | Grover | ~2^128 |",
          "\n## 8. Limites honestos\n",
          "- Domínio toy (n≤14 bits) não prova nada sobre 256/512 bits; mostra apenas ausência de estrutura grosseira testada.",
          "- A saída pública usa SHA-256/SHAKE256: a segurança de pré-imagem/colisão final é herdada de SHA, não do núcleo SPN.",
          "- Prova formal em QROM (Zhandry/Unruh) e revisão externa continuam pendentes; nada aqui altera `RESTRICOES_DE_PROJETO.md`.\n"]
    return "\n".join(L)


def test_r4_benchmark_qrom_analog():
    r = run()
    RES.mkdir(parents=True, exist_ok=True)
    (RES / "r4_benchmark_qrom_20261122.json").write_text(json.dumps(r, indent=1, default=float))
    (RES / "r4_benchmark_qrom_20261122.md").write_text(to_md(r))
    v = r["verdict"]
    assert not v["RSD-S v5.1 core cru (8R, sem SHA)"]["distinguished_from_RO"]
    assert not v["RSD-S v5.1 (8R + SHA-256)"]["distinguished_from_RO"]
    assert not v["HMAC-SHA256"]["distinguished_from_RO"]
    assert v["CONTROLE linear GF(2)"]["distinguished_from_RO"]


if __name__ == "__main__":
    test_r4_benchmark_qrom_analog()
