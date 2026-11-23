#!/usr/bin/env python3
"""Gera site/dados/paridade.json: a "verdade" do Python e do núcleo C que o motor JavaScript deve reproduzir.

Determinístico (semente fixa). Uso, a partir da raiz do repositório:
    python3 site/ferramentas/gerar_dados.py            # regrava o arquivo
    python3 site/ferramentas/gerar_dados.py --conferir # falha se o arquivo commitado divergir

Requer gcc (o integral é calculado pelo núcleo C99), numpy e a pasta implementacao/.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

RAIZ = Path(__file__).resolve().parents[2]
SAIDA = RAIZ / "site" / "dados" / "paridade.json"
sys.path.insert(0, str(RAIZ / "implementacao"))

import rsd_s_v5_hardened as H  # noqa: E402

SEMENTE = 20261123
W = H.W


def hx(b: bytes) -> str:
    return b.hex()


def estado_hex(st) -> str:
    return H.serialize_state_v5(st).hex()


def traco(x, y, s, n, rounds):
    """Estado após a soma de rk0 e após cada rodada, da execução com `rounds` rodadas."""
    keys = H.derive_keys_v5(s, n, rounds)
    st = np.bitwise_xor(H.fragment_full_v5(x, y), H.expand_key_words_v5(keys[0], W))
    out = [estado_hex(st)]
    for r in range(1, rounds + 1):
        st = H._single_round_v5(st, H.round_constant_v5(s, n, r, rounds), H.expand_key_words_v5(keys[r], W))
        out.append(estado_hex(st))
    return out


def casos_hash(rng):
    out = {"sha256": [], "hmac": [], "shake256": []}
    for tam in [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 135, 136, 137, 200, 271, 272, 273, 500] + [rng.randrange(0, 700) for _ in range(40)]:
        m = rng.randbytes(tam)
        out["sha256"].append({"msg": hx(m), "out": hashlib.sha256(m).hexdigest()})
        k = rng.randbytes(rng.choice([1, 16, 32, 64, 65, 100]))
        out["hmac"].append({"key": hx(k), "msg": hx(m), "out": hmac.new(k, m, hashlib.sha256).hexdigest()})
        for ol in (1, 32, 64, 136, 137, 300):
            out["shake256"].append({"msg": hx(m), "len": ol, "out": hashlib.shake_256(m).hexdigest(ol)})
    return out


def tabelas():
    sbox = np.array([H.sbox_v5_eval(u) for u in range(65536)], dtype="<u2")
    mds = np.array(H.M_CAUCHY_32, dtype="<u2")
    return {
        "sbox_sha256_le16": hashlib.sha256(sbox.tobytes()).hexdigest(),
        "sbox_amostra": {str(u): int(sbox[u]) for u in (0, 1, 2, 3, 255, 256, 4660, 21845, 43690, 65535)},
        "mds_sha256_le16": hashlib.sha256(mds.tobytes()).hexdigest(),
        "mds_primeira_linha": [int(v) for v in mds[0]],
        "pontos_fixos": int(sum(1 for u in range(65536) if sbox[u] == u)),
        "bijecao": bool(len(set(sbox.tolist())) == 65536),
    }


def casos_rsd(rng):
    casos, traces = [], 0
    for i in range(300):
        rounds = rng.choice([1, 2, 3, 4, 5, 6, 7, 8, 8, 8])
        x, y = rng.randrange(H.P_CURVE25519), rng.randrange(H.P_CURVE25519)
        if i % 25 == 0:
            x, y = rng.choice([0, 1, H.P_CURVE25519 - 1]), rng.choice([0, 2, H.P_CURVE25519 - 1])
        s = rng.randbytes(32)
        n = rng.choice([0, 1, rng.randrange(2**64), 2**64 - 1])
        st = H.diffuse_rsd_s_v5_pre_sha(x, y, s, n, rounds=rounds)
        caso = {
            "x": str(x), "y": str(y), "s": hx(s), "n_sess": str(n), "rounds": rounds,
            "pre_sha": estado_hex(st),
            "out32": hx(H.diffuse_rsd_s_v5(x, y, s, n, rounds=rounds, output_bytes=32)),
            "out64": hx(H.diffuse_rsd_s_v5(x, y, s, n, rounds=rounds, output_bytes=64)),
        }
        if i < 60:
            caso["traco"] = traco(x, y, s, n, rounds)
            caso["chaves"] = [hx(k) for k in H.derive_keys_v5(s, n, rounds)]
            caso["rc"] = [H.round_constant_v5(s, n, r, rounds) for r in range(1, rounds + 1)]
            traces += 1
        casos.append(caso)
    return casos


def casos_falha(rng):
    out = []
    for _ in range(80):
        rounds = rng.choice([1, 2, 4, 8, 8, 8])
        x, y, s, n = rng.randrange(H.P_CURVE25519), rng.randrange(H.P_CURVE25519), rng.randbytes(32), rng.randrange(2**64)
        fr, fw = rng.randrange(1, rounds + 1), rng.randrange(W)
        mask = rng.choice([1, 0x8000, rng.randrange(1, 65536), 0])

        def inj(st, w=fw, m=mask):
            st[w] ^= m
            return st

        try:
            H.diffuse_rsd_s_v5_pre_sha(x, y, s, n, rounds=rounds, fault_injector=inj, fault_round=fr)
            status = 0
        except H.FaultDetectedError:
            status = -2
        out.append({"x": str(x), "y": str(y), "s": hx(s), "n_sess": str(n), "rounds": rounds,
                    "round": fr, "word": fw, "mask": mask, "status": status})
    return out


def casos_contrato():
    s = bytes(32)
    P = H.P_CURVE25519
    itens = [
        ("x=p", lambda: H.diffuse_rsd_s_v5(P, 0, s, 0)),
        ("x<0", lambda: H.diffuse_rsd_s_v5(-1, 0, s, 0)),
        ("y=p", lambda: H.diffuse_rsd_s_v5(0, P, s, 0)),
        ("chave 31B", lambda: H.diffuse_rsd_s_v5(0, 0, bytes(31), 0)),
        ("n_sess=2^64", lambda: H.diffuse_rsd_s_v5(0, 0, s, 2**64)),
        ("n_sess<0", lambda: H.diffuse_rsd_s_v5(0, 0, s, -1)),
        ("rounds=0", lambda: H.diffuse_rsd_s_v5(0, 0, s, 0, rounds=0)),
        ("rounds=256", lambda: H.diffuse_rsd_s_v5(0, 0, s, 0, rounds=256)),
        ("output_bytes=48", lambda: H.diffuse_rsd_s_v5(0, 0, s, 0, output_bytes=48)),
    ]
    out = []
    for nome, f in itens:
        try:
            f()
            out.append({"caso": nome, "erro": None})
        except (ValueError, TypeError) as e:
            out.append({"caso": nome, "erro": type(e).__name__, "mensagem": str(e)})
    return out


def integral():
    """Soma XOR das 32 saídas pré-SHA para um Λ-conjunto de 2^16 entradas (uma palavra ativa),
    calculada pelo núcleo C99 (-O3 -mavx2). Instância reduzida: rounds = r, agenda própria."""
    tmp = Path(tempfile.mkdtemp(prefix="rsd_site_"))
    so = tmp / "lib.so"
    subprocess.run(["gcc", "-O3", "-mavx2", "-shared", "-fPIC", str(RAIZ / "implementacao/c_core/rsd_s_v5_ct.c"), "-o", str(so)], check=True)
    lib = ctypes.CDLL(str(so))
    P16 = ctypes.POINTER(ctypes.c_uint16)
    lib.rsd_s_v5_core_ct.argtypes = [P16, P16, P16, ctypes.c_int, ctypes.c_int, ctypes.c_uint16, P16]
    rng = random.Random(SEMENTE + 1)
    saida = []
    for _ in range(2):
        s, n = rng.randbytes(32), rng.randrange(2**64)
        base = np.array([rng.randrange(65536) for _ in range(W)], dtype=np.uint16)
        for ativa in (0, 31):
            linha = {"s": hx(s), "n_sess": str(n), "palavra_ativa": ativa, "base": [int(v) for v in base], "soma_nao_nula": {}}
            for r in range(1, 9):
                keys = H.derive_keys_v5(s, n, r)
                rk = np.concatenate([H.expand_key_words_v5(k, W) for k in keys]).astype(np.uint16)
                rc = np.array([H.round_constant_v5(s, n, q, r) for q in range(1, r + 1)], dtype=np.uint16)
                ent, out = base.copy(), np.zeros(W, dtype=np.uint16)
                pe, pr, pc, po = (a.ctypes.data_as(P16) for a in (ent, rk, rc, out))
                acc = np.zeros(W, dtype=np.uint16)
                for v in range(65536):
                    ent[ativa] = v
                    assert lib.rsd_s_v5_core_ct(pe, pr, pc, r, -1, 0, po) == 0
                    acc ^= out
                linha["soma_nao_nula"][str(r)] = int(np.count_nonzero(acc))
            saida.append(linha)
    return saida


def gerar() -> dict:
    rng = random.Random(SEMENTE)
    return {
        "versao_dados": 1,
        "semente": SEMENTE,
        "origem": "implementacao/rsd_s_v5_hardened.py e implementacao/c_core/rsd_s_v5_ct.c",
        "hash": casos_hash(rng),
        "tabelas": tabelas(),
        "rsd": casos_rsd(rng),
        "falhas": casos_falha(rng),
        "contrato": casos_contrato(),
        "integral": integral(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conferir", action="store_true")
    a = ap.parse_args()
    texto = json.dumps(gerar(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    if a.conferir:
        ok = SAIDA.read_text(encoding="utf-8") == texto
        print("paridade.json: " + ("confere" if ok else "DIVERGE do regenerado"))
        return 0 if ok else 1
    SAIDA.parent.mkdir(parents=True, exist_ok=True)
    SAIDA.write_text(texto, encoding="utf-8", newline="\n")
    print(f"escrito {SAIDA.relative_to(RAIZ)} ({len(texto) // 1024} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
