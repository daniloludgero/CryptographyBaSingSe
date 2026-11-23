"""
rsd_s_v5_hardened.py

Evolução endurecida do núcleo RSD-S (v5), preservando rsd_s_v4_final.py intacto
como baseline histórico.

Correções estruturais aplicadas frente às vulnerabilidades comprovadas nos Marcos M1-M5:
  1. [VULN-04] S-box com camada afim F_2-linear invertível (A_16 * x^{-1} XOR 0x63A9),
     zero pontos fixos e zero pontos fixos opostos em todo GF(2^16), eliminando a
     relação bilinear explorada no ataque algébrico de 25,29 ms.
  2. [VULN-02/03] Suporte nativo ao núcleo C99 constant-time e table-free (Itoh-Tsujii),
     com referência pura em Python exatamente paritária bit-a-bit.
  3. [VULN-01] Proteção Anti-DFA por execução redundante da rodada final com verificação
     de integridade em tempo constante; divergência aborta e limpa o buffer.
  4. [GAP-06] 8 rodadas oficiais (>= 132 S-boxes ativas, limite diferencial <= 2^-1848),
     eliminando o déficit entrópico pré-SHA observado em 4 rodadas.
  5. [GAP-07] Endianness unificado (big-endian >u2) e separação explícita de domínio.
"""

from __future__ import annotations

import ctypes
import hmac
from hashlib import sha256, shake_256
from pathlib import Path
from typing import Callable

import numpy as np

from mds_real import GF16_POLY, build_cauchy_mds, gf_add, gf_mult

W = 32
B = 16
MASK16 = 0xFFFF
R_V5 = 8
MAX_ROUNDS = 255
P_CURVE25519 = 2**255 - 19
KEY_SIZE = 32
MAX_SESSION = 2**64 - 1
AFFINE_CONST_V5 = 0x63A9
AFFINE_ROTATIONS = (0, 1, 2, 3, 4, 5, 7, 11, 13)
DOMAIN_PREFIX_V5 = b"RSD-S-V5.1|CORE|"

# Permutação assimétrica de colunas p(j) = (5*j + 1) mod 32:
# Preserva 100% os menores MDS (Branch Number B = 33), mas quebra a involução
# escalar M^2 = 0x5E26 * I descoberta no Lote B (992/992 entradas fora da diagonal de M^2 não-nulas).
MDS_COL_PERM_V51 = tuple((5 * j + 1) % W for j in range(W))
_M_CAUCHY_BASE = build_cauchy_mds(W)
M_CAUCHY_32 = _M_CAUCHY_BASE[:, MDS_COL_PERM_V51].copy()


class FaultDetectedError(RuntimeError):
    """Exceção disparada pela proteção Anti-DFA quando há divergência na rodada final."""


def _validate_field_element(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} deve ser um inteiro")
    if not 0 <= value < P_CURVE25519:
        raise ValueError(f"{name} deve satisfazer 0 <= {name} < 2^255 - 19")


def _validate_key(s: bytes) -> None:
    if not isinstance(s, bytes):
        raise TypeError("s deve ser bytes")
    if len(s) != KEY_SIZE:
        raise ValueError(f"s deve ter exatamente {KEY_SIZE} bytes")


def _validate_session(n_sess: int) -> None:
    if isinstance(n_sess, bool) or not isinstance(n_sess, int):
        raise TypeError("n_sess deve ser um inteiro")
    if not 0 <= n_sess <= MAX_SESSION:
        raise ValueError("n_sess deve satisfazer 0 <= n_sess < 2^64")


def _validate_rounds(rounds: int) -> None:
    if isinstance(rounds, bool) or not isinstance(rounds, int):
        raise TypeError("rounds deve ser um inteiro")
    if not 1 <= rounds <= MAX_ROUNDS:
        raise ValueError(f"rounds deve satisfazer 1 <= rounds <= {MAX_ROUNDS}")


def rotl16(x: int, k: int) -> int:
    x &= MASK16
    return ((x << k) | (x >> (16 - k))) & MASK16


def affine16(v: int) -> int:
    """Transformação F_2-linear invertível A_16 (peso de Hamming 9 por linha)."""
    v &= MASK16
    acc = 0
    for k in AFFINE_ROTATIONS:
        acc ^= rotl16(v, k)
    return acc & MASK16


def gf16_mul_ct_ref(a: int, b: int) -> int:
    """Referência sem ramos condicionais (laço fixo de 16 bits) em GF(2^16)."""
    a &= MASK16
    b &= MASK16
    res = 0
    for _ in range(16):
        mask = -(b & 1)
        res ^= a & mask
        hi = -((a >> 15) & 1)
        a = ((a << 1) ^ (GF16_POLY & hi)) & MASK16
        b >>= 1
    return res & MASK16


def gf16_inv_itoh_tsujii(x: int) -> int:
    """Inversão x^(2^16 - 2) em GF(2^16) via cadeia de adição de Itoh-Tsujii (0 -> 0)."""
    x &= MASK16

    def sq(v: int) -> int:
        return gf16_mul_ct_ref(v, v)

    def sqn(v: int, n: int) -> int:
        for _ in range(n):
            v = sq(v)
        return v

    a2 = gf16_mul_ct_ref(sq(x), x)
    a3 = gf16_mul_ct_ref(sq(a2), x)
    a6 = gf16_mul_ct_ref(sqn(a3, 3), a3)
    a7 = gf16_mul_ct_ref(sq(a6), x)
    a14 = gf16_mul_ct_ref(sqn(a7, 7), a7)
    a15 = gf16_mul_ct_ref(sq(a14), x)
    return sq(a15)


def sbox_v5_eval(u: int) -> int:
    """S-box endurecida v5: S_v5(u) = A_16(u^{-1}) XOR 0x63A9 (zero LUT)."""
    return (affine16(gf16_inv_itoh_tsujii(u)) ^ AFFINE_CONST_V5) & MASK16


def _domain_tag(n_sess: int, rounds: int) -> bytes:
    return DOMAIN_PREFIX_V5 + rounds.to_bytes(1, "big") + n_sess.to_bytes(8, "big")


def derive_keys_v5(s: bytes, n_sess: int, rounds: int = R_V5) -> list[bytes]:
    _validate_key(s)
    _validate_session(n_sess)
    _validate_rounds(rounds)
    dom = _domain_tag(n_sess, rounds)
    keys = [hmac.new(s, dom + b"\x00", sha256).digest()]
    for r in range(1, rounds + 1):
        keys.append(hmac.new(s, keys[-1] + dom + r.to_bytes(1, "big"), sha256).digest())
    return keys


def round_constant_v5(s: bytes, n_sess: int, r: int, rounds: int = R_V5) -> int:
    _validate_key(s)
    _validate_session(n_sess)
    _validate_rounds(rounds)
    if isinstance(r, bool) or not isinstance(r, int) or not 1 <= r <= rounds:
        raise ValueError(f"r deve satisfazer 1 <= r <= {rounds}")
    dom = _domain_tag(n_sess, rounds)
    h = hmac.new(s, dom + b"RC" + r.to_bytes(1, "big"), sha256).digest()
    return int.from_bytes(h[:2], "big")


def expand_key_words_v5(key_bytes: bytes, n_words: int = W) -> np.ndarray:
    """
    Expansão unificada em big-endian (>u2) com derivação PRF/HMAC em todos os blocos
    (block_idx = 0, 1, ...), fechando assimetria <u2 da v4 e mitigando RT-F1-01
    (sem exposição literal de key_bytes em rk[r][0..15]).
    """
    if isinstance(n_words, bool) or not isinstance(n_words, int) or n_words < 1:
        raise ValueError("n_words deve ser um inteiro >= 1")
    needed_bytes = n_words * 2
    material = bytearray()
    block_idx = 0
    while len(material) < needed_bytes:
        material.extend(
            hmac.new(key_bytes, b"EXP|" + block_idx.to_bytes(4, "big"), sha256).digest()
        )
        block_idx += 1
    return np.frombuffer(bytes(material[:needed_bytes]), dtype=">u2").astype(np.uint16)


def fragment_full_v5(x: int, y: int) -> np.ndarray:
    _validate_field_element(x, "x")
    _validate_field_element(y, "y")
    x_slices = [(x >> (j * B)) & MASK16 for j in range(16)]
    y_slices = [(y >> (j * B)) & MASK16 for j in range(16)]
    return np.array(x_slices + y_slices, dtype=np.uint16)


def _mds_mult_v5_ref(state: np.ndarray) -> np.ndarray:
    out = np.zeros(W, dtype=np.uint16)
    for i in range(W):
        acc = 0
        row = M_CAUCHY_32[i]
        for j in range(W):
            acc = gf_add(acc, gf_mult(int(row[j]), int(state[j])))
        out[i] = acc & MASK16
    return out


def _single_round_v5(state_in: np.ndarray, rc: int, rk_words: np.ndarray) -> np.ndarray:
    sub = np.array([(sbox_v5_eval(int(state_in[i])) ^ rc) & MASK16 for i in range(W)], dtype=np.uint16)
    diffused = _mds_mult_v5_ref(sub)
    return np.bitwise_xor(diffused, rk_words)


def diffuse_rsd_s_v5_pre_sha(
    x: int,
    y: int,
    s: bytes,
    n_sess: int,
    rounds: int = R_V5,
    fault_injector: Callable[[np.ndarray], np.ndarray] | None = None,
    fault_round: int | None = None,
) -> np.ndarray:
    """
    Executa o núcleo SPN endurecido RSD-S v5 com proteção Anti-DFA ponta-a-ponta (R1..rounds)
    [RT-F2-01]: dois fluxos independentes A e B percorrem todas as rodadas e são comparados
    em tempo constante ao final.
    Se `fault_injector` for fornecido, injeta falha no fluxo A antes da rodada `fault_round`
    (padrão: rodada final `rounds`) para validar a detecção determinística em qualquer rodada.
    """
    _validate_field_element(x, "x")
    _validate_field_element(y, "y")
    _validate_key(s)
    _validate_session(n_sess)
    _validate_rounds(rounds)
    if fault_round is not None and (not isinstance(fault_round, int) or isinstance(fault_round, bool) or not (1 <= fault_round <= rounds)):
        raise ValueError(f"fault_round deve ser inteiro em [1, {rounds}]")

    target_fault_round = rounds if fault_round is None else fault_round

    state_init = fragment_full_v5(x, y)
    keys = derive_keys_v5(s, n_sess, rounds)
    rk0 = expand_key_words_v5(keys[0], W)
    state_a = np.bitwise_xor(state_init, rk0)
    state_b = state_a.copy()

    for r in range(1, rounds + 1):
        if fault_injector is not None and r == target_fault_round:
            state_a = fault_injector(state_a.copy())
        rc = round_constant_v5(s, n_sess, r, rounds)
        rk = expand_key_words_v5(keys[r], W)
        state_a = _single_round_v5(state_a, rc, rk)
        state_b = _single_round_v5(state_b, rc, rk)

    diff = 0
    for i in range(W):
        diff |= int(state_a[i]) ^ int(state_b[i])
    if diff != 0:
        state_a.fill(0)
        state_b.fill(0)
        raise FaultDetectedError("Anti-DFA: divergência detectada entre execuções redundantes (R1..R); saída abortada.")

    return state_a


def serialize_state_v5(state: np.ndarray) -> bytes:
    return b"".join(int(state[i]).to_bytes(2, "big") for i in range(W))


def diffuse_rsd_s_v5(
    x: int,
    y: int,
    s: bytes,
    n_sess: int,
    rounds: int = R_V5,
    output_bytes: int = 32,
) -> bytes:
    """
    API oficial v5:
      - output_bytes == 32: compressão SHA-256 (compatível com saída de 256 bits)
      - output_bytes == 64: compressão SHAKE256 de 512 bits (prontidão BHT >= 128 bits)
    """
    if output_bytes not in (32, 64):
        raise ValueError("output_bytes deve ser 32 (256 bits) ou 64 (512 bits)")
    state = diffuse_rsd_s_v5_pre_sha(x, y, s, n_sess, rounds=rounds)
    raw = serialize_state_v5(state)
    dom = _domain_tag(n_sess, rounds)
    if output_bytes == 32:
        return sha256(dom + raw).digest()
    return shake_256(dom + b"|XOF512|" + raw).digest(64)


def run_c_core_pre_sha(
    lib_path: str | Path,
    x: int,
    y: int,
    s: bytes,
    n_sess: int,
    rounds: int = R_V5,
    inject_fault_word: int = -1,
    inject_fault_mask: int = 0,
    inject_fault_round: int | None = None,
) -> tuple[int, np.ndarray]:
    """
    Invoca o núcleo C99 constant-time (`rsd_s_v5_ct.c`) para paridade exata,
    TVLA real em hardware e validação de proteção Anti-DFA (R1..R).
    Retorna (status_code, state_uint16_32). status_code == 0 indica sucesso; -2 indica FAULT_DETECTED.
    """
    lib = ctypes.CDLL(str(lib_path))
    in_state = fragment_full_v5(x, y)
    keys = derive_keys_v5(s, n_sess, rounds)
    rk_flat = np.concatenate([expand_key_words_v5(k, W) for k in keys]).astype(np.uint16)
    rcs = np.array([round_constant_v5(s, n_sess, r, rounds) for r in range(1, rounds + 1)], dtype=np.uint16)
    out_state = np.zeros(W, dtype=np.uint16)

    if inject_fault_round is None:
        lib.rsd_s_v5_core_ct.argtypes = [
            ctypes.POINTER(ctypes.c_uint16),  # in_state[32]
            ctypes.POINTER(ctypes.c_uint16),  # rk_flat[(rounds+1)*32]
            ctypes.POINTER(ctypes.c_uint16),  # rc[rounds]
            ctypes.c_int,                     # rounds
            ctypes.c_int,                     # fault_word (-1 = none)
            ctypes.c_uint16,                  # fault_mask
            ctypes.POINTER(ctypes.c_uint16),  # out_state[32]
        ]
        lib.rsd_s_v5_core_ct.restype = ctypes.c_int
        rc_code = lib.rsd_s_v5_core_ct(
            in_state.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            rk_flat.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            rcs.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            ctypes.c_int(rounds),
            ctypes.c_int(inject_fault_word),
            ctypes.c_uint16(inject_fault_mask & MASK16),
            out_state.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
        )
    else:
        lib.rsd_s_v5_core_ct_ex.argtypes = [
            ctypes.POINTER(ctypes.c_uint16),  # in_state[32]
            ctypes.POINTER(ctypes.c_uint16),  # rk_flat[(rounds+1)*32]
            ctypes.POINTER(ctypes.c_uint16),  # rc[rounds]
            ctypes.c_int,                     # rounds
            ctypes.c_int,                     # fault_round (1..rounds)
            ctypes.c_int,                     # fault_word (-1 = none)
            ctypes.c_uint16,                  # fault_mask
            ctypes.POINTER(ctypes.c_uint16),  # out_state[32]
        ]
        lib.rsd_s_v5_core_ct_ex.restype = ctypes.c_int
        rc_code = lib.rsd_s_v5_core_ct_ex(
            in_state.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            rk_flat.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            rcs.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            ctypes.c_int(rounds),
            ctypes.c_int(inject_fault_round),
            ctypes.c_int(inject_fault_word),
            ctypes.c_uint16(inject_fault_mask & MASK16),
            out_state.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
        )
    return int(rc_code), out_state
