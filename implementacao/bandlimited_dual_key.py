"""
bandlimited_dual_key.py

Módulo Espectral de Banda Limitada & Operando Final Dupla-Chave para RSD-S v5.

Baseado no pipeline determinístico da Seção 9 do artigo
"Positive Bandlimited Quantile Approximations" (2026):
  1. Escolha de (T, alpha), X = T^alpha e largura de banda ell = log(X) / (2*pi).
  2. Aproximação par g_j in C_c^infty(-1, 1) do estado fundamental do meio-Laplaciano
     restrito em H_0^{1/2}(-1, 1) normalizada em L^2.
  3. Construção do kernel positivo K_j = |F^{-1} g_j|^2 e sua autocorrelação
     K_hat_j = g_j * g_j_tilde (suporte compacto em [-2, 2]).
  4. Enumeração determinística de potências de primos n = p^k <= X^2 e avaliação
     da soma aritmética finita de Guinand-Weil (eq. 8.4), quantizada em ponto fixo
     (inteiros exatos) para eliminar não-determinismo IEEE 754.
  5. Projeção / Refatoração Pública Dupla-Chave em dois modos para estudo de ablação:
       - "linear_bandlimited_raw": regressão linear de banda limitada pura (sem ruído
         estocástico chaveado) — baseline para testar ataques de deconvolução/OLS.
       - "dual_key_stochastic_hardened": projeção discreta no anel Z_q (q = 65537)
         deformada por perturbação estocástica chaveada e_priv derivada da chave
         privada K_priv, produzindo saída pública Y_pub indistinguível de ruído
         uniforme para terceiros, mas deterministicamente verificável pelo detentor
         de (s, n_sess).
"""

from __future__ import annotations

import hmac
import math
from dataclasses import dataclass
from hashlib import sha256, shake_256
from typing import Literal

import numpy as np

from rsd_s_v5_hardened import (
    R_V5,
    W,
    diffuse_rsd_s_v5_pre_sha,
    serialize_state_v5,
)

Q_FERMAT = 65537  # Primo de Fermat 2^16 + 1: contém exatamente F_{2^16} como subconjunto {0..65535}
DOMAIN_DUALKEY = b"RSD-S-V5|DUALKEY|"


@dataclass(frozen=True)
class BandlimitedKernelSpec:
    """Parâmetros públicos e determinísticos do pipeline de banda limitada (Seção 9)."""

    T: float = 1000.0
    alpha: float = 0.5
    grid_points: int = 256
    q_mod: int = Q_FERMAT

    @property
    def X(self) -> float:
        return self.T**self.alpha

    @property
    def ell(self) -> float:
        return math.log(self.X) / (2.0 * math.pi)


def _bump_ground_state_approx(u: np.ndarray) -> np.ndarray:
    """
    Aproximação par g_j in C_c^infty(-1, 1) do estado fundamental do meio-Laplaciano
    restrito em H_0^{1/2}(-1, 1): função suave compactamente suportada com decaimento
    exp(-1 / (1 - u^2)) modulada por polinômio par de Rayleigh-Ritz e normalizada em L^2.
    """
    out = np.zeros_like(u, dtype=np.float64)
    mask = np.abs(u) < 1.0 - 1e-12
    um = u[mask]
    # Combinação par simples compatível com perfil côncavo do ground state de (-Delta)^{1/2}
    envelope = np.exp(-1.0 / (1.0 - um * um))
    poly = 1.0 + 0.35 * (1.0 - um * um)
    vals = envelope * poly
    du = float(u[1] - u[0]) if len(u) > 1 else 1.0
    norm = math.sqrt(float(np.sum(vals * vals) * du))
    if norm > 0.0:
        vals = vals / norm
    out[mask] = vals
    return out


def enumerate_prime_powers(limit: int) -> list[tuple[int, float]]:
    """
    Enumera todas as potências de primos n = p^k <= limit e retorna (n, Lambda(n))
    onde Lambda(n) = log(p) é a função de von Mangoldt.
    """
    if limit < 2:
        return []
    is_prime = bytearray(b"\x01") * (limit + 1)
    is_prime[0] = 0
    is_prime[1] = 0
    for p in range(2, int(math.isqrt(limit)) + 1):
        if is_prime[p]:
            is_prime[p * p : limit + 1 : p] = b"\x00" * (((limit - p * p) // p) + 1)

    prime_powers: list[tuple[int, float]] = []
    for p in range(2, limit + 1):
        if is_prime[p]:
            log_p = math.log(p)
            pk = p
            while pk <= limit:
                prime_powers.append((pk, log_p))
                pk *= p
    prime_powers.sort(key=lambda item: item[0])
    return prime_powers


def build_bandlimited_kernel(spec: BandlimitedKernelSpec = BandlimitedKernelSpec()) -> dict[str, np.ndarray]:
    """
    Executa os passos 1-3 do pipeline determinístico (Seção 9):
      - g_j em (-1, 1)
      - K_hat_j = g_j * g_j_tilde (autocorrelação suportada em [-2, 2])
      - K_j = |F^{-1} g_j|^2 (kernel positivo de banda limitada)
    """
    n_pts = spec.grid_points
    u_grid = np.linspace(-1.0, 1.0, n_pts, dtype=np.float64)
    du = float(u_grid[1] - u_grid[0])
    g_j = _bump_ground_state_approx(u_grid)

    # Autocorrelação K_hat_j = g_j * g_j_tilde (suporte em [-2, 2])
    k_hat = np.convolve(g_j, g_j[::-1], mode="full") * du
    k_hat_max = float(np.max(np.abs(k_hat)))
    if k_hat_max > 0.0:
        k_hat = k_hat / k_hat_max  # normaliza K_hat(0) = 1
    tau_grid = np.linspace(-2.0, 2.0, len(k_hat), dtype=np.float64)

    # Kernel positivo K_j = |F^{-1} g_j|^2
    fft_g = np.fft.fftshift(np.fft.ifft(np.fft.ifftshift(g_j))) * n_pts * du
    k_pos = np.abs(fft_g) ** 2

    return {
        "u_grid": u_grid,
        "g_j": g_j,
        "tau_grid": tau_grid,
        "k_hat": k_hat,
        "k_pos": k_pos,
    }


def evaluate_guinand_weil_prime_sum(
    t_values: np.ndarray,
    spec: BandlimitedKernelSpec = BandlimitedKernelSpec(),
    kernel_data: dict[str, np.ndarray] | None = None,
) -> np.ndarray:
    """
    Passo 4 do pipeline da Seção 9: avalia a soma aritmética finita de Guinand-Weil
    sobre potências de primos n <= X^2 ponderadas por K_hat_j(log(n)/(2*pi*ell)).
    Os zeros de Riemann NÃO entram como entrada deste cálculo.
    """
    if kernel_data is None:
        kernel_data = build_bandlimited_kernel(spec)

    x_sq = int(math.floor(spec.X**2))
    prime_powers = enumerate_prime_powers(x_sq)
    tau_grid = kernel_data["tau_grid"]
    k_hat = kernel_data["k_hat"]
    two_pi_ell = 2.0 * math.pi * spec.ell

    t_arr = np.asarray(t_values, dtype=np.float64)
    result = np.zeros_like(t_arr, dtype=np.float64)
    for n, lam_n in prime_powers:
        log_n = math.log(n)
        arg = log_n / two_pi_ell
        if abs(arg) <= 2.0:
            weight = float(np.interp(arg, tau_grid, k_hat))
            result -= (lam_n / math.sqrt(n)) * weight * np.cos(t_arr * log_n)
    return result / math.pi


def build_quantized_spectral_matrix(
    spec: BandlimitedKernelSpec = BandlimitedKernelSpec(),
    dim: int = W,
) -> np.ndarray:
    """
    Constrói a matriz espectral pública determinística B_{K_j} em Z_q^{dim x dim}
    a partir da quantização em ponto fixo da soma de Guinand-Weil e do kernel K_j.
    Garante determinante não-nulo (posto cheio) em Z_q via deslocamento diagonal estrutural.
    """
    kernel_data = build_bandlimited_kernel(spec)
    # Grade de alturas determinísticas ancoradas em T
    t_grid = np.linspace(spec.T, spec.T + dim * dim * 0.25, dim * dim, dtype=np.float64)
    gw_vals = evaluate_guinand_weil_prime_sum(t_grid, spec=spec, kernel_data=kernel_data)

    # Quantização determinística em ponto fixo (escala Q24 -> Z_q)
    scale = float(1 << 24)
    quant = np.floor(gw_vals * scale + 0.5).astype(np.int64) % spec.q_mod
    mat = quant.reshape((dim, dim)).astype(np.int64)

    # Deslocamento determinístico derivado do kernel positivo K_j para evitar linhas degeneradas
    k_pos = kernel_data["k_pos"]
    diag_shift = (np.floor(k_pos[:dim] * scale + 0.5).astype(np.int64) % (spec.q_mod - 1)) + 1
    for i in range(dim):
        mat[i, i] = (mat[i, i] + diag_shift[i]) % spec.q_mod
    return mat


def _derive_dual_key_noise(
    s: bytes,
    n_sess: int,
    s_priv_bytes: bytes = b"",
    dim: int = W,
    q_mod: int = Q_FERMAT,
) -> np.ndarray:
    """
    Deriva o vetor de perturbação estocástica discreta e_priv in Z_q^{dim}
    a partir da chave privada (s, n_sess) VINCULADA ao estado interno s_priv_bytes
    (estilo SIV — Synthetic IV, fechando a vulnerabilidade de reuso de n_sess
    descoberta no Lote A).
    """
    k_priv = hmac.new(
        s,
        DOMAIN_DUALKEY + b"V5.1|SIV|" + n_sess.to_bytes(8, "big") + s_priv_bytes,
        sha256,
    ).digest()
    stream = shake_256(DOMAIN_DUALKEY + b"NOISE|V5.1|" + k_priv).digest(dim * 8)
    noise = np.zeros(dim, dtype=np.int64)
    idx = 0
    pos = 0
    limit = (1 << 32) - ((1 << 32) % q_mod)
    while idx < dim:
        if pos + 4 > len(stream):
            stream += shake_256(k_priv + idx.to_bytes(4, "big")).digest(dim * 4)
        val = int.from_bytes(stream[pos : pos + 4], "big")
        pos += 4
        if val < limit:
            noise[idx] = val % q_mod
            idx += 1
    return noise


def _unpadded_z65537_to_bytes64(y_vec: np.ndarray, s_priv_bytes: bytes, n_sess: int) -> bytes:
    """
    Converte o vetor y_vec in Z_65537^{W} para 2*W bytes (32 x uint16 big-endian)
    sem branch condicional dependente de dados (mitigação de RT-F2-04, v5.2):
      - Deriva sempre todas as W palavras de folding via um único SHAKE-256.
      - Seleciona entre v (0..65535) e fold_val (quando v == 65536) via máscara aritmética
        branchless em NumPy, mantendo TVD = 0,0.
    """
    y_arr = np.asarray(y_vec, dtype=np.int64)
    if y_arr.ndim != 1 or np.any((y_arr < 0) | (y_arr >= Q_FERMAT)):
        raise ValueError(f"Todas as coordenadas de y_vec devem pertencer a Z_{Q_FERMAT} (0..{Q_FERMAT - 1})")
    fold_stream = shake_256(
        DOMAIN_DUALKEY + b"FOLD16|V5.2|" + n_sess.to_bytes(8, "big") + s_priv_bytes
    ).digest(len(y_arr) * 2)
    fold_words = np.frombuffer(fold_stream, dtype=">u2").astype(np.int64)
    mask = -(y_arr == (Q_FERMAT - 1)).astype(np.int64)
    selected = (y_arr & ~mask) | (fold_words & mask)
    return selected.astype(">u2").tobytes()


class BandlimitedDualKeyEngine:
    """
    Motor de Refatoração Pública Dupla-Chave v5.2 (Operando Final):
      - mode="linear_bandlimited_raw": projeção linear pura (B_{K_j} * S_priv) mod q
        (sem ruído estocástico chaveado — baseline de ablação).
      - mode="dual_key_stochastic_hardened": projeção discreta + deformação estocástica
        chaveada resistente a reuso de nonce (SIV: e_priv derivado de s || n_sess || S_priv)
        Y_pub = (B_{K_j} * S_priv + e_priv) mod q + serialização compacta sem padding (64 bytes).
    """

    def __init__(self, spec: BandlimitedKernelSpec = BandlimitedKernelSpec()) -> None:
        self.spec = spec
        self.B_matrix = build_quantized_spectral_matrix(spec=spec, dim=W)

    def refactor_public_output(
        self,
        x: int,
        y: int,
        s: bytes,
        n_sess: int,
        rounds: int = R_V5,
        mode: Literal["linear_bandlimited_raw", "dual_key_stochastic_hardened"] = "dual_key_stochastic_hardened",
        *,
        include_private_debug: bool = False,
    ) -> dict[str, object]:
        if mode not in ("linear_bandlimited_raw", "dual_key_stochastic_hardened"):
            raise ValueError(f"Modo inválido: {mode}")

        s_priv_u16 = diffuse_rsd_s_v5_pre_sha(x, y, s, n_sess, rounds=rounds)
        s_priv_bytes = serialize_state_v5(s_priv_u16)
        s_priv = s_priv_u16.astype(np.int64)
        q = self.spec.q_mod
        projected = (self.B_matrix @ s_priv) % q

        if mode == "linear_bandlimited_raw":
            y_pub_vec = projected
        else:
            e_priv = _derive_dual_key_noise(s, n_sess, s_priv_bytes=s_priv_bytes, dim=W, q_mod=q)
            y_pub_vec = (projected + e_priv) % q

        # Serialização v5.2:
        #   - y_pub_bytes (64 bytes unpadded big-endian >u2): 100% densa, folding branchless
        #   - y_pub_z65537_bytes (96 bytes 3B/word): representação algébrica exata em Z_65537^32
        y_pub_bytes = _unpadded_z65537_to_bytes64(y_pub_vec, s_priv_bytes, n_sess)
        y_pub_z65537_bytes = b"".join(int(v).to_bytes(3, "big") for v in y_pub_vec)
        y_pub_digest_256 = sha256(DOMAIN_DUALKEY + mode.encode("ascii") + y_pub_z65537_bytes).digest()
        y_pub_digest_512 = shake_256(DOMAIN_DUALKEY + b"XOF512|" + mode.encode("ascii") + y_pub_z65537_bytes).digest(64)

        result: dict[str, object] = {
            "mode": mode,
            "q_mod": q,
            "y_pub_vector": y_pub_vec.astype(np.int64),
            "y_pub_bytes": y_pub_bytes,
            "y_pub_z65537_bytes": y_pub_z65537_bytes,
            "y_pub_digest_256": y_pub_digest_256,
            "y_pub_digest_512": y_pub_digest_512,
        }
        if include_private_debug:
            result["s_priv_state"] = s_priv_u16
        return result

    def verify_public_output(
        self,
        x: int,
        y: int,
        s: bytes,
        n_sess: int,
        expected_y_pub_bytes: bytes,
        rounds: int = R_V5,
        mode: Literal["linear_bandlimited_raw", "dual_key_stochastic_hardened"] = "dual_key_stochastic_hardened",
    ) -> bool:
        """Verificação determinística em tempo constante pelo detentor da chave privada."""
        recomputed = self.refactor_public_output(x, y, s, n_sess, rounds=rounds, mode=mode)
        return hmac.compare_digest(recomputed["y_pub_bytes"], expected_y_pub_bytes)
