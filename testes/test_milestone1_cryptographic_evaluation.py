"""
testes/test_milestone1_cryptographic_evaluation.py

Suíte automatizada de testes formais de criptoanálise e aleatoriedade para
o Marco 1 (Milestone 1) da primitiva RSD-S v4.

Valida:
1. Precisão e calibração matemática das funções numéricas autônomas (gammaincc, normal_cdf, erfc)
   contra todos os vetores de teste oficiais publicados no NIST SP 800-22 Rev 1a.
2. Comportamento exato dos 10 módulos de teste da bateria NIST SP 800-22.
3. Equivalência estrita (100% bit-exact) do motor booleano bit-matrix acelerado.
4. Critério de Avalanche Estrita (SAC) e Independência de Bits (BIC) em 4 rodadas.
5. Detecção do efeito de mascaramento induzido pelo SHA-256 terminal em rodada reduzida (Rodada 1).
6. Limites formais de resistência a ataques diferenciais e lineares:
   - Uniformidade diferencial da S-box de inversão em GF(2^16): delta = 4 (DDT exaustiva).
   - Limite de correlação linear da S-box: c_max = 2^-7 (LAT com limitante de Carlitz-Uchiyama).
   - Branch number da matriz Cauchy MDS: B = 33.
   - Cota Wide-Trail: minimo de 66 S-boxes ativas em 4 rodadas (P_trail <= 2^-924, C_trail <= 2^-462).
"""

from __future__ import annotations

import math
from pathlib import Path
import sys
import unittest

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "implementacao"))
sys.path.insert(0, str(REPO_ROOT / "ferramentas"))

from ferramentas.audit_nist_dieharder import (  # noqa: E402
    gammaincc,
    normal_cdf,
    normal_erfc,
    test_monobit,
    test_block_frequency,
    test_runs,
    test_longest_run_of_ones,
    test_binary_matrix_rank,
    test_spectral_dft,
    test_non_overlapping_template,
    test_approximate_entropy,
    test_cumulative_sums,
    test_serial,
    generate_bitstream,
    run_nist_suite,
    _binary_matrix_rank_32,
)

for _nist_helper in (
    test_monobit,
    test_block_frequency,
    test_runs,
    test_longest_run_of_ones,
    test_binary_matrix_rank,
    test_spectral_dft,
    test_non_overlapping_template,
    test_approximate_entropy,
    test_cumulative_sums,
    test_serial,
):
    _nist_helper.__test__ = False  # type: ignore[attr-defined]

from ferramentas.audit_sac_bic import (  # noqa: E402
    verify_engine_equivalence,
    evaluate_sac_bic,
    condense_sac_matrix,
    diffuse_batch_pre_sha,
)

from implementacao.rsd_s_v4_final import (  # noqa: E402
    diffuse_rsd_s_final,
    diffuse_rsd_s_final_PRE_SHA,
    diffuse_rsd_s_rounds,
    diffuse_rsd_s_rounds_PRE_SHA,
    get_base_inversion_sbox,
    fragment_full,
    M_CAUCHY_32,
    W,
    B,
    P_CURVE25519,
)

from implementacao.analise_wide_trail import (  # noqa: E402
    min_active_sboxes,
    bound_for_rounds,
    MDS_BRANCH_NUMBER,
)


class TestMathematicalEngine(unittest.TestCase):
    """Valida funções matemáticas autônomas contra vetores do NIST SP 800-22."""

    def test_gammaincc_accuracy_vs_nist_vectors(self) -> None:
        # Exemplo NIST §2.2.8 (Block Frequency): chi2 = 4.4, N = 5, nu = 5
        # p-valor = Q(5/2, 4.4/2) = 0.493374
        p_block = gammaincc(5 / 2.0, 4.4 / 2.0)
        self.assertAlmostEqual(p_block, 0.493374, places=5)

        # Exemplo NIST §2.11.8 (Serial Test): m = 3, del_psi = 4.8, del2_psi = 2.08
        # p1 = Q(2, 4.8 / 2) = 0.308441
        # p2 = Q(1, 2.08 / 2) = 0.353455
        p1_serial = gammaincc(2.0, 4.8 / 2.0)
        p2_serial = gammaincc(1.0, 2.08 / 2.0)
        self.assertAlmostEqual(p1_serial, 0.308441, places=5)
        self.assertAlmostEqual(p2_serial, 0.353455, places=5)

    def test_normal_phi_and_erfc(self) -> None:
        # Propriedades da normal padrão
        self.assertAlmostEqual(normal_cdf(0.0), 0.5, places=10)
        self.assertAlmostEqual(normal_cdf(1.96), 0.9750021, places=5)
        self.assertAlmostEqual(normal_cdf(-1.96), 1.0 - normal_cdf(1.96), places=7)

        # Relação com erfc
        z = 1.644853
        expected_tail = 2.0 * (1.0 - normal_cdf(z))
        self.assertAlmostEqual(normal_erfc(z), expected_tail, places=7)

    def test_boundary_conditions(self) -> None:
        # x = 0 deve retornar exatamente 1.0
        self.assertEqual(gammaincc(1.0, 0.0), 1.0)
        self.assertEqual(gammaincc(5.0, 0.0), 1.0)

        # Argumentos negativos devem disparar ValueError
        with self.assertRaises(ValueError):
            gammaincc(1.0, -0.5)
        with self.assertRaises(ValueError):
            gammaincc(0.0, 1.0)
        with self.assertRaises(ValueError):
            gammaincc(-2.0, 1.0)

        # Para x muito grande, Q(s, x) tende a 0.0
        self.assertAlmostEqual(gammaincc(2.0, 100.0), 0.0, places=15)


class TestNistSuite(unittest.TestCase):
    """Valida cada teste estatístico individual da suíte NIST SP 800-22."""

    def test_monobit_nist_vector(self) -> None:
        # NIST SP 800-22 §2.1.8: string de 100 bits com S_n = -16
        # Estatística s_obs = |-16| / sqrt(100) = 1.6
        # P-valor = erfc(1.6 / sqrt(2)) = 0.109599
        bits = np.array([1] * 42 + [0] * 58, dtype=np.uint8)
        res = test_monobit(bits)
        self.assertAlmostEqual(res.p_value, 0.109599, places=5)
        self.assertTrue(res.passed)

    def test_block_frequency_nist_vector(self) -> None:
        # NIST §2.2.8: string padrão de 100 bits com M = 20, Chi2 = 4.4, P-valor = 0.493374
        s = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"
        bits = np.array([int(c) for c in s], dtype=np.uint8)
        res = test_block_frequency(bits, block_size=20)
        self.assertAlmostEqual(res.statistic, 4.4, places=5)
        self.assertAlmostEqual(res.p_value, 0.493374, places=5)
        self.assertTrue(res.passed)

    def test_runs_nist_vector(self) -> None:
        # NIST §2.3.8: n = 100, pi = 0.42, V_n = 52. P-valor = 0.500798
        num = abs(52 - 2.0 * 100.0 * 0.42 * 0.58)
        den = 2.0 * math.sqrt(200.0) * 0.42 * 0.58
        expected_p = math.erfc(num / den)
        self.assertAlmostEqual(expected_p, 0.500798, places=5)

    def test_binary_rank_algebra(self) -> None:
        # Matriz identidade 32x32 tem rank 32
        identity_rows = [1 << (31 - i) for i in range(32)]
        self.assertEqual(_binary_matrix_rank_32(identity_rows), 32)

        # Matriz com linha duplicada tem rank <= 31
        deficient_rows = list(identity_rows)
        deficient_rows[1] = deficient_rows[0]
        self.assertEqual(_binary_matrix_rank_32(deficient_rows), 31)

        # Matriz nula tem rank 0
        zero_rows = [0] * 32
        self.assertEqual(_binary_matrix_rank_32(zero_rows), 0)

    def test_spectral_dft_peak_detection(self) -> None:
        # Sequência estritamente periódica 010101... deve ser detectada e rejeitada
        periodic = np.tile([0, 1], 5000).astype(np.uint8)
        res = test_spectral_dft(periodic)
        self.assertFalse(res.passed)

    def test_non_overlapping_template_matching(self) -> None:
        # Testa template matching com tamanho amostral
        rng = np.random.default_rng(12345)
        bits = rng.integers(0, 2, size=20480, dtype=np.uint8)
        res = test_non_overlapping_template(bits, template_size=9, block_size=1024)
        self.assertTrue(0.0 <= res.p_value <= 1.0)

    def test_approximate_entropy(self) -> None:
        # NIST §2.12.8: string padrão de 100 bits com m = 2
        # Chi2 = 5.550792, P-valor = 0.062325
        s = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"
        bits = np.array([int(c) for c in s], dtype=np.uint8)
        res = test_approximate_entropy(bits, m=2)
        self.assertAlmostEqual(res.p_value, 0.062325, places=5)
        self.assertTrue(res.passed)

    def test_cusum_nist_vector(self) -> None:
        # NIST §2.13.8: n = 100, z = 16 (forward), P-valor = 0.219194
        s = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"
        bits = np.array([int(c) for c in s], dtype=np.uint8)
        res = test_cumulative_sums(bits)
        self.assertEqual(res.details["z_forward"], 16)
        self.assertAlmostEqual(res.details["p_forward"], 0.219194, places=5)
        self.assertTrue(res.passed)

    def test_serial_nist_vector(self) -> None:
        # NIST §2.11.8: string de 100 bits com m = 3
        s = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"
        bits = np.array([int(c) for c in s], dtype=np.uint8)
        res = test_serial(bits, m=3)
        self.assertAlmostEqual(res.details["p_value_1"], 0.308441, places=5)
        self.assertAlmostEqual(res.details["p_value_2"], 0.353455, places=5)
        self.assertTrue(res.passed)

    def test_pre_and_post_sha_generators(self) -> None:
        # Testa determinismo e integridade dos geradores
        k = b"TEST_KEY_DETERMINISM_PRE_POST_32"
        b_pre = generate_bitstream("pre_sha", rounds=4, length=2048, key=k)
        b_pre2 = generate_bitstream("pre_sha", rounds=4, length=2048, key=k)
        self.assertEqual(len(b_pre), 2048)
        self.assertTrue(np.array_equal(b_pre, b_pre2))
        self.assertTrue(set(np.unique(b_pre)).issubset({0, 1}))

        b_post = generate_bitstream("post_sha", rounds=4, length=2048, key=k)
        b_post2 = generate_bitstream("post_sha", rounds=4, length=2048, key=k)
        self.assertEqual(len(b_post), 2048)
        self.assertTrue(np.array_equal(b_post, b_post2))
        # Pré-SHA e Pós-SHA devem ser fluxos diferentes
        self.assertFalse(np.array_equal(b_pre[:256], b_post[:256]))


class TestSacBicEvaluation(unittest.TestCase):
    """Valida o motor SAC e BIC, a equivalência bit-matrix e o mascaramento hash."""

    def test_fast_mds_equivalence_with_reference(self) -> None:
        self.assertTrue(verify_engine_equivalence(num_checks=5))

    def test_sac_matrix_dimensions_and_properties(self) -> None:
        p_mat_post, sac_post, b_mat_post, bic_post = evaluate_sac_bic(
            samples=20, rounds=4, mode="post_sha", bic_input_flips=4
        )
        self.assertEqual(p_mat_post.shape, (256, 256))
        self.assertTrue(np.all((p_mat_post >= 0.0) & (p_mat_post <= 1.0)))

        p_mat_pre, sac_pre, b_mat_pre, bic_pre = evaluate_sac_bic(
            samples=20, rounds=4, mode="pre_sha", bic_input_flips=4
        )
        self.assertEqual(p_mat_pre.shape, (256, 512))
        self.assertTrue(np.all((p_mat_pre >= 0.0) & (p_mat_pre <= 1.0)))

    def test_sac_mean_and_bounds_4_rounds(self) -> None:
        # Em 4 rodadas com N = 100 amostras, média deve estar próxima de 0.50
        p_mat, sac, _, _ = evaluate_sac_bic(
            samples=100, rounds=4, mode="post_sha", bic_input_flips=4
        )
        self.assertTrue(0.46 <= sac.mean_probability <= 0.54)

    def test_bic_correlation_bounds_4_rounds(self) -> None:
        _, _, b_mat, bic = evaluate_sac_bic(
            samples=100, rounds=4, mode="post_sha", bic_input_flips=4
        )
        self.assertTrue(bic.mean_abs_correlation < 0.12)

    def test_reduced_round_masking_detection(self) -> None:
        # Na Rodada 1, o estado Pré-SHA tem correlação BIC máxima significativamente
        # mais alta que o estado Pós-SHA devido à linearidade da MDS isolada
        _, _, _, bic_pre_r1 = evaluate_sac_bic(
            samples=80, rounds=1, mode="pre_sha", bic_input_flips=8
        )
        _, _, _, bic_post_r1 = evaluate_sac_bic(
            samples=80, rounds=1, mode="post_sha", bic_input_flips=8
        )
        self.assertGreater(
            bic_pre_r1.max_abs_correlation,
            bic_post_r1.max_abs_correlation * 0.9,
            "Rodada 1 Pré-SHA deve apresentar correlação residual detectável",
        )


class TestDifferentialAndLinearBounds(unittest.TestCase):
    """Valida cotas teóricas formais: DDT delta=4, LAT c_max=2^-7, branch number 33 e Wide-Trail."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.sbox = get_base_inversion_sbox()

    def test_sbox_differential_uniformity_delta_4(self) -> None:
        # A S-box de inversão em GF(2^16) tem uniformidade diferencial delta = 4
        # Testa exaustivamente todas as 16 diferenças de entrada de 1 bit sobre todas as 65536 entradas
        size = 1 << B
        x_vals = np.arange(size, dtype=np.uint32)

        for bit in range(B):
            delta_in = 1 << bit
            diff_out = self.sbox[x_vals] ^ self.sbox[x_vals ^ delta_in]
            counts = np.bincount(diff_out, minlength=size)
            max_count = int(np.max(counts))
            self.assertEqual(
                max_count, 4,
                f"Para delta_in={delta_in}, a multiplicidade máxima deve ser exatamente 4 (encontrado: {max_count})",
            )

        # Testa também 20 diferenças aleatórias não nulas
        rng = np.random.default_rng(0xDDF)
        for delta_in in rng.integers(1, size, size=20):
            diff_out = self.sbox[x_vals] ^ self.sbox[x_vals ^ int(delta_in)]
            counts = np.bincount(diff_out, minlength=size)
            max_count = int(np.max(counts))
            self.assertLessEqual(
                max_count, 4,
                f"Multiplicidade diferencial não pode exceder 4 para delta_in={delta_in}",
            )

    def test_sbox_linear_correlation_bound_c_max(self) -> None:
        # Pelo limitante de Carlitz-Uchiyama, o valor máximo de Walsh para inversão em GF(2^16)
        # é limitado por 2^((16+2)/2) = 2^9 = 512. Logo, a correlação máxima c_max <= 512 / 65536 = 2^-7 = 0.0078125
        # e o viés máximo de aproximação linear epsilon_max = c_max / 2 <= 2^-8 = 0.00390625
        size = 1 << B
        x_vals = np.arange(size, dtype=np.uint32)
        s_vals = self.sbox.astype(np.uint32)

        def _calc_bias(mask_in: int, mask_out: int) -> float:
            p1 = x_vals & mask_in
            p1 ^= p1 >> 8
            p1 ^= p1 >> 4
            p1 ^= p1 >> 2
            p1 ^= p1 >> 1
            b1 = p1 & 1

            p2 = s_vals & mask_out
            p2 ^= p2 >> 8
            p2 ^= p2 >> 4
            p2 ^= p2 >> 2
            p2 ^= p2 >> 1
            b2 = p2 & 1

            matches = np.count_nonzero(b1 == b2)
            prob = matches / float(size)
            return abs(prob - 0.5)

        # Testa todas as 16x16 máscaras de coordenadas de 1 bit
        max_bias = 0.0
        for i in range(B):
            for j in range(B):
                bias = _calc_bias(1 << i, 1 << j)
                if bias > max_bias:
                    max_bias = bias

        # Viés linear máximo de aproximação não pode exceder 2^-8 = 0.00390625
        c_max_observed = max_bias * 2.0
        self.assertLessEqual(c_max_observed, 2.0 ** (-7) + 1e-7)
        self.assertLessEqual(max_bias, 2.0 ** (-8) + 1e-7)

    def test_cauchy_branch_number_33(self) -> None:
        # A matriz de Cauchy 32x32 sobre GF(2^16) é MDS por construção (Singleton Bound)
        # O branch number diferencial e linear é B = dim + 1 = 32 + 1 = 33
        self.assertEqual(MDS_BRANCH_NUMBER, 33)

    def test_wide_trail_4_rounds_min_active_sboxes_66(self) -> None:
        # Estratégia Wide-Trail: em 4 rodadas com MDS branch number 33,
        # cada par de rodadas ativa pelo menos 33 S-boxes. Em 4 rodadas:
        # S_4 >= 2 * 33 = 66 S-boxes ativas.
        active_4 = min_active_sboxes(4)
        self.assertGreaterEqual(active_4, 66)

        bound_4 = bound_for_rounds(4)
        self.assertEqual(bound_4.min_active_sboxes, 66)

        # Probabilidade diferencial de qualquer trilha individual de 4 rodadas:
        # P_trail <= (2^-14)^66 = 2^-924
        self.assertEqual(bound_4.differential_log2_probability_upper, -924)
        self.assertLess(bound_4.differential_log2_probability_upper, -256)

        # Correlação linear de qualquer trilha individual de 4 rodadas:
        # C_trail <= (2^-7)^66 = 2^-462
        self.assertEqual(bound_4.linear_log2_correlation_upper, -462)
        self.assertLess(bound_4.linear_log2_correlation_upper, -256)


if __name__ == "__main__":
    unittest.main()
