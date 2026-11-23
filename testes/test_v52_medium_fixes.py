"""
Regressão determinística dos 3 achados de severidade Média da R5 (v5.2):
  - RT-F1-01: Derivação completa de todos os blocos (block_idx = 0, 1, ...) em
              expand_key_words_v5 via HMAC-SHA256 com separação de domínio,
              eliminando a exposição literal de keys[r] em rk[r][0..15] e
              mantendo paridade bit-a-bit exata Python <-> C99.
  - RT-F2-03: Omissão de "s_priv_state" do retorno público padrão de
              BandlimitedDualKeyEngine.refactor_public_output, expondo-o
              apenas mediante flag keyword-only include_private_debug=True.
  - RT-F2-04: Folding branchless vetorizado em _unpadded_z65537_to_bytes64 via
              SHAKE-256 único ("FOLD16|V5.2|") + máscara aritmética NumPy +
              validação explícita de faixa [0, 65536].
"""
from __future__ import annotations

import ast
import hmac
import inspect
import subprocess
import sys
import tempfile
import textwrap
import unittest
from hashlib import sha256, shake_256
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from bandlimited_dual_key import (  # noqa: E402
    DOMAIN_DUALKEY,
    Q_FERMAT,
    BandlimitedDualKeyEngine,
    BandlimitedKernelSpec,
    _unpadded_z65537_to_bytes64,
)
from rsd_s_v5_hardened import (  # noqa: E402
    R_V5,
    W,
    derive_keys_v5,
    diffuse_rsd_s_v5_pre_sha,
    expand_key_words_v5,
    run_c_core_pre_sha,
)

C_SRC = ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"


class TestV52MediumSecurityFixes(unittest.TestCase):
    """Valida as mitigações de RT-F1-01, RT-F2-03 e RT-F2-04 (stdlib unittest + numpy)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="rsd_v52_med_")
        cls.tmp = Path(cls._tmpdir.name)
        cls.so_path = cls.tmp / "lib_rsd_s_v52_med.so"
        subprocess.run(
            [
                "gcc",
                "-O3",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                str(C_SRC),
                "-o",
                str(cls.so_path),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmpdir.cleanup()

    # ------------------------------------------------------------------
    # RT-F1-01: Key Schedule (expand_key_words_v5)
    # ------------------------------------------------------------------
    def test_rt_f1_01_key_expansion_hides_key_r_and_blocks_second_half_forgery(self) -> None:
        """rk[r][0..15] não pode expor keys[r] nem permitir forjar rk[r][16..31]."""
        s = b"\x33" * 32
        keys = derive_keys_v5(s, n_sess=0, rounds=R_V5)
        for r_idx, key_r in enumerate(keys):
            with self.subTest(round_idx=r_idx):
                rk_r = expand_key_words_v5(key_r, W)
                self.assertEqual(rk_r.dtype, np.uint16)
                self.assertEqual(len(rk_r), W)

                first_half_bytes = b"".join(int(w).to_bytes(2, "big") for w in rk_r[:16])
                self.assertNotEqual(first_half_bytes, key_r)

                # Tentativa de reconstruir rk[r][16..31] usando rk[r][0..15] como chave HMAC deve falhar
                forged_second = hmac.new(
                    first_half_bytes, b"EXP|" + (1).to_bytes(4, "big"), sha256
                ).digest()
                forged_words = np.frombuffer(forged_second, dtype=">u2").astype(np.uint16)
                self.assertFalse(np.array_equal(forged_words, rk_r[16:32]))

                # Derivação canônica v5.2 via block_idx = 0 e 1
                expected_b0 = hmac.new(key_r, b"EXP|" + (0).to_bytes(4, "big"), sha256).digest()
                expected_b1 = hmac.new(key_r, b"EXP|" + (1).to_bytes(4, "big"), sha256).digest()
                expected_all = np.frombuffer(expected_b0 + expected_b1, dtype=">u2").astype(np.uint16)
                self.assertTrue(np.array_equal(rk_r, expected_all))

    def test_rt_f1_01_multi_block_expansion_and_input_validation(self) -> None:
        """Valida block_idx = 0, 1, 2 para n_words = 16, 32, 48 e rejeição de n_words inválido."""
        key_r = bytes(range(32))
        b0 = hmac.new(key_r, b"EXP|" + (0).to_bytes(4, "big"), sha256).digest()
        b1 = hmac.new(key_r, b"EXP|" + (1).to_bytes(4, "big"), sha256).digest()
        b2 = hmac.new(key_r, b"EXP|" + (2).to_bytes(4, "big"), sha256).digest()

        w16 = expand_key_words_v5(key_r, 16)
        w32 = expand_key_words_v5(key_r, 32)
        w48 = expand_key_words_v5(key_r, 48)

        self.assertTrue(np.array_equal(w16, np.frombuffer(b0, dtype=">u2").astype(np.uint16)))
        self.assertTrue(np.array_equal(w32, np.frombuffer(b0 + b1, dtype=">u2").astype(np.uint16)))
        self.assertTrue(np.array_equal(w48, np.frombuffer(b0 + b1 + b2, dtype=">u2").astype(np.uint16)))

        for bad_n in (0, -1, -32, True, False):
            with self.subTest(bad_n=bad_n):
                with self.assertRaises(ValueError):
                    expand_key_words_v5(key_r, bad_n)  # type: ignore[arg-type]

    def test_rt_f1_01_python_c99_bit_exact_parity(self) -> None:
        """Paridade bit-a-bit exata entre diffuse_rsd_s_v5_pre_sha e run_c_core_pre_sha."""
        test_cases = [
            (0, 0, b"\x00" * 32, 0),
            (0x123456789ABCDEF0, 0xFEDCBA9876543210, bytes(range(32)), 4242),
            (2**255 - 20, 2**128 + 7, b"\xA5" * 32, 2**64 - 1),
        ]
        for x, y, s, n_sess in test_cases:
            with self.subTest(n_sess=n_sess):
                py_state = diffuse_rsd_s_v5_pre_sha(x, y, s, n_sess, rounds=R_V5)
                rc, c_state = run_c_core_pre_sha(self.so_path, x, y, s, n_sess, rounds=R_V5)
                self.assertEqual(rc, 0)
                self.assertTrue(np.array_equal(py_state, c_state))

    # ------------------------------------------------------------------
    # RT-F2-03: API Exposure (BandlimitedDualKeyEngine.refactor_public_output)
    # ------------------------------------------------------------------
    def test_rt_f2_03_s_priv_state_omitted_by_default_and_opt_in_debug(self) -> None:
        """refactor_public_output não expõe s_priv_state por padrão em nenhum modo."""
        engine = BandlimitedDualKeyEngine(BandlimitedKernelSpec(T=500.0, alpha=0.5, grid_points=128))
        key = bytes(range(32))
        wrong_key = bytes(reversed(range(32)))
        x, y, n_sess = 12345, 67890, 99

        expected_s_priv = diffuse_rsd_s_v5_pre_sha(x, y, key, n_sess, rounds=R_V5)

        for mode in ("dual_key_stochastic_hardened", "linear_bandlimited_raw"):
            with self.subTest(mode=mode):
                pub = engine.refactor_public_output(x, y, key, n_sess, mode=mode)
                self.assertNotIn("s_priv_state", pub)
                self.assertEqual(len(pub["y_pub_bytes"]), 64)

                # verify_public_output continua funcionando sem alteração de assinatura
                self.assertTrue(
                    engine.verify_public_output(x, y, key, n_sess, pub["y_pub_bytes"], mode=mode)
                )
                self.assertFalse(
                    engine.verify_public_output(x, y, wrong_key, n_sess, pub["y_pub_bytes"], mode=mode)
                )

                # Flag keyword-only include_private_debug=True expõe o estado esperado
                dbg = engine.refactor_public_output(
                    x, y, key, n_sess, mode=mode, include_private_debug=True
                )
                self.assertIn("s_priv_state", dbg)
                self.assertTrue(np.array_equal(dbg["s_priv_state"], expected_s_priv))
                self.assertEqual(dbg["y_pub_bytes"], pub["y_pub_bytes"])

        # include_private_debug deve ser estritamente keyword-only
        with self.assertRaises(TypeError):
            engine.refactor_public_output(x, y, key, n_sess, R_V5, "dual_key_stochastic_hardened", True)  # type: ignore[misc]

    # ------------------------------------------------------------------
    # RT-F2-04: Branchless Folding (_unpadded_z65537_to_bytes64)
    # ------------------------------------------------------------------
    def test_rt_f2_04_folding_determinism_preservation_and_boundary_mapping(self) -> None:
        """Valida determinismo, preservação de 0..65535, folding V5.2 de 65536 e rejeição fora da faixa."""
        s_priv_bytes = bytes(range(64))
        n_sess = 20261122
        vec = np.array([0, 1, 255, 256, 32768, 65535, 65536] + [i * 1000 for i in range(25)], dtype=np.int64)
        vec[31] = 65536

        out1 = _unpadded_z65537_to_bytes64(vec, s_priv_bytes, n_sess)
        out2 = _unpadded_z65537_to_bytes64(vec, s_priv_bytes, n_sess)
        self.assertEqual(out1, out2)
        self.assertEqual(len(out1), 64)

        words = np.frombuffer(out1, dtype=">u2")
        self.assertEqual(int(words[0]), 0)
        self.assertEqual(int(words[1]), 1)
        self.assertEqual(int(words[2]), 255)
        self.assertEqual(int(words[3]), 256)
        self.assertEqual(int(words[4]), 32768)
        self.assertEqual(int(words[5]), 65535)

        expected_stream = shake_256(
            DOMAIN_DUALKEY + b"FOLD16|V5.2|" + n_sess.to_bytes(8, "big") + s_priv_bytes
        ).digest(64)
        expected_fold_words = np.frombuffer(expected_stream, dtype=">u2")
        self.assertEqual(int(words[6]), int(expected_fold_words[6]))
        self.assertEqual(int(words[31]), int(expected_fold_words[31]))

        # Entradas fora de Z_65537 ou não-1D devem levantar ValueError
        neg_vec = np.zeros(W, dtype=np.int64)
        neg_vec[0] = -1
        with self.assertRaises(ValueError):
            _unpadded_z65537_to_bytes64(neg_vec, s_priv_bytes, n_sess)

        over_vec = np.zeros(W, dtype=np.int64)
        over_vec[0] = Q_FERMAT
        with self.assertRaises(ValueError):
            _unpadded_z65537_to_bytes64(over_vec, s_priv_bytes, n_sess)

        vec_2d = np.zeros((2, 16), dtype=np.int64)
        with self.assertRaises(ValueError):
            _unpadded_z65537_to_bytes64(vec_2d, s_priv_bytes, n_sess)

    def test_rt_f2_04_folding_source_is_branchless_on_coordinate_values(self) -> None:
        """Verifica via AST que _unpadded_z65537_to_bytes64 não tem ramo condicional nem laço sobre coordenadas."""
        src = textwrap.dedent(inspect.getsource(_unpadded_z65537_to_bytes64))
        tree = ast.parse(src)
        func_def = tree.body[0]
        assert isinstance(func_def, ast.FunctionDef)

        if_nodes = [n for n in ast.walk(func_def) if isinstance(n, ast.If)]
        ifexp_nodes = [n for n in ast.walk(func_def) if isinstance(n, ast.IfExp)]
        loop_nodes = [n for n in ast.walk(func_def) if isinstance(n, (ast.For, ast.While))]

        # Deve existir apenas 1 `if` (a validação inicial de faixa que levanta ValueError),
        # e nenhum `for`/`while`/`IfExp` sobre valores de coordenadas.
        self.assertEqual(len(if_nodes), 1, "Apenas o guard de validação de faixa é permitido")
        self.assertTrue(
            len(if_nodes[0].body) == 1 and isinstance(if_nodes[0].body[0], ast.Raise),
            "O único if em _unpadded_z65537_to_bytes64 deve ser a validação de faixa com raise ValueError",
        )
        self.assertEqual(len(ifexp_nodes), 0)
        self.assertEqual(len(loop_nodes), 0)


if __name__ == "__main__":
    unittest.main()
