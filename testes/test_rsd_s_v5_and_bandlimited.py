"""Testes determinísticos de paridade Python <-> C99, Anti-DFA, S-box afim e Módulo Dupla-Chave (RSD-S v5)."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from bandlimited_dual_key import (  # noqa: E402
    BandlimitedDualKeyEngine,
    BandlimitedKernelSpec,
    build_bandlimited_kernel,
    enumerate_prime_powers,
)
from rsd_s_v5_hardened import (  # noqa: E402
    P_CURVE25519,
    FaultDetectedError,
    diffuse_rsd_s_v5,
    diffuse_rsd_s_v5_pre_sha,
    run_c_core_pre_sha,
    sbox_v5_eval,
)


class TestRsdSV5CoreAndC99Parity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.so_path = Path(cls._tmpdir.name) / "lib_rsd_s_v5.so"
        c_src = ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"
        subprocess.run(
            ["gcc", "-O3", "-mavx2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(c_src), "-o", str(cls.so_path)],
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmpdir.cleanup()

    def test_sbox_v5_bijection_and_zero_fixed_points(self) -> None:
        seen = set()
        fp = 0
        ofp = 0
        for u in range(65536):
            y = sbox_v5_eval(u)
            seen.add(y)
            if y == u:
                fp += 1
            if y == (u ^ 0xFFFF):
                ofp += 1
        self.assertEqual(len(seen), 65536)
        self.assertEqual(fp, 0)
        self.assertEqual(ofp, 0)

    def test_exact_bit_for_bit_parity_python_vs_c99(self) -> None:
        cases = [
            (0, 0, bytes(32), 0),
            (1, 2, bytes(range(32)), 1),
            (1 << 254, 1 << 253, b"\xff" * 32, (1 << 64) - 1),
            (P_CURVE25519 - 1, P_CURVE25519 - 2, bytes.fromhex("00112233445566778899aabbccddeeff" * 2), 42),
        ]
        for x, y, s, n_sess in cases:
            with self.subTest(x=x, n_sess=n_sess):
                py_state = diffuse_rsd_s_v5_pre_sha(x, y, s, n_sess)
                rc, c_state = run_c_core_pre_sha(self.so_path, x, y, s, n_sess)
                self.assertEqual(rc, 0)
                np.testing.assert_array_equal(py_state, c_state)

    def test_anti_dfa_blocks_fault_injection_in_python_and_c99(self) -> None:
        key = bytes(range(32))

        def inject(st: np.ndarray) -> np.ndarray:
            st = st.copy()
            st[7] ^= np.uint16(0x0001)
            return st

        with self.assertRaises(FaultDetectedError):
            diffuse_rsd_s_v5_pre_sha(123, 456, key, 9, fault_injector=inject)

        rc, out_c = run_c_core_pre_sha(
            self.so_path, 123, 456, key, 9, inject_fault_word=7, inject_fault_mask=0x0001
        )
        self.assertEqual(rc, -2)
        self.assertTrue(np.all(out_c == 0))

    def test_c99_secure_memory_wipe(self) -> None:
        lib = ctypes.CDLL(str(self.so_path))
        lib.rsd_s_v5_verify_wipe_ct.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.rsd_s_v5_verify_wipe_ct.restype = ctypes.c_int
        buf = ctypes.create_string_buffer(b"\xAA" * 64, 64)
        rc = lib.rsd_s_v5_verify_wipe_ct(buf, 64)
        self.assertEqual(rc, 0)
        self.assertEqual(buf.raw, b"\x00" * 64)

    def test_v5_256_and_512_bit_outputs_are_distinct_and_deterministic(self) -> None:
        key = bytes(range(32))
        d256_a = diffuse_rsd_s_v5(10, 20, key, 5, output_bytes=32)
        d256_b = diffuse_rsd_s_v5(10, 20, key, 5, output_bytes=32)
        d512 = diffuse_rsd_s_v5(10, 20, key, 5, output_bytes=64)
        self.assertEqual(len(d256_a), 32)
        self.assertEqual(len(d512), 64)
        self.assertEqual(d256_a, d256_b)
        self.assertNotEqual(d256_a, d512[:32])

    def test_v51_cauchy_mds_breaks_scalar_involution_m2_invariant(self) -> None:
        from mds_real import GF16_POLY, gf_mult
        from rsd_s_v5_hardened import M_CAUCHY_32, W

        m2 = np.zeros((W, W), dtype=np.uint32)
        for i in range(W):
            for j in range(W):
                acc = 0
                for k in range(W):
                    acc ^= gf_mult(int(M_CAUCHY_32[i, k]), int(M_CAUCHY_32[k, j]), GF16_POLY, 16)
                m2[i, j] = acc
        off_diag = m2.copy()
        np.fill_diagonal(off_diag, 0)
        self.assertEqual(int(np.count_nonzero(off_diag)), W * (W - 1))


class TestBandlimitedDualKeyModule(unittest.TestCase):
    def test_bandlimited_kernel_positivity_and_prime_powers(self) -> None:
        spec = BandlimitedKernelSpec(T=500.0, alpha=0.5, grid_points=128)
        kdata = build_bandlimited_kernel(spec)
        self.assertTrue(np.all(kdata["k_pos"] >= 0.0))
        self.assertAlmostEqual(float(np.max(kdata["k_hat"])), 1.0, places=6)
        pp = enumerate_prime_powers(20)
        ns = [n for n, _ in pp]
        self.assertEqual(ns, [2, 3, 4, 5, 7, 8, 9, 11, 13, 16, 17, 19])

    def test_dual_key_refactoring_and_verification(self) -> None:
        engine = BandlimitedDualKeyEngine(BandlimitedKernelSpec(T=500.0, alpha=0.5, grid_points=128))
        key = bytes(range(32))
        wrong_key = bytes(reversed(range(32)))

        res_raw = engine.refactor_public_output(11, 22, key, 7, mode="linear_bandlimited_raw")
        res_hard = engine.refactor_public_output(11, 22, key, 7, mode="dual_key_stochastic_hardened")

        self.assertEqual(len(res_hard["y_pub_bytes"]), 64)
        self.assertNotEqual(res_raw["y_pub_bytes"], res_hard["y_pub_bytes"])
        self.assertTrue(
            engine.verify_public_output(11, 22, key, 7, res_hard["y_pub_bytes"], mode="dual_key_stochastic_hardened")
        )
        self.assertFalse(
            engine.verify_public_output(
                11, 22, wrong_key, 7, res_hard["y_pub_bytes"], mode="dual_key_stochastic_hardened"
            )
        )

    def test_v51_siv_nonce_reuse_blocks_delta_s_priv_recovery(self) -> None:
        engine = BandlimitedDualKeyEngine(BandlimitedKernelSpec(T=500.0, alpha=0.5, grid_points=128))
        key = bytes(range(32))
        q = engine.spec.q_mod
        # Reutilizar o mesmo n_sess=77 para dois pares (x, y) distintos:
        r1 = engine.refactor_public_output(100, 200, key, 77, mode="dual_key_stochastic_hardened", include_private_debug=True)
        r2 = engine.refactor_public_output(101, 200, key, 77, mode="dual_key_stochastic_hardened", include_private_debug=True)
        delta_y = (r1["y_pub_vector"] - r2["y_pub_vector"]) % q
        expected_linear_delta = (engine.B_matrix @ ((r1["s_priv_state"].astype(np.int64) - r2["s_priv_state"].astype(np.int64)) % q)) % q
        # Com SIV (e_priv vinculado a S_priv), e_priv^(1) != e_priv^(2), impedindo o cancelamento!
        self.assertFalse(np.array_equal(delta_y, expected_linear_delta))


if __name__ == "__main__":
    unittest.main()
