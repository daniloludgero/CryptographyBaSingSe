"""Tier 1: Feature Coverage Test Suite for RSD-S v4.

Covers functional requirements across 9 core features:
1. Core PRF Compression Function
2. Pre-SHA Internal State Inspector
3. Configurable Round Scaling
4. Input Domain Validation
5. Word Decomposition & Slicing
6. Key Schedule & Round Constants
7. Galois Field Arithmetic & S-box
8. Cauchy MDS Diffusion Matrix
9. CLI Diagnostic & Verification Utility

Target: >= 45 tests (designed: 46 tests).
Zero-mock, 100% genuine implementation.
"""

from __future__ import annotations

import contextlib
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))
sys.path.insert(0, str(ROOT / "ferramentas"))

from mds_real import build_cauchy_mds, gf_add, gf_inv, gf_mult
import rsd_cli
from rsd_s_v4_final import (
    KEY_SIZE,
    MAX_ROUNDS,
    MAX_SESSION,
    P_CURVE25519,
    R,
    W,
    _expand_key_words,
    derive_keys,
    diffuse_rsd_s_final,
    diffuse_rsd_s_final_PRE_SHA,
    diffuse_rsd_s_rounds,
    diffuse_rsd_s_rounds_PRE_SHA,
    fragment_full,
    get_base_inversion_sbox,
    gf_matrix_vector_mult,
    round_constant,
    validate_inputs,
)


def run_cli(args: list[str]) -> tuple[int, str, str]:
    """Execute CLI in-process without mocks, capturing stdout and stderr."""
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
        code = rsd_cli.main(args)
    return code, out_buf.getvalue(), err_buf.getvalue()


class BaseE2ETestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Precompute & cache S-box globally to maximize test speed
        get_base_inversion_sbox()


class TestTier1CorePrf(BaseE2ETestCase):
    """Feature 1: Core PRF Compression Function Tests."""

    def test_f1_01_output_type_and_length(self) -> None:
        out = diffuse_rsd_s_final(1, 2, bytes(32), 0)
        self.assertIsInstance(out, bytes)
        self.assertEqual(len(out), 32)

    def test_f1_02_deterministic_repeatability(self) -> None:
        x = 0x123456789ABCDEF0
        y = 0xFEDCBA9876543210
        s = b"\x42" * 32
        n = 12345
        out1 = diffuse_rsd_s_final(x, y, s, n)
        out2 = diffuse_rsd_s_final(x, y, s, n)
        self.assertEqual(out1, out2)

    def test_f1_03_known_answer_tests_all_vectors(self) -> None:
        vector_path = ROOT / "testes" / "vetores_v4.json"
        vectors = json.loads(vector_path.read_text(encoding="utf-8"))
        self.assertEqual(len(vectors), 4)
        for vec in vectors:
            out = diffuse_rsd_s_final(
                int(vec["x"]),
                int(vec["y"]),
                bytes.fromhex(vec["s_hex"]),
                int(vec["n_sess"]),
            )
            self.assertEqual(out.hex(), vec["output_hex"])

    def test_f1_04_master_key_sensitivity(self) -> None:
        s0 = b"\x00" * 32
        s1 = b"\x01" + b"\x00" * 31
        x, y, n = 100, 200, 0
        out0 = diffuse_rsd_s_final(x, y, s0, n)
        out1 = diffuse_rsd_s_final(x, y, s1, n)
        self.assertNotEqual(out0, out1)
        dist = sum((a ^ b).bit_count() for a, b in zip(out0, out1))
        self.assertGreaterEqual(dist, 90)

    def test_f1_05_session_nonce_sensitivity(self) -> None:
        n0 = 0
        n1 = 1
        s = b"\x55" * 32
        x, y = 42, 84
        out0 = diffuse_rsd_s_final(x, y, s, n0)
        out1 = diffuse_rsd_s_final(x, y, s, n1)
        self.assertNotEqual(out0, out1)
        dist = sum((a ^ b).bit_count() for a, b in zip(out0, out1))
        self.assertGreaterEqual(dist, 90)

    def test_f1_06_independent_scalar_sensitivity(self) -> None:
        x, y = 123456789, 987654321
        s = b"\x33" * 32
        n = 7
        out_base = diffuse_rsd_s_final(x, y, s, n)
        out_x_flip = diffuse_rsd_s_final(x ^ 1, y, s, n)
        out_y_flip = diffuse_rsd_s_final(x, y ^ 1, s, n)
        self.assertNotEqual(out_base, out_x_flip)
        self.assertNotEqual(out_base, out_y_flip)
        self.assertNotEqual(out_x_flip, out_y_flip)


class TestTier1PreShaInspector(BaseE2ETestCase):
    """Feature 2: Pre-SHA Internal State Inspector Tests."""

    def test_f2_01_output_shape_and_dtype(self) -> None:
        state = diffuse_rsd_s_final_PRE_SHA(1, 2, bytes(32), 0)
        self.assertIsInstance(state, np.ndarray)
        self.assertEqual(state.shape, (32,))
        self.assertTrue(all(0 <= int(w) <= 0xFFFF for w in state))

    def test_f2_02_terminal_sha256_hash_parity(self) -> None:
        x, y = 0xABCDEF, 0x123456
        s = b"\x77" * 32
        n = 99
        state = diffuse_rsd_s_final_PRE_SHA(x, y, s, n)
        z_bytes = b"".join(int(w).to_bytes(2, "big") for w in state)
        expected_digest = sha256(z_bytes).digest()
        actual_digest = diffuse_rsd_s_final(x, y, s, n)
        self.assertEqual(expected_digest, actual_digest)

    def test_f2_03_pre_sha_determinism(self) -> None:
        st1 = diffuse_rsd_s_final_PRE_SHA(10, 20, b"\x11" * 32, 5)
        st2 = diffuse_rsd_s_final_PRE_SHA(10, 20, b"\x11" * 32, 5)
        self.assertTrue(np.array_equal(st1, st2))

    def test_f2_04_multi_round_pre_sha_divergence(self) -> None:
        x, y = 111, 222
        s = b"\x22" * 32
        n = 3
        states = [diffuse_rsd_s_rounds_PRE_SHA(x, y, s, n, r) for r in (1, 2, 3, 4)]
        for i in range(len(states)):
            for j in range(i + 1, len(states)):
                self.assertFalse(np.array_equal(states[i], states[j]))

    def test_f2_05_non_trivial_state_under_zero_inputs(self) -> None:
        state = diffuse_rsd_s_final_PRE_SHA(0, 0, bytes(32), 0)
        nonzero_count = int(np.count_nonzero(state))
        self.assertGreater(nonzero_count, 28)


class TestTier1ConfigurableRounds(BaseE2ETestCase):
    """Feature 3: Configurable Round Scaling Tests."""

    def test_f3_01_round_4_equals_final_api(self) -> None:
        x, y = 0x987, 0x654
        s = b"\x88" * 32
        n = 12
        out_final = diffuse_rsd_s_final(x, y, s, n)
        out_rounds4 = diffuse_rsd_s_rounds(x, y, s, n, rounds=4)
        self.assertEqual(out_final, out_rounds4)

    def test_f3_02_single_round_execution(self) -> None:
        out1 = diffuse_rsd_s_rounds(1, 2, bytes(32), 0, rounds=1)
        self.assertIsInstance(out1, bytes)
        self.assertEqual(len(out1), 32)

    def test_f3_03_scaling_round_monotonic_diversity(self) -> None:
        x, y = 55, 66
        s = b"\x99" * 32
        n = 1
        outputs = [diffuse_rsd_s_rounds(x, y, s, n, r) for r in (1, 2, 3, 4, 5)]
        self.assertEqual(len(set(outputs)), 5)

    def test_f3_04_pre_sha_rounds_parity(self) -> None:
        x, y = 77, 88
        s = b"\xAB" * 32
        n = 9
        st1 = diffuse_rsd_s_rounds_PRE_SHA(x, y, s, n, 4)
        st2 = diffuse_rsd_s_final_PRE_SHA(x, y, s, n)
        self.assertTrue(np.array_equal(st1, st2))

    def test_f3_05_high_round_support(self) -> None:
        out8 = diffuse_rsd_s_rounds(1, 1, bytes(32), 0, rounds=8)
        self.assertIsInstance(out8, bytes)
        self.assertEqual(len(out8), 32)


class TestTier1InputValidation(BaseE2ETestCase):
    """Feature 4: Input Validation Contracts Tests."""

    def test_f4_01_valid_inputs_pass(self) -> None:
        self.assertIsNone(validate_inputs(0, 0, bytes(32), 0))

    def test_f4_02_field_element_type_error(self) -> None:
        for bad in (True, False, 1.5, "10"):
            with self.assertRaises(TypeError):
                validate_inputs(bad, 0, bytes(32), 0)
            with self.assertRaises(TypeError):
                validate_inputs(0, bad, bytes(32), 0)

    def test_f4_03_field_element_value_error(self) -> None:
        for bad in (-1, P_CURVE25519, P_CURVE25519 + 1):
            with self.assertRaises(ValueError):
                validate_inputs(bad, 0, bytes(32), 0)
            with self.assertRaises(ValueError):
                validate_inputs(0, bad, bytes(32), 0)

    def test_f4_04_key_validation(self) -> None:
        for bad_type in (bytearray(32), "0" * 32, 12345):
            with self.assertRaises(TypeError):
                validate_inputs(0, 0, bad_type, 0)  # type: ignore[arg-type]
        for bad_len in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                validate_inputs(0, 0, bad_len, 0)

    def test_f4_05_session_validation(self) -> None:
        for bad_type in (True, False, 1.0, "0"):
            with self.assertRaises(TypeError):
                validate_inputs(0, 0, bytes(32), bad_type)  # type: ignore[arg-type]
        for bad_val in (-1, MAX_SESSION + 1):
            with self.assertRaises(ValueError):
                validate_inputs(0, 0, bytes(32), bad_val)


class TestTier1WordSlicing(BaseE2ETestCase):
    """Feature 5: Word Decomposition & Slicing Tests."""

    def test_f5_01_output_dimension_and_range(self) -> None:
        arr = fragment_full(12345, 67890)
        self.assertEqual(len(arr), 32)
        self.assertTrue(all(0 <= int(w) <= 0xFFFF for w in arr))

    def test_f5_02_exact_reconstruction(self) -> None:
        x = 0x1234567890ABCDEF1234567890ABCDEF
        y = 0xFEDCBA0987654321FEDCBA0987654321
        arr = fragment_full(x, y)
        rec_x = sum(int(arr[j]) << (16 * j) for j in range(16))
        rec_y = sum(int(arr[16 + j]) << (16 * j) for j in range(16))
        self.assertEqual(rec_x, x)
        self.assertEqual(rec_y, y)

    def test_f5_03_independent_x_y_assignment(self) -> None:
        arr1 = fragment_full(100, 500)
        arr2 = fragment_full(200, 500)
        self.assertFalse(np.array_equal(arr1[:16], arr2[:16]))
        self.assertTrue(np.array_equal(arr1[16:], arr2[16:]))

    def test_f5_04_high_bit_coverage(self) -> None:
        x_high = 1 << 200
        arr = fragment_full(x_high, 0)
        word_idx = 200 // 16  # 12
        bit_in_word = 200 % 16  # 8
        self.assertEqual(int(arr[word_idx]), 1 << bit_in_word)
        for i in range(32):
            if i != word_idx:
                self.assertEqual(int(arr[i]), 0)

    def test_f5_05_invalid_slicing_parameters(self) -> None:
        with self.assertRaises(ValueError):
            fragment_full(0, 0, w_per_input=8, b=16)
        with self.assertRaises(ValueError):
            fragment_full(0, 0, w_per_input=16, b=8)


class TestTier1KeySchedule(BaseE2ETestCase):
    """Feature 6: Key Schedule & Round Constants Tests."""

    def test_f6_01_derive_keys_structure(self) -> None:
        keys = derive_keys(bytes(32), 0, rounds=4)
        self.assertEqual(len(keys), 5)
        for k in keys:
            self.assertIsInstance(k, bytes)
            self.assertEqual(len(k), 32)

    def test_f6_02_derive_keys_pairwise_distinct(self) -> None:
        keys = derive_keys(b"\x12" * 32, 10, rounds=4)
        self.assertEqual(len(set(keys)), 5)

    def test_f6_03_round_constant_bounds(self) -> None:
        for r in range(1, 5):
            rc = round_constant(b"\x34" * 32, 42, r)
            self.assertTrue(0 <= rc <= 0xFFFF)

    def test_f6_04_round_constant_diversity(self) -> None:
        rcs = [round_constant(b"\x56" * 32, 99, r) for r in range(1, 5)]
        self.assertEqual(len(set(rcs)), 4)

    def test_f6_05_expand_key_words_structure(self) -> None:
        expanded = _expand_key_words(bytes(32), 32)
        self.assertIsInstance(expanded, np.ndarray)
        self.assertEqual(expanded.shape, (32,))
        self.assertEqual(expanded.dtype, np.uint64)
        self.assertTrue(all(0 <= int(w) <= 0xFFFF for w in expanded))


class TestTier1GaloisAndSbox(BaseE2ETestCase):
    """Feature 7: Galois Field Arithmetic & S-box Tests."""

    def test_f7_01_gf_addition_is_xor(self) -> None:
        pairs = [(0, 0), (1, 1), (0x1234, 0x5678), (0xFFFF, 0xAAAA)]
        for a, b in pairs:
            self.assertEqual(gf_add(a, b), a ^ b)

    def test_f7_02_gf_inv_multiplicative_identity(self) -> None:
        test_vals = [1, 2, 3, 0x1234, 0x8000, 0xFFFF]
        for a in test_vals:
            inv = gf_inv(a)
            self.assertEqual(gf_mult(a, inv), 1)

    def test_f7_03_gf_inv_zero_definition(self) -> None:
        self.assertEqual(gf_inv(0), 0)

    def test_f7_04_sbox_bijective_permutation(self) -> None:
        sbox = get_base_inversion_sbox()
        self.assertEqual(len(sbox), 65536)
        self.assertEqual(len(np.unique(sbox)), 65536)

    def test_f7_05_sbox_read_only_protection(self) -> None:
        sbox = get_base_inversion_sbox()
        self.assertFalse(sbox.flags.writeable)
        with self.assertRaises(ValueError):
            sbox[0] = 1


class TestTier1CauchyMds(BaseE2ETestCase):
    """Feature 8: Cauchy MDS Diffusion Matrix Tests."""

    def test_f8_01_matrix_dimensions_and_dtype(self) -> None:
        M = build_cauchy_mds(32)
        self.assertEqual(M.shape, (32, 32))
        self.assertEqual(M.dtype, np.uint32)

    def test_f8_02_no_zero_elements(self) -> None:
        M = build_cauchy_mds(32)
        self.assertEqual(int(np.count_nonzero(M == 0)), 0)

    def test_f8_03_zero_vector_multiplication(self) -> None:
        M = build_cauchy_mds(32)
        zero_vec = np.zeros(32, dtype=np.uint32)
        res = gf_matrix_vector_mult(M, zero_vec, 32)
        self.assertEqual(int(np.count_nonzero(res)), 0)

    def test_f8_04_unit_vector_full_diffusion(self) -> None:
        M = build_cauchy_mds(32)
        e0 = np.zeros(32, dtype=np.uint32)
        e0[0] = 1
        res = gf_matrix_vector_mult(M, e0, 32)
        self.assertEqual(int(np.count_nonzero(res)), 32)

    def test_f8_05_branch_number_lower_bound(self) -> None:
        M = build_cauchy_mds(32)
        e0 = np.zeros(32, dtype=np.uint32)
        e0[0] = 1
        res = gf_matrix_vector_mult(M, e0, 32)
        wt_in = int(np.count_nonzero(e0))
        wt_out = int(np.count_nonzero(res))
        self.assertGreaterEqual(wt_in + wt_out, 33)


class TestTier1CliCommands(BaseE2ETestCase):
    """Feature 9: CLI Diagnostic & Verification Utility Tests."""

    def test_f9_01_cli_kat_json_pass(self) -> None:
        code, out, err = run_cli(["--json", "kat"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["vectors_checked"], 4)

    def test_f9_02_cli_demo_json_payload(self) -> None:
        code, out, err = run_cli(["--json", "demo"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("high_bit_truncation_comparison", data)
        hbc = data["high_bit_truncation_comparison"]
        self.assertEqual(hbc["v1_changed_bits_out_of_256"], 0)
        self.assertGreater(hbc["v4_changed_bits_out_of_256"], 100)

    def test_f9_03_cli_bounds_json_active_sboxes(self) -> None:
        code, out, err = run_cli(["--json", "bounds", "--rounds", "4"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("wide_trail_bounds", data)
        self.assertEqual(data["wide_trail_bounds"][0]["min_active_sboxes"], 66)

    def test_f9_04_cli_hash_execution_matches_output(self) -> None:
        code, out, err = run_cli(
            [
                "--json",
                "hash",
                "--x",
                "0",
                "--y",
                "0",
                "--key-hex",
                "00" * 32,
                "--session",
                "0",
            ]
        )
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(
            data["digest_hex"],
            "6a73a2975c18d0880483b71dfca4a98e64fabc3b470cf0b87a79c401a3ffb64f",
        )

    def test_f9_05_cli_error_exit_code(self) -> None:
        code, out, err = run_cli(["hash", "--x", "-1", "--y", "0"])
        self.assertEqual(code, 2)
        self.assertIn("Input validation error", err)


if __name__ == "__main__":
    unittest.main()
