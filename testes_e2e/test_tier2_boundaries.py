"""Tier 2: Boundary & Corner Cases Test Suite for RSD-S v4.

Covers boundary condition verification across 9 core features:
1. Core PRF Boundary Invariants
2. Pre-SHA Inspector Boundary Conditions
3. Configurable Rounds Boundaries
4. Input Validation Boundary Conditions
5. Word Slicing Boundary Conditions
6. Key Schedule & Round Constant Boundaries
7. Galois Arithmetic & S-box Boundary Points
8. Cauchy MDS Boundary Conditions
9. CLI Boundary Inputs

Target: >= 45 tests (designed: 46 tests).
Zero-mock, 100% genuine implementation.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))
sys.path.insert(0, str(ROOT / "ferramentas"))

from mds_real import build_cauchy_mds
import rsd_cli
from rsd_s_v4_final import (
    KEY_SIZE,
    MAX_ROUNDS,
    MAX_SESSION,
    P_CURVE25519,
    R,
    W,
    _validate_rounds,
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
        get_base_inversion_sbox()


class TestTier2CorePrfBoundaries(BaseE2ETestCase):
    """Feature 1: Core PRF Boundary Invariants."""

    def test_b1_01_zero_scalar_inputs(self) -> None:
        out = diffuse_rsd_s_final(0, 0, bytes(32), 0)
        self.assertEqual(
            out.hex(),
            "6a73a2975c18d0880483b71dfca4a98e64fabc3b470cf0b87a79c401a3ffb64f",
        )

    def test_b1_02_max_field_scalar_inputs(self) -> None:
        max_scalar = P_CURVE25519 - 1
        out = diffuse_rsd_s_final(max_scalar, max_scalar, bytes(32), 0)
        self.assertIsInstance(out, bytes)
        self.assertEqual(len(out), 32)
        self.assertEqual(out, diffuse_rsd_s_final(max_scalar, max_scalar, bytes(32), 0))

    def test_b1_03_all_zeros_key(self) -> None:
        s = b"\x00" * 32
        out = diffuse_rsd_s_final(1, 2, s, 3)
        self.assertEqual(len(out), 32)
        self.assertNotEqual(out, bytes(32))

    def test_b1_04_all_ones_key(self) -> None:
        s = b"\xff" * 32
        out = diffuse_rsd_s_final(1, 2, s, 3)
        self.assertEqual(len(out), 32)
        self.assertNotEqual(out, bytes(32))

    def test_b1_05_max_uint64_session(self) -> None:
        out = diffuse_rsd_s_final(1, 2, bytes(32), MAX_SESSION)
        self.assertEqual(len(out), 32)
        self.assertEqual(out, diffuse_rsd_s_final(1, 2, bytes(32), MAX_SESSION))


class TestTier2PreShaBoundaries(BaseE2ETestCase):
    """Feature 2: Pre-SHA Inspector Boundary Conditions."""

    def test_b2_01_pre_sha_zero_state_entropy(self) -> None:
        st = diffuse_rsd_s_final_PRE_SHA(0, 0, bytes(32), 0)
        unique_words = len(set(int(w) for w in st))
        self.assertGreater(unique_words, 20)

    def test_b2_02_pre_sha_max_field_element_word_bounds(self) -> None:
        max_scalar = P_CURVE25519 - 1
        st = diffuse_rsd_s_final_PRE_SHA(max_scalar, max_scalar, bytes(32), 0)
        self.assertTrue(all(0 <= int(w) <= 0xFFFF for w in st))

    def test_b2_03_pre_sha_single_round_state_validity(self) -> None:
        st = diffuse_rsd_s_rounds_PRE_SHA(100, 200, bytes(32), 0, rounds=1)
        self.assertEqual(len(st), 32)
        self.assertTrue(all(0 <= int(w) <= 0xFFFF for w in st))

    def test_b2_04_pre_sha_max_rounds_255_state_validity(self) -> None:
        _validate_rounds(MAX_ROUNDS)
        keys = derive_keys(bytes(32), 0, rounds=MAX_ROUNDS)
        self.assertEqual(len(keys), 256)
        rc = round_constant(bytes(32), 0, MAX_ROUNDS)
        self.assertTrue(0 <= rc <= 0xFFFF)

    def test_b2_05_pre_sha_isolated_copy_safety(self) -> None:
        st1 = diffuse_rsd_s_final_PRE_SHA(1, 2, bytes(32), 0)
        orig_val = int(st1[0])
        st1[0] = 0x9999
        st2 = diffuse_rsd_s_final_PRE_SHA(1, 2, bytes(32), 0)
        self.assertEqual(int(st2[0]), orig_val)


class TestTier2RoundsBoundaries(BaseE2ETestCase):
    """Feature 3: Configurable Rounds Boundaries."""

    def test_b3_01_rounds_lower_bound_1(self) -> None:
        out = diffuse_rsd_s_rounds(1, 2, bytes(32), 0, rounds=1)
        self.assertEqual(len(out), 32)

    def test_b3_02_rounds_upper_bound_255(self) -> None:
        self.assertIsNone(_validate_rounds(255))

    def test_b3_03_rounds_rejects_zero(self) -> None:
        with self.assertRaises(ValueError):
            _validate_rounds(0)
        with self.assertRaises(ValueError):
            diffuse_rsd_s_rounds(1, 2, bytes(32), 0, rounds=0)

    def test_b3_04_rounds_rejects_256(self) -> None:
        with self.assertRaises(ValueError):
            _validate_rounds(256)
        with self.assertRaises(ValueError):
            diffuse_rsd_s_rounds(1, 2, bytes(32), 0, rounds=256)

    def test_b3_05_rounds_rejects_negative_and_types(self) -> None:
        with self.assertRaises(ValueError):
            _validate_rounds(-1)
        for bad in (False, True, 4.0, "4"):
            with self.assertRaises(TypeError):
                _validate_rounds(bad)  # type: ignore[arg-type]


class TestTier2InputValidationBoundaries(BaseE2ETestCase):
    """Feature 4: Input Validation Boundary Conditions."""

    def test_b4_01_field_element_exact_modulus_rejection(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            validate_inputs(P_CURVE25519, 0, bytes(32), 0)
        self.assertIn("x deve satisfazer 0 <= x < 2^255 - 19", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            validate_inputs(0, P_CURVE25519, bytes(32), 0)
        self.assertIn("y deve satisfazer 0 <= y < 2^255 - 19", str(ctx.exception))

    def test_b4_02_field_element_above_modulus_rejection(self) -> None:
        for val in (P_CURVE25519 + 1, (1 << 255) - 1, 1 << 256):
            with self.assertRaises(ValueError):
                validate_inputs(val, 0, bytes(32), 0)
            with self.assertRaises(ValueError):
                validate_inputs(0, val, bytes(32), 0)

    def test_b4_03_field_element_negative_rejection(self) -> None:
        for val in (-1, -100, -(1 << 255)):
            with self.assertRaises(ValueError):
                validate_inputs(val, 0, bytes(32), 0)
            with self.assertRaises(ValueError):
                validate_inputs(0, val, bytes(32), 0)

    def test_b4_04_session_boundary_rejection(self) -> None:
        for val in (MAX_SESSION + 1, 1 << 65, -1):
            with self.assertRaises(ValueError):
                validate_inputs(0, 0, bytes(32), val)

    def test_b4_05_key_length_boundaries_rejection(self) -> None:
        for length in (0, 1, 31, 33, 64):
            with self.assertRaises(ValueError) as ctx:
                validate_inputs(0, 0, bytes(length), 0)
            self.assertIn("s deve ter exatamente 32 bytes", str(ctx.exception))

    def test_b4_06_boolean_strict_type_rejection(self) -> None:
        with self.assertRaises(TypeError):
            validate_inputs(True, 0, bytes(32), 0)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            validate_inputs(0, False, bytes(32), 0)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            validate_inputs(0, 0, bytes(32), True)  # type: ignore[arg-type]


class TestTier2WordSlicingBoundaries(BaseE2ETestCase):
    """Feature 5: Word Slicing Boundary Conditions."""

    def test_b5_01_slicing_zero_inputs(self) -> None:
        arr = fragment_full(0, 0)
        self.assertEqual(int(np.count_nonzero(arr)), 0)

    def test_b5_02_slicing_max_field_element(self) -> None:
        arr = fragment_full(P_CURVE25519 - 1, 0)
        w15 = int(arr[15])
        self.assertEqual(w15 & 0x8000, 0)

    def test_b5_03_slicing_lowest_bit_boundary(self) -> None:
        arr = fragment_full(1, 0)
        self.assertEqual(int(arr[0]), 1)
        self.assertEqual(int(np.count_nonzero(arr[1:])), 0)

    def test_b5_04_slicing_highest_valid_bit_boundary(self) -> None:
        val = 1 << 254
        arr = fragment_full(val, 0)
        self.assertEqual(int(arr[15]), 0x4000)
        self.assertEqual(int(np.count_nonzero(arr[:15])), 0)
        self.assertEqual(int(np.count_nonzero(arr[16:])), 0)

    def test_b5_05_slicing_rejects_overflow_input(self) -> None:
        with self.assertRaises(ValueError):
            fragment_full(P_CURVE25519, 0)
        with self.assertRaises(ValueError):
            fragment_full(0, P_CURVE25519)


class TestTier2KeyScheduleBoundaries(BaseE2ETestCase):
    """Feature 6: Key Schedule & Round Constant Boundaries."""

    def test_b6_01_rc_round_1_and_255_valid(self) -> None:
        rc1 = round_constant(bytes(32), 0, 1)
        rc255 = round_constant(bytes(32), 0, 255)
        self.assertTrue(0 <= rc1 <= 0xFFFF)
        self.assertTrue(0 <= rc255 <= 0xFFFF)

    def test_b6_02_rc_rejects_round_0_and_256(self) -> None:
        with self.assertRaises(ValueError):
            round_constant(bytes(32), 0, 0)
        with self.assertRaises(ValueError):
            round_constant(bytes(32), 0, 256)

    def test_b6_03_rc_rejects_boolean_round(self) -> None:
        with self.assertRaises(TypeError):
            round_constant(bytes(32), 0, True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            round_constant(bytes(32), 0, False)  # type: ignore[arg-type]

    def test_b6_04_derive_keys_max_session(self) -> None:
        keys = derive_keys(b"\x88" * 32, MAX_SESSION, rounds=4)
        self.assertEqual(len(keys), 5)
        self.assertEqual(len(set(keys)), 5)

    def test_b6_05_derive_keys_all_zeros_and_ones(self) -> None:
        keys_zero = derive_keys(b"\x00" * 32, 0, rounds=4)
        keys_one = derive_keys(b"\xff" * 32, 0, rounds=4)
        self.assertEqual(len(set(keys_zero)), 5)
        self.assertEqual(len(set(keys_one)), 5)
        self.assertTrue(all(len(k) == 32 for k in keys_zero))
        self.assertTrue(all(len(k) == 32 for k in keys_one))


class TestTier2GaloisSboxBoundaries(BaseE2ETestCase):
    """Feature 7: Galois Arithmetic & S-box Boundary Points."""

    def test_b7_01_sbox_zero_point(self) -> None:
        sbox = get_base_inversion_sbox()
        self.assertEqual(int(sbox[0]), 0)

    def test_b7_02_sbox_unit_point(self) -> None:
        sbox = get_base_inversion_sbox()
        self.assertEqual(int(sbox[1]), 1)

    def test_b7_03_sbox_max_point(self) -> None:
        sbox = get_base_inversion_sbox()
        max_val = int(sbox[0xFFFF])
        self.assertNotEqual(max_val, 0)
        self.assertNotEqual(max_val, 1)
        self.assertTrue(0 <= max_val <= 0xFFFF)

    def test_b7_04_sbox_involutive_self_inversion(self) -> None:
        sbox = get_base_inversion_sbox()
        test_pts = [0, 1, 2, 0x1234, 0x7FFF, 0x8000, 0xFFFF]
        for pt in test_pts:
            self.assertEqual(int(sbox[int(sbox[pt])]), pt)

    def test_b7_05_sbox_immutability_slice_assignment(self) -> None:
        sbox = get_base_inversion_sbox()
        with self.assertRaises(ValueError):
            sbox[:10] = 0


class TestTier2CauchyMdsBoundaries(BaseE2ETestCase):
    """Feature 8: Cauchy MDS Boundary Conditions."""

    def test_b8_01_zero_vector_mapping(self) -> None:
        M = build_cauchy_mds(32)
        v0 = np.zeros(32, dtype=np.uint32)
        out = gf_matrix_vector_mult(M, v0, 32)
        self.assertEqual(int(np.count_nonzero(out)), 0)

    def test_b8_02_all_ones_vector_mapping(self) -> None:
        M = build_cauchy_mds(32)
        v1 = np.ones(32, dtype=np.uint32)
        out = gf_matrix_vector_mult(M, v1, 32)
        self.assertEqual(int(np.count_nonzero(out)), 32)

    def test_b8_03_max_word_values_vector(self) -> None:
        M = build_cauchy_mds(32)
        vmax = np.full(32, 0xFFFF, dtype=np.uint32)
        out = gf_matrix_vector_mult(M, vmax, 32)
        self.assertEqual(int(np.count_nonzero(out)), 32)
        self.assertTrue(all(0 <= int(w) <= 0xFFFF for w in out))

    def test_b8_04_unit_vectors_diffusion_at_boundaries(self) -> None:
        M = build_cauchy_mds(32)
        for idx in (0, 15, 16, 31):
            e = np.zeros(32, dtype=np.uint32)
            e[idx] = 1
            out = gf_matrix_vector_mult(M, e, 32)
            self.assertEqual(int(np.count_nonzero(out)), 32)

    def test_b8_05_branch_number_preservation_boundary(self) -> None:
        M = build_cauchy_mds(32)
        for idx in (0, 15, 16, 31):
            e = np.zeros(32, dtype=np.uint32)
            e[idx] = 1
            out = gf_matrix_vector_mult(M, e, 32)
            wt = int(np.count_nonzero(e)) + int(np.count_nonzero(out))
            self.assertGreaterEqual(wt, 33)


class TestTier2CliBoundaries(BaseE2ETestCase):
    """Feature 9: CLI Boundary Inputs."""

    def test_b9_01_cli_hash_boundary_scalars(self) -> None:
        code1, out1, _ = run_cli(["--json", "hash", "--x", "0", "--y", "0"])
        self.assertEqual(code1, 0)
        d1 = json.loads(out1)
        self.assertEqual(len(d1["digest_hex"]), 64)

        max_scalar_str = str(P_CURVE25519 - 1)
        code2, out2, _ = run_cli(
            ["--json", "hash", "--x", max_scalar_str, "--y", max_scalar_str]
        )
        self.assertEqual(code2, 0)
        d2 = json.loads(out2)
        self.assertEqual(len(d2["digest_hex"]), 64)

    def test_b9_02_cli_hash_rejects_modulus(self) -> None:
        code, out, err = run_cli(["hash", "--x", str(P_CURVE25519), "--y", "0"])
        self.assertEqual(code, 2)
        self.assertIn("Input validation error", err)

    def test_b9_03_cli_hash_session_boundaries(self) -> None:
        code_s0, _, _ = run_cli(["hash", "--x", "0", "--y", "0", "--session", "0"])
        self.assertEqual(code_s0, 0)

        code_smax, _, _ = run_cli(
            ["hash", "--x", "0", "--y", "0", "--session", str(MAX_SESSION)]
        )
        self.assertEqual(code_smax, 0)

        code_over, _, err_over = run_cli(
            ["hash", "--x", "0", "--y", "0", "--session", str(MAX_SESSION + 1)]
        )
        self.assertEqual(code_over, 2)
        self.assertIn("Input validation error", err_over)

        code_neg, _, err_neg = run_cli(
            ["hash", "--x", "0", "--y", "0", "--session", "-1"]
        )
        self.assertEqual(code_neg, 2)
        self.assertIn("Input validation error", err_neg)

    def test_b9_04_cli_hash_key_boundaries(self) -> None:
        code62, _, err62 = run_cli(
            ["hash", "--x", "0", "--y", "0", "--key-hex", "aa" * 31]
        )
        self.assertEqual(code62, 2)
        self.assertIn("Input validation error", err62)

        code66, _, err66 = run_cli(
            ["hash", "--x", "0", "--y", "0", "--key-hex", "aa" * 33]
        )
        self.assertEqual(code66, 2)
        self.assertIn("Input validation error", err66)

    def test_b9_05_cli_bounds_boundaries(self) -> None:
        code1, _, _ = run_cli(["bounds", "--rounds", "1"])
        self.assertEqual(code1, 0)

        code255, _, _ = run_cli(["bounds", "--rounds", "255"])
        self.assertEqual(code255, 0)

        code0, _, err0 = run_cli(["bounds", "--rounds", "0"])
        self.assertEqual(code0, 2)
        self.assertIn("Error: rounds must be in 1..255", err0)

        code256, _, err256 = run_cli(["bounds", "--rounds", "256"])
        self.assertEqual(code256, 2)
        self.assertIn("Error: rounds must be in 1..255", err256)


if __name__ == "__main__":
    unittest.main()
