"""Tier 3: Cross-Feature Combinations & Interaction Test Suite for RSD-S v4.

Covers multi-parameter interaction testing, pairwise feature combinations,
state pipeline equivalence, and representation parity.

Target: >= 15 tests (designed: 16 tests).
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

from analise_wide_trail import bound_for_rounds
from mds_real import build_cauchy_mds
import rsd_cli
from rsd_s_v4_final import (
    KEY_SIZE,
    MAX_ROUNDS,
    MAX_SESSION,
    P_CURVE25519,
    R,
    W,
    _hash_state,
    derive_keys,
    diffuse_rsd_s_final,
    diffuse_rsd_s_final_PRE_SHA,
    diffuse_rsd_s_rounds,
    diffuse_rsd_s_rounds_PRE_SHA,
    get_base_inversion_sbox,
    gf_matrix_vector_mult,
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


class TestTier3CrossFeatureCombinations(BaseE2ETestCase):
    """Tier 3 Cross-Feature Interaction Tests."""

    def test_c01_max_scalar_max_session_min_rounds(self) -> None:
        max_scalar = P_CURVE25519 - 1
        res = diffuse_rsd_s_rounds(
            max_scalar, max_scalar, b"\xaa" * 32, MAX_SESSION, rounds=1
        )
        self.assertIsInstance(res, bytes)
        self.assertEqual(len(res), 32)

    def test_c02_max_scalar_max_session_official_rounds(self) -> None:
        max_scalar = P_CURVE25519 - 1
        res4 = diffuse_rsd_s_final(
            max_scalar, max_scalar, b"\xaa" * 32, MAX_SESSION
        )
        res1 = diffuse_rsd_s_rounds(
            max_scalar, max_scalar, b"\xaa" * 32, MAX_SESSION, rounds=1
        )
        self.assertEqual(len(res4), 32)
        self.assertNotEqual(res4, res1)

    def test_c03_zero_state_all_ones_key_max_session(self) -> None:
        out = diffuse_rsd_s_final(0, 0, b"\xff" * 32, MAX_SESSION)
        self.assertEqual(len(out), 32)
        self.assertNotEqual(out, bytes(32))

    def test_c04_zero_state_all_zeros_key_session_increment(self) -> None:
        s = b"\x00" * 32
        out0 = diffuse_rsd_s_final(0, 0, s, 0)
        out1 = diffuse_rsd_s_final(0, 0, s, 1)
        self.assertNotEqual(out0, out1)
        dist = sum((a ^ b).bit_count() for a, b in zip(out0, out1))
        self.assertTrue(110 <= dist <= 146, f"Hamming distance {dist} out of [110, 146]")

    def test_c05_pre_sha_pipeline_to_terminal_hash_direct_parity(self) -> None:
        x, y = 0x13579BDF, 0x2468ACE0
        s = b"\x5c" * 32
        n = 101
        st = diffuse_rsd_s_final_PRE_SHA(x, y, s, n)
        z_bytes = b"".join(int(w).to_bytes(2, "big") for w in st)
        digest_manual = sha256(z_bytes).digest()
        digest_direct = diffuse_rsd_s_final(x, y, s, n)
        self.assertEqual(digest_manual, digest_direct)

    def test_c06_pre_sha_pipeline_variable_rounds_parity(self) -> None:
        x, y = 42, 84
        s = b"\x99" * 32
        n = 7
        for r in (1, 2, 3, 5):
            st = diffuse_rsd_s_rounds_PRE_SHA(x, y, s, n, r)
            manual = _hash_state(st)
            direct = diffuse_rsd_s_rounds(x, y, s, n, r)
            self.assertEqual(manual, direct)

    def test_c07_cli_hash_json_direct_python_api_parity(self) -> None:
        x_val = 0x1234
        y_val = 0x5678
        key_hex = "bb" * 32
        session = 42
        rounds = 4
        code, out, _ = run_cli(
            [
                "--json",
                "hash",
                "--x",
                str(x_val),
                "--y",
                str(y_val),
                "--key-hex",
                key_hex,
                "--session",
                str(session),
                "--rounds",
                str(rounds),
            ]
        )
        self.assertEqual(code, 0)
        data = json.loads(out)
        py_digest = diffuse_rsd_s_final(x_val, y_val, bytes.fromhex(key_hex), session)
        self.assertEqual(data["digest_hex"], py_digest.hex())
        py_pre_sha = diffuse_rsd_s_final_PRE_SHA(
            x_val, y_val, bytes.fromhex(key_hex), session
        )
        expected_words = [f"0x{int(w):04x}" for w in py_pre_sha]
        self.assertEqual(data["pre_sha_words_hex"], expected_words)

    def test_c08_cli_kat_json_direct_vetores_json_parity(self) -> None:
        code, out, _ = run_cli(["--json", "kat"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        vector_path = ROOT / "testes" / "vetores_v4.json"
        expected_vectors = json.loads(vector_path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["results"]), len(expected_vectors))
        for res, vec in zip(data["results"], expected_vectors):
            self.assertEqual(res["actual"], vec["output_hex"])
            self.assertTrue(res["matched"])

    def test_c09_asymmetric_scalar_inputs_non_commutativity(self) -> None:
        a = 0x12345
        b = 0x67890
        s = b"\x77" * 32
        n = 1
        d1 = diffuse_rsd_s_final(a, b, s, n)
        d2 = diffuse_rsd_s_final(b, a, s, n)
        self.assertNotEqual(d1, d2)

    def test_c10_input_position_pairwise_divergence(self) -> None:
        x = 0x100000000
        y = 0x200000000
        s = b"\x33" * 32
        n = 12
        out_x_flip = diffuse_rsd_s_final(x ^ 1, y, s, n)
        out_y_flip = diffuse_rsd_s_final(x, y ^ 1, s, n)
        dist = sum((a ^ b).bit_count() for a, b in zip(out_x_flip, out_y_flip))
        self.assertTrue(
            100 <= dist <= 156,
            f"Pairwise divergence distance {dist} outside [100, 156]",
        )

    def test_c11_sbox_and_mds_composition_with_round_constant(self) -> None:
        M = build_cauchy_mds(W)
        sbox = get_base_inversion_sbox()
        state = np.zeros(W, dtype=np.uint64)
        state[0] = 0x1234
        rc = 0x5678
        for i in range(W):
            state[i] = int(sbox[state[i]]) ^ rc
        out_state = gf_matrix_vector_mult(M, state, W)
        self.assertEqual(int(np.count_nonzero(out_state)), 32)

    def test_c12_key_schedule_multi_round_evolution(self) -> None:
        keys = derive_keys(b"\x99" * 32, 100, rounds=10)
        self.assertEqual(len(keys), 11)
        self.assertEqual(len(set(keys)), 11)
        for k in keys:
            self.assertNotEqual(k, bytes(32))

    def test_c13_word_slicing_and_sbox_all_words_active(self) -> None:
        sbox = get_base_inversion_sbox()
        base_state = np.zeros(W, dtype=np.uint64)
        base_sboxed = np.array([sbox[w] for w in base_state])
        for i in range(W):
            perturbed = base_state.copy()
            perturbed[i] = 1
            sboxed = np.array([sbox[w] for w in perturbed])
            self.assertFalse(np.array_equal(base_sboxed, sboxed))
            self.assertNotEqual(int(sboxed[i]), int(base_sboxed[i]))

    def test_c14_combined_invalid_parameters_precedence(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            validate_inputs("invalid_x", 0, "invalid_s", 0)  # type: ignore[arg-type]
        self.assertIn("x deve ser um inteiro", str(ctx.exception))

    def test_c15_cli_hex_and_decimal_representation_equivalence(self) -> None:
        code_hex, out_hex, _ = run_cli(
            [
                "--json",
                "hash",
                "--x",
                "0x1234",
                "--y",
                "0x5678",
                "--key-hex",
                "00" * 32,
                "--session",
                "0",
            ]
        )
        code_dec, out_dec, _ = run_cli(
            [
                "--json",
                "hash",
                "--x",
                "4660",
                "--y",
                "22136",
                "--key-hex",
                "00" * 32,
                "--session",
                "0",
            ]
        )
        self.assertEqual(code_hex, 0)
        self.assertEqual(code_dec, 0)
        d_hex = json.loads(out_hex)
        d_dec = json.loads(out_dec)
        self.assertEqual(d_hex["digest_hex"], d_dec["digest_hex"])

    def test_c16_cli_bounds_consistency_with_wide_trail(self) -> None:
        code, out, _ = run_cli(["--json", "bounds", "--rounds", "4"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        bound = bound_for_rounds(4)
        self.assertEqual(
            data["wide_trail_bounds"][0]["min_active_sboxes"],
            bound.min_active_sboxes,
        )
        self.assertEqual(bound.min_active_sboxes, 66)


if __name__ == "__main__":
    unittest.main()
