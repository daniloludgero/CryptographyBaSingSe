"""
testes/test_milestone3_threat_model_bounds.py

Regression Test Suite for Milestone 3 (Threat Modeling & Provable Security)
Validates the empirical assertions, domain boundary clamping, endianness sensitivity,
and nonce reuse properties of RSD-S v4.
"""

import json
import os
import secrets
import sys
import unittest

import numpy as np

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
IMPL_DIR = os.path.join(REPO_ROOT, "implementacao")
if IMPL_DIR not in sys.path:
    sys.path.insert(0, IMPL_DIR)
TOOLS_DIR = os.path.join(REPO_ROOT, "ferramentas")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from rsd_s_v4_final import (
    diffuse_rsd_s_final,
    diffuse_rsd_s_rounds_PRE_SHA,
    fragment_full,
    P_CURVE25519,
    KEY_SIZE,
    M_CAUCHY_32,
    W,
)
from audit_threat_model_bounds import (
    NonceReuseAuditor,
    DomainBoundaryAuditor,
    EndiannessAuditor,
    PrfDistinguishingSimulator,
)


class TestMilestone3ThreatModelBounds(unittest.TestCase):
    """Test suite ensuring threat model bounds and domain invariants are upheld."""

    def test_nonce_reuse_determinism(self):
        """Verify deterministic collision on nonce reuse and divergence on modified inputs."""
        res = NonceReuseAuditor.test_identical_output_under_reuse(num_trials=50)
        self.assertTrue(res["deterministic_collision_guarantee"])
        self.assertEqual(res["identical_equality_rate"], 1.0)
        self.assertEqual(res["distinct_input_divergence_rate"], 1.0)
        self.assertEqual(res["distinct_nonce_divergence_rate"], 1.0)

    def test_keystream_two_time_pad_cancellation(self):
        """Verify that keystream completely cancels when a nonce is reused in stream mode."""
        res = NonceReuseAuditor.simulate_ctr_keystream_two_time_pad(num_blocks=8)
        self.assertTrue(res["keystream_perfectly_cancelled"])
        self.assertEqual(res["xor_bit_error_count"], 0)
        self.assertTrue(res["crib_drag_test"]["crib_recovery_success"])

    def test_domain_boundary_msb_clamping(self):
        """Verify that Word 15 and Word 31 MSB is strictly 0 for valid Curve25519 inputs."""
        res = DomainBoundaryAuditor.test_msb_zero_clamping(num_samples=1000)
        self.assertEqual(res["total_violations"], 0)
        self.assertEqual(res["msb_clamped_rate"], 1.0)
        self.assertFalse(res["exceeds_0x7fff"])
        self.assertEqual(res["clamped_structural_bits"], 2)
        self.assertAlmostEqual(res["theoretical_active_entropy_bits"], 510.0, places=1)

    def test_endianness_kat_sensitivity(self):
        """Verify that KAT vectors strictly enforce canonical mixed endianness."""
        res = EndiannessAuditor.verify_kat_vectors_endian_sensitivity()
        self.assertEqual(res["canonical_matches"], 4)
        self.assertEqual(res["variant2_be_keys_matches"], 0)
        self.assertEqual(res["variant3_le_hash_matches"], 0)
        self.assertEqual(res["variant4_all_be_matches"], 0)

    def test_reduced_round_linear_invariant(self):
        """Verify 1-round linear invariant holds (Adv=1.0) while 4-round is broken (Adv=0.0)."""
        res = PrfDistinguishingSimulator.evaluate_reduced_round_prf_distinguisher(num_pairs=30)
        self.assertEqual(res["round1_distinguishing_advantage"], 1.0)
        self.assertEqual(res["round4_distinguishing_advantage"], 0.0)

    def test_results_json_artifact(self):
        """Verify threat_model_bounds_results.json exists, is valid, and contains all sections."""
        json_path = os.path.join(REPO_ROOT, "resultados", "threat_model_bounds_results.json")
        self.assertTrue(os.path.exists(json_path), f"File {json_path} does not exist")
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("nonce_reuse_audit", data)
        self.assertIn("domain_boundary_audit", data)
        self.assertIn("endianness_audit", data)
        self.assertIn("prf_distinguishing_simulation", data)
        self.assertEqual(data["nonce_reuse_audit"]["identical_output"]["identical_equality_rate"], 1.0)
        self.assertEqual(data["domain_boundary_audit"]["msb_clamping"]["total_violations"], 0)


if __name__ == "__main__":
    unittest.main()
