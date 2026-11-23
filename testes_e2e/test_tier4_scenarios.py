"""Tier 4: Real-World Cryptographic Application Scenarios Test Suite for RSD-S v4.

Simulates 5 high-level cryptographic protocols:
1. Key Derivation Function (KDF) Subkey Generation with Domain Separation
2. Streaming Pseudo-Random Generator (PRG) Counter Mode
3. Chained Message Authentication Code (MAC) Multi-Block Protocol
4. Concurrent Multi-Session Nonce Isolation & Orthogonality
5. Strict Avalanche Criterion (SAC) & Collision Stress under Perturbations

Target: >= 5 scenarios (designed: 5 comprehensive protocols).
Zero-mock, 100% genuine implementation.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))
sys.path.insert(0, str(ROOT / "ferramentas"))

from rsd_s_v4_final import (
    P_CURVE25519,
    diffuse_rsd_s_final,
    get_base_inversion_sbox,
)


def hamming_distance(a: bytes, b: bytes) -> int:
    """Compute bitwise Hamming distance between two byte sequences."""
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


class BaseE2ETestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        get_base_inversion_sbox()


class TestTier4RealWorldScenarios(BaseE2ETestCase):
    """Tier 4 Real-World Application Workload Scenarios."""

    def test_s01_kdf_multi_key_derivation_and_domain_separation(self) -> None:
        """Protocol 1: KDF Subkey Generation and Domain Separation."""
        master_secret = sha256(b"RSD_S_v4_KDF_MASTER_SECRET").digest()

        # Context-separated scalars
        x_enc = int.from_bytes(b"AES_256_GCM_ENC", "big")
        y_enc = 0x01
        x_mac = int.from_bytes(b"HMAC_SHA256_MAC", "big")
        y_mac = 0x02
        x_iv = int.from_bytes(b"INITIAL_VECTOR", "big")
        y_iv = 0x03

        epoch = 10
        k_enc = diffuse_rsd_s_final(x_enc, y_enc, master_secret, epoch)
        k_mac = diffuse_rsd_s_final(x_mac, y_mac, master_secret, epoch)
        k_iv = diffuse_rsd_s_final(x_iv, y_iv, master_secret, epoch)

        # Uniqueness
        self.assertEqual(len({k_enc, k_mac, k_iv}), 3)

        # Orthogonality
        dist_enc_mac = hamming_distance(k_enc, k_mac)
        dist_enc_iv = hamming_distance(k_enc, k_iv)
        dist_mac_iv = hamming_distance(k_mac, k_iv)
        pairwise_dists = [dist_enc_mac, dist_enc_iv, dist_mac_iv]
        for dist in pairwise_dists:
            self.assertTrue(
                115 <= dist <= 141,
                f"Pairwise KDF distance {dist} outside [115, 141]",
            )

        # Bit Balance
        for subkey in (k_enc, k_mac, k_iv):
            ones = sum(b.bit_count() for b in subkey)
            ratio = ones / 256.0
            self.assertTrue(
                0.40 <= ratio <= 0.60,
                f"Key bit balance {ratio:.2f} outside [0.40, 0.60]",
            )

        # Epoch Rotation
        epoch_next = 11
        k_enc_next = diffuse_rsd_s_final(x_enc, y_enc, master_secret, epoch_next)
        self.assertNotEqual(k_enc, k_enc_next)
        dist_epoch = hamming_distance(k_enc, k_enc_next)
        self.assertTrue(
            115 <= dist_epoch <= 141,
            f"Epoch rotation distance {dist_epoch} outside [115, 141]",
        )

    def test_s02_streaming_prg_counter_mode_keystream(self) -> None:
        """Protocol 2: Streaming PRG Counter Mode Keystream Generator."""
        seed_key = sha256(b"RSD_S_v4_PRG_SEED_KEY").digest()
        x_seed = 0x1234567890ABCDEF
        y_seed = 0xFEDCBA0987654321

        num_blocks = 100
        blocks = [
            diffuse_rsd_s_final(x_seed, y_seed, seed_key, i)
            for i in range(num_blocks)
        ]

        # Collision Freedom
        self.assertEqual(len(set(blocks)), num_blocks)

        # Consecutive Block Distance
        consec_dists = [
            hamming_distance(blocks[i], blocks[i + 1])
            for i in range(num_blocks - 1)
        ]
        mean_consec_dist = sum(consec_dists) / len(consec_dists)
        self.assertTrue(
            115 <= mean_consec_dist <= 141,
            f"Mean consecutive distance {mean_consec_dist:.2f} outside [115, 141]",
        )

        # Byte Distribution
        stream = b"".join(blocks)
        self.assertEqual(len(stream), num_blocks * 32)
        unique_bytes = len(set(stream))
        self.assertGreaterEqual(
            unique_bytes,
            240,
            f"Only {unique_bytes} distinct bytes observed in 3200 bytes",
        )
        for blk in blocks:
            self.assertNotEqual(blk, bytes(32))
            self.assertNotEqual(blk, b"\xff" * 32)

        # Reproducibility
        blocks_replay = [
            diffuse_rsd_s_final(x_seed, y_seed, seed_key, i)
            for i in range(num_blocks)
        ]
        self.assertEqual(blocks, blocks_replay)

    def test_s03_chained_mac_multi_block_authentication(self) -> None:
        """Protocol 3: Chained MAC Multi-Block Authentication Protocol."""
        auth_key = sha256(b"RSD_S_v4_AUTH_MAC_KEY").digest()
        payload = bytes([i % 251 for i in range(512)])  # 8 blocks of 64 bytes

        def compute_chained_mac(data: bytes, key: bytes) -> bytes:
            blocks = [data[i * 64 : (i + 1) * 64] for i in range(len(data) // 64)]
            x0 = int.from_bytes(blocks[0][:32], "big") % P_CURVE25519
            y0 = int.from_bytes(blocks[0][32:], "big") % P_CURVE25519
            tag = diffuse_rsd_s_final(x0, y0, key, 0)
            for blk in blocks[1:]:
                xi = int.from_bytes(blk[:32], "big") % P_CURVE25519
                yi = int.from_bytes(blk[32:], "big") % P_CURVE25519
                ni = int.from_bytes(tag[:8], "big")
                tag = diffuse_rsd_s_final(xi, yi, key, ni)
            return tag

        tag_base = compute_chained_mac(payload, auth_key)
        self.assertEqual(len(tag_base), 32)

        # Determinism
        tag_repeat = compute_chained_mac(payload, auth_key)
        self.assertEqual(tag_base, tag_repeat)

        # Tamper Detection
        tampered_payload = bytes([payload[0] ^ 1]) + payload[1:]
        tag_tampered = compute_chained_mac(tampered_payload, auth_key)
        self.assertNotEqual(tag_base, tag_tampered)
        dist_tamper = hamming_distance(tag_base, tag_tampered)
        self.assertGreater(
            dist_tamper,
            100,
            f"Tamper detection distance {dist_tamper} <= 100 bits",
        )

        # Order Sensitivity
        swapped_payload = payload[64:128] + payload[0:64] + payload[128:]
        tag_swapped = compute_chained_mac(swapped_payload, auth_key)
        self.assertNotEqual(tag_base, tag_swapped)

        # Length Extension Resistance
        extended_payload = payload + bytes(64)
        tag_extended = compute_chained_mac(extended_payload, auth_key)
        self.assertNotEqual(tag_base, tag_extended)

    def test_s04_multi_session_nonce_isolation(self) -> None:
        """Protocol 4: Multi-Session Nonce Isolation & Orthogonality."""
        server_key = sha256(b"SERVER_MULTI_SESSION_KEY").digest()
        req_x = 0x5555555555555555
        req_y = 0xAAAAAAAAAAAAAAAA

        num_sessions = 50
        nonces = [1000 + j for j in range(num_sessions)]
        tags = [diffuse_rsd_s_final(req_x, req_y, server_key, n) for n in nonces]

        # Strict Isolation
        self.assertEqual(len(set(tags)), num_sessions)

        # Pairwise Distance
        pairwise_dists = [
            hamming_distance(tags[i], tags[j])
            for i in range(num_sessions)
            for j in range(i + 1, num_sessions)
        ]
        mean_pairwise = sum(pairwise_dists) / len(pairwise_dists)
        self.assertTrue(
            118 <= mean_pairwise <= 138,
            f"Mean session distance {mean_pairwise:.2f} outside [118, 138]",
        )

        # Replay Determinism
        tag_rep = diffuse_rsd_s_final(req_x, req_y, server_key, nonces[25])
        self.assertEqual(tags[25], tag_rep)

        # Sequence Independence
        rev_tags = [
            diffuse_rsd_s_final(req_x, req_y, server_key, n)
            for n in reversed(nonces)
        ]
        self.assertEqual(rev_tags, list(reversed(tags)))

    def test_s05_avalanche_and_collision_stress(self) -> None:
        """Protocol 5: Strict Avalanche Criterion (SAC) & Collision Stress Protocol."""
        all_dists: list[int] = []
        bit_flip_counts = [0] * 256
        total_trials = 0
        collisions = 0

        num_seeds = 20
        for k in range(num_seeds):
            x_base = int.from_bytes(sha256(f"x_{k}".encode()).digest(), "big") >> 2
            y_base = int.from_bytes(sha256(f"y_{k}".encode()).digest(), "big") >> 2
            s_base = sha256(f"s_{k}".encode()).digest()
            n_base = int.from_bytes(
                sha256(f"n_{k}".encode()).digest()[:8], "big"
            )

            d0 = diffuse_rsd_s_final(x_base, y_base, s_base, n_base)

            perturbs = []
            for bit in (0, 63, 127, 191, 254):
                perturbs.append((x_base ^ (1 << bit), y_base, s_base, n_base))
            for bit in (0, 63, 127, 191, 254):
                perturbs.append((x_base, y_base ^ (1 << bit), s_base, n_base))
            for b_idx in (0, 15, 31):
                s_p = s_base[:b_idx] + bytes([s_base[b_idx] ^ 1]) + s_base[b_idx + 1 :]
                perturbs.append((x_base, y_base, s_p, n_base))
            for bit in (0, 31, 63):
                perturbs.append((x_base, y_base, s_base, n_base ^ (1 << bit)))

            for x_p, y_p, s_p, n_p in perturbs:
                total_trials += 1
                dk = diffuse_rsd_s_final(x_p, y_p, s_p, n_p)
                if dk == d0:
                    collisions += 1
                dist = hamming_distance(d0, dk)
                all_dists.append(dist)
                for byte_idx in range(32):
                    diff = d0[byte_idx] ^ dk[byte_idx]
                    for bit_idx in range(8):
                        if (diff >> bit_idx) & 1:
                            bit_flip_counts[byte_idx * 8 + bit_idx] += 1

        # 1. Collision Resistance
        self.assertEqual(collisions, 0, f"{collisions} collisions detected!")

        # 2. Avalanche Ratio
        mean_dist = sum(all_dists) / len(all_dists)
        mean_ratio = mean_dist / 256.0
        self.assertTrue(
            0.45 <= mean_ratio <= 0.55,
            f"Mean avalanche ratio {mean_ratio:.4f} outside [0.45, 0.55]",
        )

        # 3. No Bit Stagnation: every bit position flips in at least 20% of trials
        min_flips = min(bit_flip_counts)
        min_ratio = min_flips / total_trials
        self.assertGreaterEqual(
            min_ratio,
            0.20,
            f"Bit position with lowest activity flipped only {min_flips}/{total_trials} ({min_ratio:.2%})",
        )


if __name__ == "__main__":
    unittest.main()
