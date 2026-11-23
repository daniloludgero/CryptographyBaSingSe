"""
Verificação determinística dos vetores KAT congelados de RSD-S v5.2 (`testes/vetores_v52.json`).

Valida:
  - Paridade exata bit-a-bit de todos os vetores contra Python (`rsd_s_v5_hardened.py`)
    e núcleo C99 (`implementacao/c_core/rsd_s_v5_ct.c`).
  - Saídas pré-SHA (64B), SHA-256 (32B) e SHAKE256-512 (64B).
  - Módulo BandlimitedDualKeyEngine (`y_pub_bytes`, `y_pub_z65537_bytes`, digests 256/512,
    ausência de `s_priv_state` [RT-F2-03] e `verify_public_output` determinístico).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from bandlimited_dual_key import BandlimitedDualKeyEngine  # noqa: E402
from rsd_s_v5_hardened import (  # noqa: E402
    R_V5,
    diffuse_rsd_s_v5,
    diffuse_rsd_s_v5_pre_sha,
    run_c_core_pre_sha,
    serialize_state_v5,
)

KAT_PATH = ROOT / "testes" / "vetores_v52.json"
C_SRC = ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"


class TestVetoresV52KAT(unittest.TestCase):
    """Confirma que todos os vetores KAT congelados de RSD-S v5.2 reproduzem exatamente."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = json.loads(KAT_PATH.read_text(encoding="utf-8"))
        cls.eng = BandlimitedDualKeyEngine()
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="rsd_v52_kat_")
        cls.so_path = Path(cls._tmpdir.name) / "lib_rsd_v52_kat.so"
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

    def test_kat_schema_and_all_v52_vectors_python_and_c99(self) -> None:
        self.assertEqual(self.doc["primitive"], "RSD-S v5.2")
        vectors = self.doc["vectors"]
        self.assertGreaterEqual(len(vectors), 6)

        for v in vectors:
            with self.subTest(vector=v["name"]):
                x = int(v["x"])
                y = int(v["y"])
                s = bytes.fromhex(v["s_hex"])
                n_sess = int(v["n_sess"])
                rounds = int(v["rounds"])

                st_py = diffuse_rsd_s_v5_pre_sha(x, y, s, n_sess, rounds=rounds)
                self.assertEqual(serialize_state_v5(st_py).hex(), v["pre_sha_hex"])

                rc, st_c = run_c_core_pre_sha(self.so_path, x, y, s, n_sess, rounds=rounds)
                self.assertEqual(rc, 0)
                self.assertTrue(np.array_equal(st_py, st_c))

                d32 = diffuse_rsd_s_v5(x, y, s, n_sess, rounds=rounds, output_bytes=32)
                d64 = diffuse_rsd_s_v5(x, y, s, n_sess, rounds=rounds, output_bytes=64)
                self.assertEqual(d32.hex(), v["output_256_hex"])
                self.assertEqual(d64.hex(), v["output_512_hex"])

                if rounds == R_V5:
                    pub = self.eng.refactor_public_output(x, y, s, n_sess)
                    self.assertNotIn("s_priv_state", pub)
                    self.assertEqual(pub["y_pub_bytes"].hex(), v["dual_key_y_pub_bytes_hex"])
                    self.assertEqual(pub["y_pub_z65537_bytes"].hex(), v["dual_key_y_pub_z65537_hex"])
                    self.assertEqual(pub["y_pub_digest_256"].hex(), v["dual_key_digest_256_hex"])
                    self.assertEqual(pub["y_pub_digest_512"].hex(), v["dual_key_digest_512_hex"])
                    self.assertTrue(
                        self.eng.verify_public_output(x, y, s, n_sess, pub["y_pub_bytes"])
                    )


if __name__ == "__main__":
    unittest.main()
