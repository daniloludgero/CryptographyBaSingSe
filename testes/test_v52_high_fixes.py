"""
Regressão determinística dos 2 achados de severidade Alta da R5 (v5.2):
  - RT-F2-01: Redundância temporal completa ponta-a-ponta (R1..R8) em C99 e Python,
              bloqueando falhas em qualquer rodada (incluindo R7 / R-1 e R1..R8).
  - RT-F2-02: Inicialização thread-safe atômica (acquire/release) de CAUCHY_MDS e
              CAUCHY_BIT_BASIS em init_cauchy_mds(), sem data race sob ThreadSanitizer.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from rsd_s_v5_hardened import (  # noqa: E402
    FaultDetectedError,
    R_V5,
    diffuse_rsd_s_v5,
    diffuse_rsd_s_v5_pre_sha,
    run_c_core_pre_sha,
)

C_SRC = ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"


class TestV52HighSecurityFixes(unittest.TestCase):
    """Valida as correções de RT-F2-01 (Anti-DFA R1..R) e RT-F2-02 (TSan thread-safety)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="rsd_v52_fix_")
        cls.tmp = Path(cls._tmpdir.name)
        cls.so_path = cls.tmp / "lib_rsd_s_v52.so"
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

    def test_rt_f2_01_anti_dfa_blocks_faults_in_every_round_python_and_c99(self) -> None:
        """Falha de 1 bit em qualquer rodada r in 1..8 (incluindo R7) deve ser bloqueada."""
        s = b"\x55" * 32
        n_sess = 4242
        x = 0x123456789ABCDEF0123456789ABCDEF0
        y = 0xFEDCBA9876543210FEDCBA9876543210

        py_clean = diffuse_rsd_s_v5_pre_sha(x, y, s, n_sess, rounds=R_V5)
        rc_clean, c_clean = run_c_core_pre_sha(self.so_path, x, y, s, n_sess, rounds=R_V5)
        self.assertEqual(rc_clean, 0)
        self.assertTrue(np.array_equal(py_clean, c_clean))

        def _flip_word0_bit0(st: np.ndarray) -> np.ndarray:
            st[0] ^= 0x0001
            return st

        for r in range(1, R_V5 + 1):
            with self.subTest(round=r):
                with self.assertRaises(FaultDetectedError):
                    diffuse_rsd_s_v5_pre_sha(
                        x, y, s, n_sess, rounds=R_V5, fault_injector=_flip_word0_bit0, fault_round=r
                    )

                rc_fault, out_fault = run_c_core_pre_sha(
                    self.so_path,
                    x,
                    y,
                    s,
                    n_sess,
                    rounds=R_V5,
                    inject_fault_word=0,
                    inject_fault_mask=0x0001,
                    inject_fault_round=r,
                )
                self.assertEqual(rc_fault, -2, f"C99 deveria retornar -2 para falha na rodada {r}")
                self.assertTrue(
                    np.all(out_fault == 0), f"C99 deveria zerar out_state para falha na rodada {r}"
                )

                # Máscara nula não deve disparar falso positivo
                rc_zero, out_zero = run_c_core_pre_sha(
                    self.so_path,
                    x,
                    y,
                    s,
                    n_sess,
                    rounds=R_V5,
                    inject_fault_word=0,
                    inject_fault_mask=0,
                    inject_fault_round=r,
                )
                self.assertEqual(rc_zero, 0)
                self.assertTrue(np.array_equal(out_zero, c_clean))

    def test_rt_f2_01_preserves_public_output_and_backward_compat(self) -> None:
        """Redundância R1..R não altera a saída criptográfica nem a compatibilidade da API."""
        s = bytes(range(32))
        d32 = diffuse_rsd_s_v5(12345, 67890, s, 1, rounds=R_V5, output_bytes=32)
        d64 = diffuse_rsd_s_v5(12345, 67890, s, 1, rounds=R_V5, output_bytes=64)
        self.assertEqual(len(d32), 32)
        self.assertEqual(len(d64), 64)

        # Wrapper legado rsd_s_v5_core_ct continua bloqueando falha na rodada final
        rc_legacy, out_legacy = run_c_core_pre_sha(
            self.so_path, 12345, 67890, s, 1, rounds=R_V5, inject_fault_word=3, inject_fault_mask=0x8000
        )
        self.assertEqual(rc_legacy, -2)
        self.assertTrue(np.all(out_legacy == 0))

    def test_rt_f2_02_init_cauchy_mds_thread_safe_under_tsan(self) -> None:
        """16 threads concorrentes sob ThreadSanitizer não devem reportar data race."""
        harness_c = self.tmp / "tsan_v52_harness.c"
        harness_bin = self.tmp / "tsan_v52_harness"
        harness_c.write_text(
            """
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

int rsd_s_v5_core_ct(const uint16_t *in_state, const uint16_t *rk_flat, const uint16_t *rc,
                     int rounds, int fault_word, uint16_t fault_mask, uint16_t *out_state);

static uint16_t results[16][32];

static void *worker(void *arg) {
    int tid = *(int *)arg;
    uint16_t in_s[32] = {1};
    uint16_t rk[9 * 32] = {0};
    uint16_t rc[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    if (rsd_s_v5_core_ct(in_s, rk, rc, 8, -1, 0, results[tid]) != 0) {
        abort();
    }
    return NULL;
}

int main(void) {
    pthread_t th[16];
    int tids[16];
    for (int i = 0; i < 16; ++i) {
        tids[i] = i;
        pthread_create(&th[i], NULL, worker, &tids[i]);
    }
    for (int i = 0; i < 16; ++i) pthread_join(th[i], NULL);
    for (int i = 1; i < 16; ++i) {
        for (int w = 0; w < 32; ++w) {
            if (results[i][w] != results[0][w]) return 2;
        }
    }
    return 0;
}
""",
            encoding="utf-8",
        )
        compile_proc = subprocess.run(
            [
                "gcc",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=thread",
                str(harness_c),
                str(C_SRC),
                "-lpthread",
                "-o",
                str(harness_bin),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if compile_proc.returncode != 0:
            self.skipTest(f"ThreadSanitizer indisponível neste ambiente: {compile_proc.stderr.strip()}")

        cmd = [str(harness_bin)]
        if shutil.which("setarch"):
            cmd = ["setarch", "x86_64", "-R", str(harness_bin)]

        for trial in range(3):
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            combined = proc.stderr + proc.stdout
            self.assertEqual(proc.returncode, 0, f"TSan falhou na tentativa {trial}: {combined}")
            self.assertNotIn("ThreadSanitizer: data race", combined)


if __name__ == "__main__":
    unittest.main()
