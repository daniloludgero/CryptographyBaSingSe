"""Confere o invariante algébrico da matriz B (módulo de dupla chave) construída em ponto flutuante."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))

from bandlimited_dual_key import BandlimitedDualKeyEngine  # noqa: E402

Q = 65537


def _det_mod_q(rows: list[list[int]]) -> int:
    m = [[int(v) % Q for v in r] for r in rows]
    n = len(m)
    det = 1
    for c in range(n):
        piv = next((r for r in range(c, n) if m[r][c] % Q), None)
        if piv is None:
            return 0
        if piv != c:
            m[c], m[piv] = m[piv], m[c]
            det = -det
        det = det * m[c][c] % Q
        inv = pow(m[c][c], -1, Q)
        for r in range(c + 1, n):
            f = m[r][c] * inv % Q
            if f:
                m[r] = [(a - f * b) % Q for a, b in zip(m[r], m[c])]
    return det % Q


class TestMatrizB(unittest.TestCase):
    def test_determinante_modulo_65537(self) -> None:
        b = BandlimitedDualKeyEngine().B_matrix
        self.assertEqual(b.shape, (32, 32))
        self.assertEqual(_det_mod_q(b.tolist()), 31974)


if __name__ == "__main__":
    unittest.main()
