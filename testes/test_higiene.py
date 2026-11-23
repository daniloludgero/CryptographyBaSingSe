"""Testes do verificador de higiene (`ferramentas/verificar_higiene.py`)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ferramentas"))

import verificar_higiene  # noqa: E402


class TestHigiene(unittest.TestCase):
    def _tree(self, files: dict[str, str]) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return root

    def test_arvore_limpa_passa(self) -> None:
        root = self._tree({"README.md": "ola", "src/a.py": "x = 1\n", ".env.example": "CHAVE=\n"})
        self.assertEqual(verificar_higiene.verificar(root), [])

    def test_detecta_nomes_sensiveis(self) -> None:
        root = self._tree({".env": "A=1", "chaves/id_rsa": "x", "cert.pem": "x", "app.log": "x"})
        problemas = " ".join(verificar_higiene.verificar(root))
        for nome in (".env", "id_rsa", "cert.pem", "app.log"):
            self.assertIn(nome, problemas)

    def test_detecta_conteudo_de_credencial(self) -> None:
        token = "gh" + "p_" + "A" * 36
        pem = "-----BEGIN " + "PRIVATE KEY-----"
        aws = "AK" + "IA" + "A" * 16
        root = self._tree({"a.txt": token, "b.txt": pem, "c.txt": aws, "d.txt": "/home/pessoa/projeto"})
        problemas = " ".join(verificar_higiene.verificar(root))
        for nome in ("a.txt", "b.txt", "c.txt", "d.txt"):
            self.assertIn(nome, problemas)

    def test_repositorio_atual_esta_limpo(self) -> None:
        self.assertEqual(verificar_higiene.verificar(ROOT), [])


if __name__ == "__main__":
    unittest.main()
