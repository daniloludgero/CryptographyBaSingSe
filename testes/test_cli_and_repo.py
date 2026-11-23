"""Testes automatizados para a CLI (`rsd_cli.py`), arquivos de governança, licença e imagens do repositório."""

from __future__ import annotations

import io
import json
from pathlib import Path
import re
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "implementacao"))
sys.path.insert(0, str(ROOT / "ferramentas"))

import rsd_cli  # noqa: E402
from rsd_s_v4_final import P_CURVE25519  # noqa: E402


class TestCliCommands(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = rsd_cli.main(argv)
            except SystemExit as exc:
                code = int(exc.code) if isinstance(exc.code, int) else 2
        return code, out.getvalue(), err.getvalue()

    def test_cli_kat_json_passes_all_vectors(self) -> None:
        code, stdout, stderr = self._run_cli(["--json", "kat"])
        self.assertEqual(code, 0, stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["vectors_checked"], 4)
        self.assertTrue(all(item["matched"] for item in payload["results"]))

    def test_cli_demo_json_exposes_v1_truncation_vs_v4_coverage(self) -> None:
        code, stdout, stderr = self._run_cli(["--json", "demo"])
        self.assertEqual(code, 0, stderr)
        payload = json.loads(stdout)
        comp = payload["high_bit_truncation_comparison"]
        self.assertEqual(comp["flipped_bit"], 200)
        self.assertEqual(comp["v1_changed_bits_out_of_256"], 0)
        self.assertGreater(comp["v4_changed_bits_out_of_256"], 100)
        self.assertEqual(payload["four_round_wide_trail_min_active_sboxes"], 66)

    def test_cli_bounds_json_and_invalid_round_edge_cases(self) -> None:
        code, stdout, _ = self._run_cli(["--json", "bounds", "--rounds", "4", "6"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(
            [item["min_active_sboxes"] for item in payload["wide_trail_bounds"]],
            [66, 99],
        )

        for bad_round in ("0", "256", "-3"):
            with self.subTest(bad_round=bad_round):
                bad_code, _, bad_err = self._run_cli(["bounds", "--rounds", bad_round])
                self.assertEqual(bad_code, 2)
                self.assertIn("error", bad_err.lower())

    def test_cli_hash_matches_kat_and_rejects_invalid_inputs(self) -> None:
        code, stdout, stderr = self._run_cli(
            [
                "--json",
                "hash",
                "--x",
                "1",
                "--y",
                "2",
                "--key-hex",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "--session",
                "1",
            ]
        )
        self.assertEqual(code, 0, stderr)
        payload = json.loads(stdout)
        self.assertEqual(
            payload["digest_hex"],
            "38659dbb20ab18e575e635a708bdd67131ab6afefc79b253c246ced16e8a41ac",
        )
        self.assertEqual(len(payload["pre_sha_words_hex"]), 32)

        # Edge cases: x = P_CURVE25519 (out of domain), negative x, bad key length, bad session
        invalid_cases = [
            ["hash", "--x", str(P_CURVE25519), "--y", "0"],
            ["hash", "--x", "-1", "--y", "0"],
            ["hash", "--x", "0", "--y", "0", "--key-hex", "0011"],
            ["hash", "--x", "0", "--y", "0", "--session", "-1"],
            ["hash", "--x", "0", "--y", "0", "--rounds", "0"],
        ]
        for case in invalid_cases:
            with self.subTest(case=case):
                err_code, _, err_out = self._run_cli(case)
                self.assertEqual(err_code, 2)
                self.assertIn("Input validation error", err_out)


class TestRepositoryGovernanceAndAssets(unittest.TestCase):
    def test_required_files_exist(self) -> None:
        required_files = [
            "README.md",
            "README.en.md",
            "LICENSE",
            "NOTICE",
            "COMMERCIAL.md",
            "CLA.md",
            "CHANGELOG.md",
            "TRADEMARK_POLICY.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "GOVERNANCE.md",
            "CITATION.cff",
            "pyproject.toml",
            "requirements.txt",
            ".gitignore",
            ".gitattributes",
            ".github/REPO_METADATA.json",
            ".github/PULL_REQUEST_TEMPLATE.md",
            ".github/CODEOWNERS",
            ".github/FUNDING.yml",
            ".github/dependabot.yml",
            ".github/workflows/ci.yml",
            ".github/workflows/release.yml",
            "especificacao/ESPECIFICACAO_V5_2.md",
            "especificacao/RESTRICOES_DE_PROJETO.md",
            "docs/evidencia/GARANTIAS_E_LIMITES.md",
            "docs/evidencia/COBERTURA_DE_CRIPTOANALISE.md",
            "docs/evidencia/MEDICOES_V5_2.md",
            "ferramentas/medicao_v52/executar_medicao.sh",
            "resultados/v5_2/medicoes_v52_20261123.json",
            "docs/evidencia/OBJETIVO_E_MODELO_DE_AMEACA.md",
            "docs/DESAFIO.md",
            "docs/historia/RELATORIO_FINAL.md",
            "testes/vetores_v52.json",
        ]
        for rel_path in required_files:
            with self.subTest(path=rel_path):
                path = ROOT / rel_path
                self.assertTrue(path.is_file(), f"Missing required file: {rel_path}")
                self.assertGreater(path.stat().st_size, 20, f"Empty file: {rel_path}")

    def test_repo_metadata_adheres_to_github_seo_constraints(self) -> None:
        meta = json.loads((ROOT / ".github" / "REPO_METADATA.json").read_text(encoding="utf-8"))
        self.assertLessEqual(len(meta["description"]), 350)
        self.assertGreaterEqual(len(meta["topics"]), 5)
        self.assertLessEqual(len(meta["topics"]), 20)
        self.assertEqual(meta["license"], "PolyForm-Noncommercial-1.0.0")

    def test_license_is_polyform_noncommercial_verbatim(self) -> None:
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# PolyForm Noncommercial License 1.0.0"))
        self.assertIn("https://polyformproject.org/licenses/noncommercial/1.0.0", text)
        self.assertEqual(len(text.encode("utf-8")), 4563)

    def test_social_and_readme_images_are_present_and_light(self) -> None:
        expected = {
            "assets/derivados/imagem-social-1280x640.png": (1280, 640, 1_000_000),
            "assets/derivados/cabecalho-readme-dia-640x320.png": (640, 320, 1_000_000),
            "assets/derivados/cabecalho-readme-noite-640x320.png": (640, 320, 1_000_000),
        }
        for rel, (w, h, limit) in expected.items():
            with self.subTest(img=rel):
                data = (ROOT / rel).read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(int.from_bytes(data[16:20], "big"), w)
                self.assertEqual(int.from_bytes(data[20:24], "big"), h)
                self.assertLess(len(data), limit)

    def test_readme_relative_links_resolve(self) -> None:
        link = re.compile(r"(?:\]\(|src=\"|srcset=\")([^)\"#\s]+)")
        for name in ("README.md", "README.en.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            for target in link.findall(text):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                with self.subTest(readme=name, target=target):
                    self.assertTrue((ROOT / target).exists(), f"{name}: link quebrado -> {target}")

    def test_cli_kat52_passes_all_v52_vectors(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rsd_cli.main(["--json", "kat52"])
        self.assertEqual(code, 0, err.getvalue())
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["status"], "PASS")
        self.assertGreaterEqual(payload["vectors_checked"], 6)
        self.assertTrue(all(item["matched"] for item in payload["results"]))


if __name__ == "__main__":
    unittest.main()
