#!/usr/bin/env python3
"""Verificação de higiene: procura segredos e arquivos sensíveis na árvore do repositório.

Falha (código 1) se encontrar nome de arquivo sensível ou conteúdo com padrão de credencial.
Uso: python3 ferramentas/verificar_higiene.py [raiz]
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

NOMES_PROIBIDOS = re.compile(
    r"(^|/)(\.env(\..*)?|id_rsa(\..*)?|id_ed25519(\..*)?|\.netrc|\.npmrc|\.pypirc|credentials.*\.json|"
    r"service-account.*\.json|secrets.*\.(json|ya?ml))$|\.(pem|key|p12|pfx|jks|keystore|kdbx|gpg|tfstate|sqlite3?|dump|log)$"
)
NOMES_PERMITIDOS = re.compile(r"(^|/)\.env\.example$")

PADROES_CONTEUDO = {
    "chave privada PEM": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    "token GitHub": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "token GitHub (fine-grained)": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "chave de acesso AWS": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "chave de API Google": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "token Slack": re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"),
    "token de API (prefixo sk-)": re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{32,}\b"),
    "caminho absoluto de usuário": re.compile(r"(?:/home/[a-z0-9_.-]+/|/Users/[A-Za-z0-9_.-]+/|C:\\\\Users\\\\)"),
}
IGNORAR_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
EXTENSOES_BINARIAS = {".png", ".gif", ".ico", ".gz", ".zip", ".so", ".o", ".pyc", ".cnf"}
ARQUIVOS_DE_REGRAS = {"ferramentas/verificar_higiene.py", "testes/test_higiene.py"}


def listar_arquivos(raiz: Path) -> list[Path]:
    try:
        out = subprocess.run(["git", "-C", str(raiz), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             check=True, capture_output=True).stdout.decode("utf-8")
        files = [raiz / p for p in out.split("\0") if p]
        if files:
            return files
    except (OSError, subprocess.CalledProcessError):
        pass
    return [p for p in raiz.rglob("*") if p.is_file() and not (set(p.relative_to(raiz).parts) & IGNORAR_DIRS)]


def verificar(raiz: Path) -> list[str]:
    problemas: list[str] = []
    for p in listar_arquivos(raiz):
        rel = p.relative_to(raiz).as_posix()
        if NOMES_PROIBIDOS.search(rel) and not NOMES_PERMITIDOS.search(rel):
            problemas.append(f"{rel}: nome de arquivo sensível")
            continue
        if p.suffix in EXTENSOES_BINARIAS or rel in ARQUIVOS_DE_REGRAS or not p.is_file():
            continue
        try:
            texto = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for nome, padrao in PADROES_CONTEUDO.items():
            if padrao.search(texto):
                problemas.append(f"{rel}: padrão de {nome}")
    return problemas


def main(argv: list[str]) -> int:
    raiz = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    problemas = verificar(raiz)
    if problemas:
        print("Higiene: FALHOU")
        for item in problemas:
            print(" -", item)
        return 1
    print("Higiene: OK (nenhum segredo ou arquivo sensível encontrado)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
