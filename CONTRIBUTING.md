# Como contribuir

Obrigado pelo interesse no **BaSingSe**. Aqui valem duas regras de integridade antes de qualquer código.

## 1. Regras de integridade científica

1. **Preserve os contratos congelados.** `implementacao/rsd_s_v4_final.py` e os vetores `testes/vetores_v4.json` e `testes/vetores_v52.json` não mudam. Uma proposta de nova versão da primitiva começa numa issue de discussão, nunca num PR direto. As versões históricas (`v1`, `v2`, `v3`) existem para reproduzir o diagnóstico e ficam como estão.
2. **Honestidade intelectual** ([`especificacao/RESTRICOES_DE_PROJETO.md`](especificacao/RESTRICOES_DE_PROJETO.md)):
   - nunca chame um teste estatístico, um escore de avalanche ou um limite de característica única de "prova de segurança";
   - registre `unknown` ou *timeout* de SAT/SMT como **inconclusivo**, nunca como indício de segurança;
   - não escreva "pós-quântico", "inquebrável" ou "pronto para produção".

## 2. Ambiente em 30 segundos

```bash
git clone https://github.com/daniloludgero/CryptographyBaSingSe.git
cd CryptographyBaSingSe
pip install -r requirements.txt
python3 -m unittest discover -s testes -p "test_*.py"
python3 ferramentas/rsd_cli.py kat
python3 ferramentas/rsd_cli.py kat52
```

Para o núcleo C99, tenha `gcc`. Para os modelos SMT, instale `z3-solver`.

## 3. Licença das contribuições (CLA)

Para que o autor possa licenciar o projeto também de forma comercial, toda contribuição exige o aceite do [`CLA.md`](CLA.md). Na primeira contribuição, comente no PR a frase indicada no CLA. **Sem o aceite, o PR não é mesclado.**

## 4. Fluxo de trabalho

- Ramos curtos: `feat/…`, `fix/…`, `docs/…`, `test/…`, `chore/…`.
- Commits pequenos, no estilo Conventional Commits: `tipo(escopo): resumo no imperativo`, com o corpo explicando o **porquê**.
- Abra o PR contra `main` e preencha o modelo.

## 5. Lista antes de abrir o PR

- [ ] `python3 -m unittest discover -s testes -p "test_*.py"` passa
- [ ] `python3 testes/suite_testes_completa.py` passa
- [ ] `python3 ferramentas/rsd_cli.py kat` e `kat52` passam
- [ ] `python3 ferramentas/verificar_higiene.py` passa. Nenhum segredo, `.env`, chave ou `__pycache__` no commit
- [ ] Se mexeu em `site/`: `cd site && npm ci && node --test "testes/*.test.js" "testes/*.e2e.mjs"` passa (veja [`site/README.md`](site/README.md))
- [ ] Resultados novos trazem o ambiente (versões de Python, NumPy e solver, semente e comando) em `resultados/`
- [ ] Você aceitou o CLA
