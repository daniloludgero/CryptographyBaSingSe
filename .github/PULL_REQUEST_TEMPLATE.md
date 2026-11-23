## Resumo da mudança

<!-- Explique o POR QUÊ, não só o quê. -->

## Relação com issue ou relatório de criptoanálise

- Fecha #

## Disciplina de escopo (o que eu NÃO toquei)

- [ ] `implementacao/rsd_s_v4_final.py` e `testes/vetores_v4.json` permanecem inalterados.
- [ ] `testes/vetores_v52.json` permanece inalterado (ou a mudança é uma proposta de nova versão, discutida antes em issue).
- [ ] As implementações históricas (`v1`, `v2`, `v3`) permanecem preservadas.

## Lista de verificação

- [ ] `python3 -m unittest discover -s testes -p "test_*.py"` passa
- [ ] `python3 ferramentas/rsd_cli.py kat` e `python3 ferramentas/rsd_cli.py kat52` passam
- [ ] `python3 ferramentas/verificar_higiene.py` passa (sem segredos nem arquivos sensíveis)
- [ ] Li e aceito o `CLA.md` (a primeira contribuição pede o aceite no próprio PR)
- [ ] Mensagens de commit seguem Conventional Commits (`feat`, `fix`, `docs`, `test`, `chore`)
- [ ] A documentação respeita `especificacao/RESTRICOES_DE_PROJETO.md`: nenhuma alegação de segurança pós-quântica ou de uso em produção sem prova e revisão externa
