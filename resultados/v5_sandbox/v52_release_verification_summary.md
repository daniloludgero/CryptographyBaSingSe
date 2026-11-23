# RSD-S v0.5.2 — Resumo de Mitigações e Verificação de Release

**Data:** 2026-11-22  
**Versão:** `v0.5.2`  
**Repositório:** `daniloludgero/CryptographyBaSingSe`  
**Status:** verificação interna por testes automatizados (ver seção 2); **sem revisão independente externa**.

> **Aviso Obrigatório (`especificacao/RESTRICOES_DE_PROJETO.md`):**  
> `RSD-S v5.2` é um **protótipo experimental de pesquisa** de difusão simétrica / PRF. Embora não dependa de fatoração de inteiros ou logaritmo discreto (os problemas atacados pelo algoritmo de Shor), esta release **não possui revisão independente externa, não possui certificação pós-quântica, não alega superar o algoritmo de Shor e não está aprovada para uso em produção** (sem modelo formal completo e prova QROM formalmente verificada por terceiros).

---

## 1. Mitigações Consolidada na Release `v0.5.2`

### 1.1 Achados de Severidade Alta (Commit `3ff0893`)
1. **`RT-F2-01` — Redundância Anti-DFA de Ponta a Ponta (`R1..R`):**
   - Redundância de dupla execução com detecção de falhas estendida para todas as rodadas `1..rounds` em `implementacao/c_core/rsd_s_v5_ct.c` e `implementacao/rsd_s_v5_hardened.py`, bloqueando injeção de falhas em rodadas intermediárias (incluindo `R-1`) e zerando a saída em caso de divergência.
2. **`RT-F2-02` — Inicialização Thread-Safe da Tabela Cauchy MDS:**
   - `init_cauchy_mds()` em `implementacao/c_core/rsd_s_v5_ct.c` endurecida com sincronização atômica acquire/release (`__atomic_load_n` / `__atomic_compare_exchange_n`), eliminando corridas de dados sob ThreadSanitizer.

### 1.2 Achados de Severidade Média (Rodada Atual `v0.5.2`)
3. **`RT-F1-01` — Expansão Completa de Palavras de Chave via PRF (`implementacao/rsd_s_v5_hardened.py`):**
   - `expand_key_words_v5(key_bytes, n_words=W)` atualizada para derivar **todos** os blocos (`block_idx = 0, 1, ...`) via `HMAC-SHA256(key_bytes, b"EXP|" + block_idx.to_bytes(4, "big"))` com validação explícita `n_words >= 1`.
   - Elimina a exposição literal de `keys[r]` em `rk[r][0..15]`, impedindo a reconstrução de `rk[r][16..31]` a partir da primeira metade e preservando paridade bit-a-bit exata Python ↔ C99 (`run_c_core_pre_sha`).
   - *Nota:* altera intencionalmente os digests de `v5` em relação à `v0.5.1`; `implementacao/rsd_s_v4_final.py` e os KATs `v4` permanecem intactos.
4. **`RT-F2-03` — Isolamento de Estado Secreto na API Pública (`implementacao/bandlimited_dual_key.py`):**
   - Removido `"s_priv_state"` do dicionário padrão retornado por `BandlimitedDualKeyEngine.refactor_public_output(...)`.
   - Adicionado parâmetro keyword-only `include_private_debug: bool = False` para uso explícito por chamadores de auditoria/debug interno, mantendo `verify_public_output` compatível.
5. **`RT-F2-04` — Folding Sem Ramificação em $\mathbb{Z}_{65537}$ (`implementacao/bandlimited_dual_key.py`):**
   - `_unpadded_z65537_to_bytes64()` reescrita de forma vetorizada e sem ramificação condicional dependente do valor das coordenadas, utilizando fluxo único `SHAKE-256(DOMAIN_DUALKEY || "FOLD16|V5.2|" || n_sess_8B || s_priv_bytes)` e seleção por máscara aritmética NumPy (`mask = -(y_arr == 65536)`), com validação explícita de faixa `0 <= v < 65537` (`ValueError`).
   - Preserva `TVD = 0` no mapeamento $65536 \to \{0..65535\}$ e reduz o vazamento de timing aleatorizado para a faixa de ruído (`|Welch t| < 4.5`).

---

## 2. Resultados da verificação interna (contagens registradas na data do relatório)

| Verificação | Resultado | Observações |
|---|---|---|
| Suíte Core `unittest` (8 módulos incl. `test_v52_high_fixes.py` e `test_v52_medium_fixes.py`) | **86/86 PASS** | Compatível com stdlib `unittest` + `numpy` (CI/Release) |
| Suíte Básica (`testes/suite_testes_completa.py`) | **5/5 PASS** | Todos os testes básicos aprovados |
| Suíte E2E (`testes_e2e/`) | **113/113 PASS** | Sem regressões de ponta a ponta |
| Suíte Red-Team Ofensiva (`testes/test_r5_m4_red_team_offensive.py`) | **8/8 PASS** | `Welch t = -0.08` e `0.25` (`|t| < 4.5`), `RT-F1-01`/`RT-F2-03`/`RT-F2-04` mitigados |
| Known-Answer Tests (`ferramentas/rsd_cli.py --json kat`) | **4/4 PASS** | Vetores `v4` inalterados |
| Imutabilidade de `implementacao/rsd_s_v4_final.py` | **INTACTO** | `git diff implementacao/rsd_s_v4_final.py` vazio |

---

## 3. Escopo de Integração CI/CD e Empacotamento

- `pyproject.toml` atualizado para `version = "0.5.2"`.
- `CHANGELOG.md` atualizado com as seções `[0.5.2]` e `[0.5.1]` em conformidade com `especificacao/RESTRICOES_DE_PROJETO.md`.
- `.github/workflows/ci.yml` e `.github/workflows/release.yml` atualizados para executar `testes/test_v52_medium_fixes.py` em adição à suíte existente.
- `especificacao/ESPECIFICACAO_V5_2.md` atualizada para refletir a expansão completa de chaves de rodada via `HMAC-SHA256(K_r, "EXP|" || uint32_be(block_idx))`.
