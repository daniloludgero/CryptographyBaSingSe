# Registro de mudanças

Todas as mudanças relevantes do **BaSingSe (RSD-S)** ficam neste arquivo. O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e as versões seguem o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

---

## [0.6.0] - 2026-11-22

> **Mudança de licença.** A partir desta versão o projeto usa a [PolyForm Noncommercial 1.0.0](LICENSE) e licença comercial concedida pelo autor ([`COMMERCIAL.md`](COMMERCIAL.md)). As versões v0.4.0 a v0.5.2 continuam disponíveis para quem as obteve sob a licença MIT com que foram publicadas.

### Adicionado
- Repositório comercial do BaSingSe, com a RSD-S v5.2 como foco: `README.md` e `README.en.md`, [`COMMERCIAL.md`](COMMERCIAL.md), [`CLA.md`](CLA.md), [`NOTICE`](NOTICE), política de segurança com formulário, política de marca e identidade visual em [`assets/`](assets/).
- Subcomando `kat52` em `ferramentas/rsd_cli.py`, que confere os vetores congelados da v5.2.
- `ferramentas/verificar_higiene.py` e `testes/test_higiene.py`: detecção de segredos e arquivos sensíveis, executada na CI e no portão de release.
- Documentos de evidência em [`docs/evidencia/`](docs/evidencia/): objetivo e modelo de ameaça, garantias e limites, cobertura de criptoanálise e [desafio público](docs/DESAFIO.md).

- **Medições da v5.2** em [`docs/evidencia/MEDICOES_V5_2.md`](docs/evidencia/MEDICOES_V5_2.md): latência do núcleo C99, custo do Anti-DFA, TVLA com controle, paridade C99 × Python, ataque Square de 3 rodadas reproduzido e comparativo com o AES. Dados brutos em [`resultados/v5_2/`](resultados/v5_2/) e ferramenta reproduzível em [`ferramentas/medicao_v52/`](ferramentas/medicao_v52/).
- `testes/test_matriz_b.py`: confere `det(B) mod 65537 = 31974`.
- **Prova das correções da v5.2** em [`docs/evidencia/CORRECOES_V5_2.md`](docs/evidencia/CORRECOES_V5_2.md): o mesmo exploit da v5.1 é executado contra o código v5.1 e contra o v5.2 (`ferramentas/verificacao_correcoes_v52/reproduzir.py`). Os 2 achados Altos e os 3 Médios ficam bloqueados; os 4 Baixos continuam como estavam.

### Corrigido
- **Desempenho:** o README citava 16,26 µs por chamada (v5.1, outra CPU). Na v5.2 o núcleo leva **29,6 µs**, porque o Anti-DFA agora cobre todas as rodadas (custo de 1,95×).
- **Comparativo linear com o AES:** o relatório R5 comparava a RSD-S com N = 524 288 contra o AES com N = 16 384. Com máscaras genéricas e o mesmo N, a RSD-S é detectada em 0R e o AES em 1R; com máscaras estruturais da MDS, a RSD-S é detectada em 1R.
- **Tempo constante:** o \|t\| de 0,32 era da v5.1; na v5.2 o máximo foi 2,30 em 12 execuções (controle 2,18).
- **Quebra de 3 rodadas:** reproduzida na v5.2 em cerca de 10 s (o relatório da v5.1 dizia 296 s).
- `testes/test_r5_m4_red_team_offensive.py`, teste 05: a afirmação "falha em R-1 passa despercebida" passava na v5.2 e contradizia a correção do RT-F2-01. O teste agora injeta a falha **dentro** da execução em cada rodada (detectada) e trata a corrupção **entre duas chamadas** como o limite declarado que é.
- Comentários do cabeçalho de `rsd_s_v5_ct.c` (versão, 6 multiplicações, Anti-DFA em `R1..R`). O código de máquina gerado não mudou.

### Alterado
- `ESPECIFICACAO_V5_AAA.md` passou a [`ESPECIFICACAO_V5_2.md`](especificacao/ESPECIFICACAO_V5_2.md), com correções: 6 multiplicações (e não 5) na inversão de Itoh–Tsujii; descrição do Anti-DFA por dois fluxos A/B em `R1..R`; *folding* por SHAKE-256; definição completa da permutação e da saída; limite de reprodutibilidade do `float64` na matriz `B`; seção quântica sem alegação de prontidão.
- O rascunho QROM passou a [`REDUCAO_QROM_RASCUNHO_V5_1.md`](especificacao/REDUCAO_QROM_RASCUNHO_V5_1.md), com aviso das divergências em relação à v5.2 e correção do mínimo de S-boxes ativas em 4 rodadas (66, e não 132).
- CI e release com ações fixadas por SHA de commit.
- Relatórios históricos de resultados receberam nota de versão e tiveram caminhos locais e referências internas removidos, sem alterar nenhum número.

### Removido
- Laboratório web, páginas e material de estratégia interna da árvore pública.
- Fórmulas CNF acima de 1 MB da árvore: passam a ser *assets* de release, com soma SHA-256 ([`ferramentas/LEIAME_CNF.md`](ferramentas/LEIAME_CNF.md)).

---

## Histórico anterior (versões publicadas sob licença MIT)

> Os links e nomes de arquivo nas entradas abaixo refletem o repositório na época e podem apontar para arquivos que não existem mais.

## [0.5.2] - 2026-11-22

> **Experimental Research Status (`especificacao/RESTRICOES_DE_PROJETO.md`):** `RSD-S v5.2` is an experimental symmetric diffusion/PRF research prototype. While it does not rely on integer factorization or discrete logarithms (the problems attacked by Shor's algorithm), this release makes **no claim** of post-quantum certification, beating Shor, or production readiness without independent external peer review and a formally verified QROM proof.

### Security
- **RT-F2-01 (High — End-to-End Anti-DFA Redundancy R1..R):** Extended dual-execution fault-detection redundancy across all rounds `1..rounds` in both `implementacao/c_core/rsd_s_v5_ct.c` and `implementacao/rsd_s_v5_hardened.py`, blocking fault injection in intermediate rounds (including `R-1`) and zeroing output on divergence.
- **RT-F2-02 (High — Thread-Safe MDS Table Initialization):** Hardened `init_cauchy_mds()` in `implementacao/c_core/rsd_s_v5_ct.c` with atomic acquire/release synchronization (`__atomic_load_n` / `__atomic_compare_exchange_n`), eliminating data races under ThreadSanitizer.
- **RT-F1-01 (Medium — Full PRF Key-Word Expansion):** Updated `expand_key_words_v5()` in `implementacao/rsd_s_v5_hardened.py` to derive all expansion blocks (`block_idx = 0, 1, ...`) via domain-separated `HMAC-SHA256(key_bytes, b"EXP|" + block_idx.to_bytes(4, "big"))` with `n_words >= 1` validation, eliminating literal exposure of `keys[r]` in `rk[r][0..15]` while maintaining bit-exact Python ↔ C99 parity. *(Note: intentionally changes `v5` digest outputs relative to `v0.5.1`; `v4` KATs remain untouched.)*
- **RT-F2-03 (Medium — Public API Secret State Isolation):** Removed `"s_priv_state"` from the default dictionary returned by `BandlimitedDualKeyEngine.refactor_public_output()` in `implementacao/bandlimited_dual_key.py`; internal/audit callers must opt in explicitly via the keyword-only flag `include_private_debug=True`.
- **RT-F2-04 (Medium — Branchless Z_65537 Boundary Folding):** Replaced the data-dependent branch in `_unpadded_z65537_to_bytes64()` (`implementacao/bandlimited_dual_key.py`) with a vectorized branchless NumPy implementation using a single `SHAKE-256(DOMAIN_DUALKEY || "FOLD16|V5.2|" || n_sess_8B || s_priv_bytes)` stream and arithmetic masking, plus explicit `Z_65537` range validation (`ValueError` on `< 0`, `>= 65537`, or non-1D inputs), reducing randomized Welch timing leakage to noise (`|t| < 4.5`) while preserving `TVD = 0`.

### Added
- **Deterministic v5.2 Regression Suites:** Added `testes/test_v52_high_fixes.py` (RT-F2-01, RT-F2-02) and `testes/test_v52_medium_fixes.py` (RT-F1-01, RT-F2-03, RT-F2-04; stdlib `unittest` + `numpy` only) and wired both into `.github/workflows/ci.yml` and `.github/workflows/release.yml`.

### Changed
- Updated `pyproject.toml` package version to `0.5.2`, `especificacao/ESPECIFICACAO_V5_AAA.md` key-expansion description, and red-team/benchmark test suites to reflect the `v0.5.2` mitigations.

---

## [0.5.1] - 2026-11-22

### Added
- **RSD-S v5.1 Hardened Core (`implementacao/rsd_s_v5_hardened.py`, `implementacao/c_core/rsd_s_v5_ct.c`):** 8-round SPN over $\mathbb{F}_{2^{16}}$ with Itoh-Tsujii inversion + affine S-box `A_16`, asymmetric Cauchy MDS column permutation `p(j) = (5j + 1) mod 32` breaking the $M^2 = cI$ involution invariant while preserving branch number $\mathcal{B} = 33$, and AVX2 constant-time C99 vectorization (`CAUCHY_BIT_BASIS`).
- **Bandlimited Dual-Key SIV Layer (`implementacao/bandlimited_dual_key.py`):** Synthetic-IV (SIV) noise derivation binding `e_priv` to `(s, n_sess, S_priv)` to block nonce-reuse $\Delta S_{\text{priv}}$ recovery, plus compact 64-byte unpadded serialization over $\mathbb{Z}_{65537}^{32}$.
- **Cryptanalysis & Audit Campaigns (R3/R4/R5):** Added per-metric surgical audit suites, QROM reduction draft (`especificacao/QROM_REDUCTION_DRAFT_V51.md`), and offensive red-team test suite (`testes/test_r5_m4_red_team_offensive.py`).

---

## [0.4.1] - 2026-10-18

### Added
- **Interactive Cryptanalysis Web Laboratory (`docs/index.html`)**: Browser-based interactive workbench for exploring $\mathbb{F}_{2^{16}}$ inversion (`0x1100B`), $32 \times 32$ Cauchy MDS diffusion, `v1` (128-bit truncation bug) vs `v4` (256-bit full $\mathbb{F}_p$ coverage) bit-flip behavior, Known-Answer Test (KAT) vector verification, and Wide-Trail / SAT / SMT bounds.
- **Developer Quickstart CLI (`ferramentas/rsd_cli.py`)**: Zero-friction command-line interface supporting `kat`, `demo`, `bounds`, and `hash` subcommands with machine-readable `--json` output in under 10 seconds.
- **Python Packaging (`pyproject.toml`, `requirements.txt`)**: Standardized package metadata for `basingse-rsd-s`.
- **GitHub Engineering & CI/CD Automation (`.github/`)**: Multi-Python (`3.10–3.12`) and multi-NumPy (`1.26.x`, `2.x`) CI quality gates, tag-triggered release automation, GitHub Pages deployment, structured YAML issue forms (including Cryptanalysis Finding reports), PR template, and Dependabot configuration.
- **OSS Governance & Commercial Strategy**: Added `LICENSE` (MIT), `TRADEMARK_POLICY.md`, `CITATION.cff`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `docs/strategy/OSS_COMMERCIAL_STRATEGY.md`, and `docs/growth/GITHUB_LAUNCH_PLAYBOOK.md`.

### Fixed
- **NumPy 1.26 / 2.x Cross-Version Compatibility**: Cast Python scalar `int` operands to `np.uint64` during in-place XOR (`^=`) operations on `dtype=np.uint64` arrays in `implementacao/analise_duas_rodadas.py` and `implementacao/busca_branch_bound.py`, resolving `TypeError` on NumPy 1.26 while preserving bit-identical behavior and KAT outputs on NumPy 2.x.

---

## [0.4.0] - 2026-08-09

### Added
- **RSD-S v4 Official Specification & Implementation (`implementacao/rsd_s_v4_final.py`)**:
  - Full 256-bit input fragmentation (16 slices of 16 bits per scalar $x, y \in \mathbb{F}_p$, $p = 2^{255}-19$) into a 32-word (512-bit) internal state, eliminating the silent 127-bit truncation of `v1–v3`.
  - Expanded $32 \times 32$ Cauchy MDS matrix over $\mathbb{F}_{2^{16}}$ with verified branch number 33 (`implementacao/mds_real.py`).
  - Bijective 16-bit inversion S-box over $\mathbb{F}_{2^{16}} / (x^{16} + x^{12} + x^3 + x + 1)$ (`0x1100B`) with proven differential uniformity 4 ($2^{-14}$ max differential probability) and max Walsh magnitude 512 ($2^{-7}$ max linear correlation).
  - Strict input contract validation (`validate_inputs`) rejecting out-of-range field elements, non-32-byte keys, and invalid session nonces.
- **Formal SAT/SMT & Differential Trail Analysis Suite**:
  - Algebraic and Z3 SMT proof of exact S-box DDT uniformity (`ferramentas/prova_ddt_smt.py`).
  - Boolean MDS bit-matrix verification (`implementacao/mds_bitmatrix.py`) and greedy common-subexpression XOR circuit synthesis reducing 130,848 XOR gates to 45,050 gates (`-65.57%`, `implementacao/mds_xor_synthesis.py`).
  - Exact DIMACS CNF encodings for $\mathbb{F}_{2^{16}}$ inversion (`implementacao/gf16_inverse_cnf.py`), first round (`implementacao/rsd_round_cnf.py`), and compact differential queries (`implementacao/rsd_differential_cnf.py`).
  - Multi-round concrete witness propagation (`implementacao/analise_duas_rodadas.py`), branch-and-bound search (`implementacao/busca_branch_bound.py`, best discovered 4-round characteristic weight $2^{-1439}$), and diversified background search (`implementacao/busca_diversificada.py`).
  - Conservative Wide-Trail dynamic programming bounds (`implementacao/analise_wide_trail.py`) establishing $\ge 66, 99, 132, 165$ active S-boxes for $4, 6, 8, 10$ rounds.
  - Known-Answer Test vectors (`testes/vetores_v4.json`) and 29 deterministic unit tests (`testes/test_rsd_s_v4.py`).
  - Historical implementations (`v1`, `v2`, `v3`) and empirical reports in `RELATORIO_FINAL.md` and `resultados/`.
