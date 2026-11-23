# Relatório Técnico de Red-Team Ofensivo — Marco M_R5_4 (`RSD-S v5.1`)

- **Data:** 2026-11-22
- **Escopo:** Auditoria ofensiva de criptoanálise (Frente 1) e segurança de implementação/falhas/canais laterais/API (Frente 2) sobre `RSD-S v5.1` (`implementacao/rsd_s_v5_hardened.py`, `implementacao/c_core/rsd_s_v5_ct.c`, `implementacao/bandlimited_dual_key.py`).
- **Suíte executável:** [`testes/test_r5_m4_red_team_offensive.py`](../../testes/test_r5_m4_red_team_offensive.py)
- **Comando executado:** `python3 -m pytest testes/test_r5_m4_red_team_offensive.py -v -s`
- **Resultado:** **8/8 testes passando** em 125,75 s (compilação C99 AVX2 com `gcc -O3 -mavx2 -Wall -Wextra -Werror -shared -fPIC` em `/tmp/r5_m4_build/lib_rsd_v5.so`).

---

## Resumo Executivo e Classificação de Severidade

| ID | Frente | Achado / Vetor Testado | Severidade | Status |
|---|---|---|---|---|
| **RT-F2-01** | Implementação / DFA | Bypass total da proteção Anti-DFA por injeção de falha na penúltima rodada `R-1` (R7) — passa 100% despercebida (`rc == 0`) em C99 e Python | **Alta** | Confirmado |
| **RT-F2-02** | Concorrência | Data race em `init_cauchy_mds()` (`CAUCHY_INIT` não atômico) sob 16 threads simultâneas — detectado pelo ThreadSanitizer (`exit=66`) | **Alta** | Confirmado |
| **RT-F1-01** | Criptoanálise / Key Schedule | `expand_key_words_v5(keys[r])` expõe `keys[r]` literalmente em `rk[r][0..15]`, permitindo reconstruir `rk[r][16..31]` sem a chave mestra `s` | **Média** | Confirmado |
| **RT-F2-03** | API | `BandlimitedDualKeyEngine.refactor_public_output` expõe `s_priv_state` (estado secreto pré-SHA) no dicionário de retorno público | **Média** | Confirmado |
| **RT-F2-04** | Side-Channel Python | Vazamento de timing aleatorizado em `_unpadded_z65537_to_bytes64`: pior caso `0/32` vs `32/32` (`Welch t = 9,11`, `p = 2,36e-19`) e realista `0/32` vs `1/32` (`Welch t = 20,35`, `p = 3,17e-85`) | **Média** | Confirmado |
| **RT-F2-05** | Folding / Serialização | Colisão 2-para-1 estrutural na função isolada `_unpadded_z65537_to_bytes64` (`65536` vs `36475` em 64B para `s_priv_bytes` fixo); no `BandlimitedDualKeyEngine` completo, `(x, y)` distintos geram `s_priv_bytes` distintos | **Baixa** | Confirmado |
| **RT-F2-06** | Memória / AVX2 | `sizeof(CAUCHY_BIT_BASIS) == 32768` bytes (100% de L1D 32 KB); `objdump -d` confirma `vzeroupper` antes do `ret` principal (limpa bits `128..255` de `ymm`), mas sem `vzeroall`/`vpxor` para zerar `xmm0..xmm15` (bits `0..127`) | **Baixa** | Confirmado |
| **RT-F1-02** | Criptoanálise / Entrada | `fragment_full_v5(x, y)` fixa sempre os 2 MSBs (`state[15] >> 15 == 0` e `state[31] >> 15 == 0`) para todo `x, y < 2^255 - 19`; viés persiste determinístico pós-`rk[0]` e dissipa após 1R (`130/256`, `139/256`) | **Baixa** | Confirmado (dissipado em 1R) |
| **RT-F1-03** | Criptoanálise / Subespaço | `round_constant_v5` é constante nas 32 palavras e `M_CAUCHY_32` tem soma de linha constante (`0x1731`) nas 32 linhas; somente `rk[r]` quebra o subespaço simétrico `S_eq` em 1R–2R | **Baixa** | Confirmado (mitigado por `rk[r]`) |
| **RT-F1-04** | Criptoanálise / Boomerang | Sonda *switch* `M`-alinhada (`N=500`) atinge `500/500` em 1R, caindo a `0/500` em 2R–4R (`aligned_trunc(<32)`: `0/500` em 2R–3R; `1/500` em 4R é ruído estatístico esperado) | **Mitigada** | Margem >= 6R sobre 2R |
| **RT-F1-05** | Criptoanálise / Impossível & MitM | MDS `B=33` (`min_active_words=32` em 1000 pares 1R); diferencial impossível 2R (`0/8192`) violado em 3R (`9/8192`); barreira MitM com dependência `32/32` em `fwd_1R` e `bwd_1R` | **Mitigada** | Margem >= 5R sobre 3R |
| **RT-F1-06** | Criptoanálise / Algébrica & Integral | Grau ANF exato `15` nas 16 coordenadas de `sbox_v5_eval`; recuperação 1R (`rk[1]` dado `rk[0]`) vs `2R=64`, `3R=96`, `8R=256` S-boxes; $\Lambda$-set `2^16` zera em 1R–2R (`0/32`) e quebra em 3R–4R (`32/32`) | **Mitigada** | Margem >= 5R sobre 3R |
| **RT-F1-07** | Slide / Related-Key | `_domain_tag` com `rounds` e `n_sess` produz distância de Hamming `0,4897` (rounds), `0,5013` (sessão) e `0,4918` (related-key 1-bit) | **Mitigada** | Eficaz |
| **RT-F2-07** | API / Fuzzing | `41/41` casos de fronteira (entradas inválidas, limites válidos, `verify_public_output`, `_unpadded_z65537_to_bytes64` fora de $\mathbb{Z}_{65537}$ e API C) verificados | **Mitigada** | Eficaz |

---

## Frente 1 — Criptoanálise Ofensiva (`RSD-S v5.1`)

### 1. Boomerang / Rectangle (`1R–4R pre_sha`)
Testado em `test_01_boomerang_rectangle_1r_to_4r` sobre `rsd_s_v5_core_ct` truncado (`N = 500` quartetos por número de rodadas, `alpha` de 1 bit na palavra 0).
- **Nota metodológica:** `beta_aligned = M * e_1` foi utilizado como sonda *switch* alinhada para 1 rodada; não foi executada busca de trilha boomerang multi-rodada ótima.
- **Resultados empíricos:**
  - **1R:** `aligned_exact = 500/500`, `aligned_trunc(<32) = 500/500`, `1word_exact = 0/500`.
  - **2R:** `aligned_exact = 0/500`, `aligned_trunc(<32) = 0/500`, `1word_exact = 0/500`.
  - **3R:** `aligned_exact = 0/500`, `aligned_trunc(<32) = 0/500`, `1word_exact = 0/500`.
  - **4R:** `aligned_exact = 0/500`, `aligned_trunc(<32) = 1/500`, `1word_exact = 0/500`. O valor `1/500` em `aligned_trunc(<32)` corresponde ao ruído estatístico esperado para permutação aleatória ($\mathbb{E}[X] = 500 \cdot 32 / 65536 \approx 0{,}244$).

### 2. Diferencial Impossível & Barreira Meet-in-the-Middle (`1R–3R`)
Testado em `test_02_impossible_differential_mds_and_mitm_2r_vs_3r`:
- **Propriedade MDS (`B = 33`) em 1R:** Em `1.000` diferenciais aleatórios de 1 palavra ativa, o mínimo de palavras ativas após 1R foi **`32/32`** (`0` transições `1 -> <32`).
- **Distinguidor Diferencial Impossível (`2R` vs `3R`, `N = 8.192` pares de 1 palavra ativa):**
  - **2R:** `wt_word(M^{-1}(out_diff)) < 32` ocorreu **`0 / 8.192`** vezes (estritamente impossível).
  - **3R:** `wt_word(M^{-1}(out_diff)) < 32` ocorreu **`9 / 8.192`** vezes (compatível com o esperado aleatório `~32 / 65536 = 4,88e-4`, média `~4,00`).
- **Barreira Meet-in-the-Middle (MitM) `2R/3R`:** Validada consistência exata no estado intermediário de 2R (`32/32` palavras entre `mid_fwd` e `mid_bwd`). Ao perturbar 1 bit em `P` ou em `C`, a dependência observada no ponto de encontro foi **`fwd_1R = 32/32`** e **`bwd_1R = 32/32`**, impedindo particionamento parcial independente de palavras em `>= 3R`.

### 3. Slide / Related-Key / Subespaço Simétrico / Key Schedule / Viés de Entrada
Testado em `test_03_slide_related_key_symmetric_subspace_key_schedule_and_input_bias`:
- **Separação de domínio HMAC-SHA256 (`_domain_tag`):** Distâncias de Hamming normalizadas de **`0,4897`** (`rounds=8` vs `7`), **`0,5013`** (`n_sess=0` vs `1`) e **`0,4918`** (`s` vs `s ^ 0x01`).
- **Simetria de `rc(r)` e `M_CAUCHY_32`:** `round_constant_v5` é idêntico nas 32 palavras e todas as 32 linhas de `M_CAUCHY_32` possuem a mesma soma (`0x1731`, `1/32` somas distintas). O subespaço simétrico `S_eq = {(c, ..., c)}` é quebrado exclusivamente por `rk[r]`.
- **Achado real de Key Schedule (`RT-F1-01`, Média):** `expand_key_words_v5(keys[r])` copia `keys[r]` literalmente para `rk[r][0..15]`, permitindo reconstruir **100% de `rk[r][16..31]`** sem conhecer `s`.
- **Achado real de Entrada (`RT-F1-02`, Baixa):** `fragment_full_v5(x, y)` fixa sempre `state[15] >> 15 == 0` e `state[31] >> 15 == 0` (`0/256`), persistindo pós-`rk[0]` e dissipando após **1R** (`130/256` e `139/256`).

### 4. Algébrica (ANF) & Integral / Square (`1R–4R`)
Testado em `test_04_algebraic_anf_degree_and_integral_division_property`:
- **Grau ANF de `sbox_v5_eval` (`A_16`):** Transformada de Möbius sobre `GF(2)^16` confirmou grau **`15`** em todas as 16 coordenadas de saída.
- **Recuperação algébrica em 1R e contagem estrutural para 2R–8R:** Em 1R, conhecido `rk[0]`, `rk[1]` é recuperado algebricamente em 1 consulta. Para múltiplas rodadas (sem execução de solver SAT/MILP completo), o número de S-boxes ativas de grau 15 escala linearmente: **`2R = 64`**, **`3R = 96`**, **`8R = 256`** S-boxes.
- **Propriedade Integral / Division Property empírica ($\Lambda$-set Square de `2^16 = 65.536` textos em 1 palavra):**
  - **1R:** `0 / 32` palavras com soma XOR != 0.
  - **2R:** `0 / 32` palavras com soma XOR != 0.
  - **3R:** `32 / 32` palavras com soma XOR != 0.
  - **4R:** `32 / 32` palavras com soma XOR != 0.

---

## Frente 2 — Implementação / Fault / Side-Channel / API

### 1. DFA / SIFA na Penúltima Rodada `R-1` (R7) (`RT-F2-01` — Severidade Alta)
Testado em `test_05_dfa_sifa_penultimate_round_r7_bypass`:
- Falha em `R=8` é bloqueada (`FaultDetectedError` em Python; `rc == -2` e `out_state == 0` em C99). `fault_mask == 0` retorna `rc == 0`.
- **Bypass em R7 (`R-1`):** Falha injetada na saída de R7 propaga identicamente para `state_a` e `state_b` de R8, retornando **`status == 0`** com saída corrompida tanto em C99 quanto em Python.

### 2. Concorrência, Cache L1D e Assembly AVX2 (`RT-F2-02` Alta, `RT-F2-06` Baixa)
Testado em `test_06_concurrency_data_race_tsan_cache_size_and_avx2_objdump`:
- **Data Race (ThreadSanitizer):** Sob `setarch x86_64 -R` com 16 pthreads simultâneas, TSan detectou **`WARNING: ThreadSanitizer: data race`** (`exit=66`) em `init_cauchy_mds` (`rsd_s_v5_ct.c:182, 189, 193`) sobre `CAUCHY_MDS`, `CAUCHY_BIT_BASIS` e `CAUCHY_INIT` não atômico.
- **Footprint L1D:** `sizeof(CAUCHY_BIT_BASIS) = 32.768 bytes` (32 KB L1D).
- **Assembly AVX2 (`objdump -d`):** Em `rsd_s_v5_core_ct` (`2.156` linhas), a janela imediatamente anterior à instrução `ret` principal contém `vzeroupper` (que limpa apenas os bits `128..255` de `ymm`), mas **não contém `vzeroall` nem `vpxor`** limpando `xmm0..xmm15` (bits `0..127`).

### 3. Timing Aleatorizado & Colisão 2-para-1 em `_unpadded_z65537_to_bytes64` (`RT-F2-04` Média, `RT-F2-05` Baixa)
Testado em `test_07_python_folding_timing_welch_and_2to1_collision` (`N = 1.500` amostras por classe, ordem aleatorizada):
- **Cenário (a) pior caso (`0/32` vs `32/32` palavras `== 65536`):** `mean0 = 7.570,3 ns` vs `mean32 = 52.046,8 ns` (**`Welch t = 9,11`**, **`p = 2,36e-19`**).
- **Cenário (b) realista (`0/32` vs `1/32` palavra `== 65536`):** `mean0 = 6.254,5 ns` vs `mean1 = 7.780,1 ns` (**`Welch t = 20,35`**, **`p = 3,17e-85`**) — mesmo uma única coordenada `65536` gera vazamento mensurável pelo ramo condicional `sha256`.
- **Colisão 2-para-1:** Na função isolada `_unpadded_z65537_to_bytes64` (fixado `s_priv_bytes`), `vec_a[0] = 65536` e `vec_b[0] = 36475` colidem em `y_pub_bytes` (64B), permanecendo distinguíveis em `y_pub_z65537_bytes` (96B) e `y_pub_digest_256`. No `BandlimitedDualKeyEngine` completo, entradas `(x, y)` distintas produzem `s_priv_bytes` distintos via SPN bijetora.

### 4. API & Boundary Fuzzing (`RT-F2-03` Média, `RT-F2-07` Mitigada)
Testado em `test_08_api_s_priv_exposure_and_boundary_fuzzing`:
- `BandlimitedDualKeyEngine.refactor_public_output` expõe `"s_priv_state"` no dicionário de retorno.
- **`41/41` casos de fronteira** verificados com sucesso, incluindo: entradas inválidas em Python (`x, y, n_sess, rounds, output_bytes, s, mode`), fronteiras válidas (`0`, `P_CURVE25519-1`, `n_sess=0` e `2^64-1`, `rounds=1/255`, `output_bytes=64`), `verify_public_output` válido/inválido, `_unpadded_z65537_to_bytes64` com `-1` (`OverflowError`) e `65537` (cai silenciosamente no fallback por ausência de validação superior), e fronteiras da API C (`rounds=0/256` -> `-1`, `NULL` -> `-1`, `fault_word=32` -> `0`).

---

## Conformidade com `especificacao/RESTRICOES_DE_PROJETO.md`

- Os arquivos de implementação (`implementacao/rsd_s_v4_final.py`, `implementacao/rsd_s_v5_hardened.py`, `implementacao/c_core/rsd_s_v5_ct.c`, `implementacao/bandlimited_dual_key.py`) permaneceram **intactos**.
- Este relatório não afirma que a primitiva “supera Shor”, é “pós-quântica certificada” ou está aprovada para produção; todas as vulnerabilidades e margens empíricas foram reportadas de forma estritamente factual.
