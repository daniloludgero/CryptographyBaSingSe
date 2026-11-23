# Relatório Final Consolidado — Rodada R5 (`RSD-S v5.1` & `Dupla-Chave SIV`)

> **Nota de versão.** Relatório do marco R5, sobre a **v5.1**. Os achados de severidade Alta e Média que ele lista foram corrigidos na v5.2 (ver [`GARANTIAS_E_LIMITES.md`](GARANTIAS_E_LIMITES.md)). Onde o texto diz "aprovado", leia: aprovado nos testes **internos** do projeto. Não houve revisão independente externa.


> [!CAUTION]
> **Conformidade Estrita com [`especificacao/RESTRICOES_DE_PROJETO.md`](../../especificacao/RESTRICOES_DE_PROJETO.md):**
> A primitiva **RSD-S v5.1** é uma construção simétrica experimental de difusão/compressão chaveada. Ela **não se baseia nos problemas atacados por Shor** (fatoração ou logaritmo discreto), mas este relatório **NÃO afirma** que a primitiva “supera Shor”, **NÃO declara** certificação pós-quântica e **NÃO aprova** a primitiva para uso em produção. Todas as medições empíricas de criptoanálise, comparações com AES e reduções formais em QROM são condicionais e dependem de hipóteses não-provadas e revisão externa independente.

---

## 1. Verificação Global de Testes e Integridade (Estado Final R5)

A verificação global executada ao término da consolidação R5 confirmou a integridade do código legado e a aprovação integral de todas as suítes automatizadas (R5 e E2E):

| Verificação | Comando Executado | Resultado Real Observado | Status |
|---|---|---|---|
| **Integridade v4** | `git diff implementacao/rsd_s_v4_final.py` | Saída vazia (`0` alterações) | **PASS** |
| **Suíte R5 (`pytest`)** | `pytest -q testes/test_r5_m1_hardened_margin.py testes/test_r5_m2_aes_prp_comparison.py testes/test_r5_m4_red_team_offensive.py` | `16 passed in 507.03s (0:08:27)` | **PASS (16/16)** |
| **Suíte E2E (`unittest`)** | `python3 -m unittest discover -s testes_e2e -p "test_*.py" -q` | `Ran 113 tests in 27.023s` — `OK` | **PASS (113/113)** |

- **Distribuição dos 16 testes R5:**
  - `M_R5_1` ([`test_r5_m1_hardened_margin.py`](../../testes/test_r5_m1_hardened_margin.py)): `5 passed`
  - `M_R5_2` ([`test_r5_m2_aes_prp_comparison.py`](../../testes/test_r5_m2_aes_prp_comparison.py)): `3 passed`
  - `M_R5_4` ([`test_r5_m4_red_team_offensive.py`](../../testes/test_r5_m4_red_team_offensive.py)): `8 passed`

---

## 2. O que Resistiu e Margem de Segurança por Ataque (`M_R5_1` e Mitigações `M_R5_4`)

Na rodada R4 anterior, o uso de uma entrada fixa (`y=12345`) impedia a detecção do controle `RSD 2R`. Em `M_R5_1`, a bateria foi endurecida em [`testes/r5_metrics_harness.py`](../../testes/r5_metrics_harness.py) com **entradas aleatórias completas de 512 bits** e **truncamento real da agenda de chaves de 8 rodadas** (`RSDKeyedV5`) sobre o núcleo C99 AVX2 constant-time (`with_sha=False` para isolar a difusão SPN).

### 2.1. Detecção Determinística de `RSD 2R` e Margens (`M_R5_1`)

O controle **RSD 2R foi detectado de forma determinística** em duas famílias independentes de criptoanálise, com saturação completa a partir de `3R`:

| Família de Ataque / Métrica | Alcance Máximo Detectado | Total de Rodadas | Margem Absoluta | Margem (%) | Evidência Empírica Chave |
|---|---:|---:|---:|---:|---|
| **Integral / Square (`Lambda-set` $2^{16}$, `trials=2`)** | **2R** | 8R | **6R** | **75,0%** | `32/32` palavras com `XOR == 0` em `1R` e `2R`; `0/32` em `3R..8R`. |
| **Algébrico / ANF (Möbius 16-bit)** | **2R** | 8R | **6R** | **75,0%** | Grau máximo **`15`** (`0/16` bits saturados em grau `16`) em `1R` e `2R`; satura para grau **`16`** em `3R` (`9/16` bits) e `4R` (`5/16` bits). |
| **Diferencial & Truncado ($N=4.096$)** | **1R** | 8R | **7R** | **87,5%** | `1R`: `234` colisões de diferença vs `127,97` esperado (`z = +9,373`). Em `2R..8R`: `z` entre `-2,384` e `+1,859`. |
| **Linear / Walsh (`(M^T)^{-1}`, $N=524.288$, 40 másc.)** | **1R** | 8R | **7R** | **87,5%** | `1R`: `max_abs_corr = 0,009369`, `z = 6,784` (detectado; piso $1/\sqrt{N} \approx 0,001381$). Em `2R..8R`: `max_z` entre `1,842` e `3,019`. |
| **QROM-analog ($n \in \{10,12,14,16\}$)** | **1R** | 8R | **7R** | **87,5%** | `1R` distinguido fortemente com erro padrão de duas amostras (`n=12`: `z=-5,60`; `n=14`: `z=-45,96`; `n=16`: `z=-604,36`). Em `2R..8R`, nenhuma métrica ultrapassou `|z| > 4,0`. |

Além disso, em `8R` o núcleo apresentou avalanche média de `0,50039 ± 0,02195` e uniformidade $\chi^2 = 271,59$ (`p = 0,2270`).

> **Notas Metodológicas Críticas (`M_R5_1`):**
> 1. **Equivalência Matemática ANF vs. Integral/Square:** Na Transformada de Möbius sobre $\mathbb{F}_2^{16}$, o coeficiente do monômio de grau máximo $x_0 x_1 \cdots x_{15}$ (`anf[-1]`) equivale exatamente à soma XOR da tabela-verdade sobre todo o domínio $2^{16}$. Logo, `anf[-1] == 0` (grau $< 16$) e `XOR == 0` no `Lambda-set` de $2^{16}$ são **manifestações matematicamente equivalentes** do mesmo fenômeno estrutural em `1R` e `2R` (não constituindo duas famílias independentes de quebra).
> 2. **Escopo da Margem `6R (75,0%)`:** A margem medida de **6R (75,0%)** refere-se exclusivamente a **distinguidores de 1 palavra sem *key-guessing*** na rodada seguinte.

### 2.2. Ataques Mitigados no Red-Team Ofensivo (`M_R5_4`)

- **Boomerang / Rectangle (`RT-F1-04` — Margem `>= 6R` sobre `2R`):** Sonda *switch* $M$-alinhada (`N = 500` quartetos) atingiu `500/500` em `1R`, caindo para `0/500` em `2R` e `3R`; em `4R`, `aligned_trunc(<32)` obteve `1/500` (compatível com o ruído aleatório esperado $\mathbb{E}[X] \approx 0,244$).
- **Diferencial Impossível & MitM (`RT-F1-05` — Margem `>= 5R` sobre `3R`):** A propriedade MDS ($\mathcal{B} = 33$) manteve `min_active_words = 32/32` em `1.000` pares `1R`. O distinguidor diferencial impossível de `2R` (`0/8.192` ocorrências com `wt_word(M^{-1}(out_diff)) < 32`) foi violado em `3R` (`9/8.192`, compatível com ruído aleatório). A barreira Meet-in-the-Middle apresentou dependência total `32/32` tanto em `fwd_1R` quanto em `bwd_1R` a partir de `>= 3R`.
- **Algébrica / ANF & Integral (`RT-F1-06` — Margem `>= 5R` sobre `3R`):** Grau ANF exato `15` nas 16 coordenadas de `sbox_v5_eval`; recuperação algébrica em `1R` (`rk[1]` dado `rk[0]`) frente a `2R = 64`, `3R = 96` e `8R = 256` S-boxes ativas; $\Lambda$-set `2^16` zera em `1R–2R` (`0/32` palavras não-nulas) e quebra em `3R–4R` (`32/32` palavras não-nulas).
- **Slide / Related-Key (`RT-F1-07` — Mitigada):** A separação de domínio via `HMAC-SHA256` (`_domain_tag` com `rounds` e `n_sess`) produziu distâncias de Hamming normalizadas de `0,4897` (`rounds=8` vs `7`), `0,5013` (`n_sess=0` vs `1`) e `0,4918` (*related-key* 1-bit).
- **Fuzzing de Fronteira e API (`RT-F2-07` — Mitigada):** `41/41` casos de fronteira validados (entradas inválidas e limites de `x, y, n_sess, rounds, output_bytes, s, mode`, `verify_public_output`, e fronteiras da API C como `rounds=0/256` $\to$ `-1`, `NULL` $\to$ `-1`, `fault_word=32` $\to$ `0`).

---

## 3. O que foi Quebrado ou Exposto pelo Red-Team Ofensivo (`M_R5_4`)

O Red-Team Ofensivo ([`r5_m4_red_team_offensive.md`](../../resultados/v5_sandbox/r5_m4_red_team_offensive.md)) identificou **9 vulnerabilidades/achados reais confirmados** (2 de severidade **Alta**, 3 **Média** e 4 **Baixa**), que impedem a aprovação imediata para produção:

### 3.1. Severidade Alta (2 Achados)

1. **`RT-F2-01` — Bypass Total da Proteção Anti-DFA na Penúltima Rodada `R-1` (R7):**
   - **Descrição:** A redundância temporal Anti-DFA protege apenas a última rodada (`R=8`). Uma falha injetada na saída de `R7` (`R-1`) propaga-se de forma idêntica para ambos os caminhos (`state_a` e `state_b`) de `R8`, fazendo a verificação retornar `rc == 0` / `status == 0` com saída corrompida tanto em C99 quanto em Python.
   - **Remediação (v5.2):** Estender a redundância temporal (ou verificação por invariante/dupla execução) para cobrir pelo menos `R-1` e `R`, ou executar redundância completa com comparação de estado intermediário.
2. **`RT-F2-02` — Data Race em `init_cauchy_mds()` (Concorrência C99):**
   - **Descrição:** Sob `16` pthreads simultâneas (`setarch x86_64 -R`), o ThreadSanitizer detectou `WARNING: ThreadSanitizer: data race` (`exit=66`) em `init_cauchy_mds` (`rsd_s_v5_ct.c:182, 189, 193`) devido à escrita concorrente em `CAUCHY_MDS`, `CAUCHY_BIT_BASIS` e na flag não-atômica `CAUCHY_INIT`.
   - **Remediação (v5.2):** Substituir `CAUCHY_INIT` por inicialização segura via `pthread_once` / `stdatomic.h` (`atomic_flag` / `call_once`) ou pré-computação estática em tempo de compilação / `__attribute__((constructor))`.

### 3.2. Severidade Média (3 Achados)

3. **`RT-F1-01` — Exposição Literal de `keys[r]` em `rk[r][0..15]` (Key Schedule):**
   - **Descrição:** `expand_key_words_v5(keys[r])` copia literalmente os 32 bytes de `keys[r]` para `rk[r][0..15]` e deriva `rk[r][16..31]` a partir de `keys[r]`. Isso permite reconstruir 100% de `rk[r][16..31]` a partir de `rk[r][0..15]` sem conhecer a chave mestra `s`.
   - **Remediação (v5.2):** Derivar ambas as metades de `rk[r]` via KDF unidirecional (`HMAC-SHA256(keys[r], "EXP|" || 0)` e `"EXP|" || 1`, ou `SHAKE256`), eliminando a exposição literal de `keys[r]`.
4. **`RT-F2-03` — Exposição de `s_priv_state` no Retorno Público da API:**
   - **Descrição:** `BandlimitedDualKeyEngine.refactor_public_output` inclui `"s_priv_state"` (o estado secreto pré-SHA) no dicionário público retornado ao chamador.
   - **Remediação (v5.2):** Remover `"s_priv_state"` do retorno público padrão, restringindo-o a uma flag explícita de depuração/auditoria desativada por padrão.
5. **`RT-F2-04` — Vazamento de Timing em `_unpadded_z65537_to_bytes64` (Python):**
   - **Descrição:** O desvio condicional `if iv < 65536` que aciona `SHA-256` apenas quando a coordenada é `65536` gera vazamento de tempo estatisticamente significativo (`N = 1.500` amostras/classe em ordem aleatorizada): pior caso `0/32` vs `32/32` (`mean0 = 7.570,3 ns` vs `mean32 = 52.046,8 ns`, **`Welch t = 9,11`**, `p = 2,36e-19`) e caso realista `0/32` vs `1/32` (`mean0 = 6.254,5 ns` vs `mean1 = 7.780,1 ns`, **`Welch t = 20,35`**, `p = 3,17e-85`).
   - **Remediação (v5.2):** Calcular o *fallback* `SHA-256` incondicionalmente para todas as coordenadas e selecionar o resultado de forma *branchless* (e validar explicitamente o intervalo `0 <= iv < 65537`, mitigando também o comportamento silencioso para `>= 65537`).

### 3.3. Severidade Baixa (4 Achados)

6. **`RT-F2-05` — Colisão 2-para-1 na Função Isolada `_unpadded_z65537_to_bytes64`:** Para `s_priv_bytes` fixo, `vec_a[0] = 65536` e `vec_b[0] = 36475` colidem na saída compacta de 64B (embora no `BandlimitedDualKeyEngine` completo entradas `(x, y)` distintas produzam `s_priv_bytes` distintos via SPN bijetora). *Remediação:* documentar explicitamente a não-injetividade isolada do *folding* e validar faixa `0 <= iv < 65537`.
7. **`RT-F2-06` — Footprint L1D e Limpeza Parcial de Registradores AVX2:** `sizeof(CAUCHY_BIT_BASIS) = 32.768` bytes ocupa 100% de uma cache L1D típica de 32 KB; ademais, `objdump -d` em `rsd_s_v5_core_ct` mostra `vzeroupper` antes do `ret` principal (limpa apenas os bits `128..255` de `ymm`), sem `vzeroall`/`vpxor` para zerar `xmm0..xmm15` (bits `0..127`). *Remediação:* zerar `xmm0..xmm15` antes do retorno e avaliar redução de pegada L1D.
8. **`RT-F1-02` — Viés Determinístico dos 2 MSBs na Entrada:** `fragment_full_v5(x, y)` fixa sempre `state[15] >> 15 == 0` e `state[31] >> 15 == 0` (`0/256`) para todo $x, y < 2^{255}-19$; o viés persiste após `rk[0]` e dissipa após `1R` (`130/256` e `139/256`). *Remediação:* documentado como limite estrutural ($\approx 510$ bits de entropia de entrada); opcionalmente injetar *domain/padding* nos 2 bits livres caso se deseje entropia uniforme de 512 bits antes de `rk[0]`.
9. **`RT-F1-03` — Simetria Estrutural de `rc(r)` e `M_CAUCHY_32`:** `round_constant_v5` aplica o mesmo valor nas 32 palavras e todas as 32 linhas de `M_CAUCHY_32` têm soma constante (`0x1731`), deixando apenas `rk[r]` responsável por quebrar o subespaço simétrico $S_{\text{eq}}$ em `1R–2R`. *Remediação:* variar `rc(r)` por índice de palavra `i` (`rc(r, i)`) para defesa em profundidade.

---

## 4. Comparação com Baseline AES-128 (`10R`) / AES-256 (`14R`) PRP (`M_R5_2`)

Um núcleo C99 genuíno conforme NIST FIPS 197 ([`testes/aes_prp_baseline.c`](../../testes/aes_prp_baseline.c)) foi validado em **100% dos vetores oficiais** (Apêndices **B**, **C.1** e **C.3** — todos **PASS**) e avaliado sob o mesmo harness `r5_metrics_harness.py`.

### 4.1. Alcance Máximo e Margem Lado a Lado

| Família de Ataque / Métrica | AES-128 (`10R`) Alcance / Margem | AES-256 (`14R`) Alcance / Margem | RSD-S v5.1 (`8R`) Alcance / Margem |
|---|---:|---:|---:|
| **Integral / Square (`Lambda-set`)** | **3R** / 7R (**70,0%**) | **3R** / 11R (**78,6%**) | **2R** / 6R (**75,0%**) |
| **Algébrico / ANF (grau não-saturado)** | **3R** / 7R (**70,0%**) | **3R** / 11R (**78,6%**) | **2R** / 6R (**75,0%**) |
| **Diferencial & Truncado ($N=4.096$)** | **2R** / 8R (**80,0%**) | **2R** / 12R (**85,7%**) | **1R** / 7R (**87,5%**) |
| **QROM-analog ($n=10..16$, $\|z\| > 4,0$)** | **3R** / 7R (**70,0%**) | **3R** / 11R (**78,6%**) | **1R** / 7R (**87,5%**) |
| **Linear / Walsh** | **1R** / 9R (**90,0%**) | **1R** / 13R (**92,9%**) | **1R** / 7R (**87,5%**) *(másc. estr. `(M^T)^{-1}`, $N=524.288$)* |

### 4.2. Explicação Estrutural e Benchmark de Throughput

- **Explicação Estrutural (`B=33` vs `ShiftRows+MixColumns`):** No AES, `ShiftRows` + `MixColumns` ($4 \times 4$ por coluna) exige **2 rodadas** para difundir 1 byte ativo por todos os 16 bytes (`1R`: 1 byte ativo, `avalanche = 0,03157`; `2R`: 4 bytes; `3R`: 16 bytes, explicando Integral/Square até `3R`). Na RSD-S v5.1, a matriz Cauchy MDS densa $32 \times 32$ (`Branch Number = 33`) difunde 1 palavra para todas as 32 palavras já em **1 rodada** (`avalanche = 0,50002` em `1R`). Em contrapartida, o AES possui maior margem absoluta em rodadas (`7R` / `11R` vs `6R` no Integral/ANF), aceleração por hardware (AES-NI) e mais de 25 anos de criptoanálise pública.
- **Escopo do Alcance `3R` no AES vs. Literatura Pública:** O alcance **`3R`** observado para o AES refere-se **exclusivamente aos 5 ataques automatizados do harness `r5_metrics_harness.py`** (sem extensão de recuperação de subchave). Na literatura pública, existem ataques estruturais (Square estendido com recuperação de subchave, *Impossible Differential*, *Boomerang* e *Meet-in-the-Middle*) que alcançam mais rodadas reduzidas do AES.
- **Benchmark de Throughput (`10.000` blocos):**

| Primitiva | Bloco | `eval_block` (`µs/chamada`) | `eval_block` (`MB/s`) | Modo Lote 10.000 (`µs/bloco`) | Modo Lote 10.000 (`MB/s`) |
|---|---:|---:|---:|---:|---:|
| **AES-128 (`10R`)** | 16 B | **1,486 µs** | **10,272 MB/s** | **0,1821 µs** *(C puro)* | **83,796 MB/s** |
| **AES-256 (`14R`)** | 16 B | **1,576 µs** | **9,680 MB/s** | **0,2352 µs** *(C puro)* | **64,882 MB/s** |
| **RSD-S v5.1 (`8R`)** | 64 B | **21,949 µs** | **2,781 MB/s** | **22,8221 µs** *(loop Python)* | **2,674 MB/s** |

*(Nota metodológica: na coluna **"Modo Lote 10.000"**, há uma assimetria estrutural de medição: o AES executa `aes_encrypt_batch_rounds` em C puro com apenas 1 chamada `ctypes`, enquanto a RSD-S v5.1 executa `RSDKeyedV5.eval_words` com 10.000 iterações Python/NumPy e 10.000 chamadas `ctypes`, por ausência de API batch em `rsd_s_v5_ct.c`. Assim, a comparação justa de custo entre as implementações é `eval_block`, onde mesmo contra AES C99 escalar portátil sem AES-NI o AES é `~3,5×` mais rápido em `MB/s` e `~14×` menor em latência por chamada devido ao custo da multiplicação matricial MDS $32 \times 32$ em $GF(2^{16})$.)*

---

## 5. Estado do Rascunho Formal QROM (`M_R5_3`)

O documento [`especificacao/REDUCAO_QROM_RASCUNHO_V5_1.md`](../../especificacao/REDUCAO_QROM_RASCUNHO_V5_1.md) (resumido em [`r5_m3_qrom_draft_summary.md`](../../resultados/v5_sandbox/r5_m3_qrom_draft_summary.md)) formaliza uma **redução condicional** com separação explícita de três regimes:
1. **Q1-qPRF:** $q_H$ consultas quânticas ao QRO + $q_C$ clássicas a $F_s$ ($q_S \le q_C$ sessões).
2. **Q2-Sessão-Clássica (Principal):** $n_{\text{sess}}$ clássico ($q_S$ sessões) e superposição apenas sobre $(x, y) \in \mathcal{D}$.
3. **Q2-Superposição-Completa:** superposição conjunta sobre $(x, y, n_{\text{sess}})$.

- **Teorema 1 (`RSD-S v5.1`):** Reduz a vantagem qPRF nos 3 regimes à segurança qPRF de `HMAC-SHA256` ($17 q_S$ ou $17 q_Q$ chamadas), à segurança qPRP/tqPRP de $\text{SPN}_8$, ao Switching Lemma ($\frac{q_C(q_C-1)}{2^{513}}$ em Q1; $O(q_Q^3/2^{512})$ em Q2) e ao *Compressed Oracle* de Zhandry ($O(q_H \sqrt{q/2^{512}})$).
- **Teorema 2 (`Dupla-Chave SIV` + Folding 64B):** Prova independência aditiva (*One-Time Pad* em $\mathbb{Z}_{65537}^{32}$) mesmo sob reuso de $n_{\text{sess}}$ entre entradas distintas $(x,y) \neq (x',y')$, contabiliza explicitamente $\frac{q_C(q_C-1)}{2^{512}} = 2 \cdot \frac{q_C(q_C-1)}{2^{513}}$ em Q1 (soma do Switching Lemma $\frac{q_C(q_C-1)}{2^{513}}$ com a colisão de $R_1$ $\frac{q_C(q_C-1)}{2^{513}}$; $O(q_Q^3/2^{512})$ em Q2) e o *Compressed Oracle* sobre `SHAKE256` ($O(q_H \sqrt{q/2^{256}})$), demonstrando distância estatística exata **`TVD = 0`** para o *folding* de 64 bytes pela Lei da Probabilidade Total ($\frac{1}{65537} + \frac{1}{65537 \cdot 65536} = \frac{1}{65536}$).

| Reduzido Formalmente (Condicional) | Permanece Assumido / Não Provado (Para Revisão Externa) |
|---|---|
| Composição QRO $\text{SPN}_8 \to H_{32}/H_{64}$ (Switching Lemma + Compressed Oracle) | $\text{SPN}_8$ (8 rodadas, **incluindo** `expand_key_words_v5`) é uma **qPRP** / **tqPRP** segura |
| Mascaramento aditivo SIV em $\mathbb{Z}_{65537}^{32}$ sob reuso de $n_{\text{sess}}$ | `HMAC-SHA256` é **Q1-qPRF** e **Q2-qPRF** |
| Uniformidade exata do *Folding* 64B ($\text{TVD} = 0$) | `SHA-256` e `SHAKE256` são QROs independentes (indiferenciabilidade) |
| Implicação $\text{qPRF} \implies \text{qMAC}$ (Q1 e Q2 PO-EUF) | Ausência de subgrupo oculto / periodicidade explorável em $\text{SPN}_8$ ou $B_{K_j}$ |
| — | Segurança *constant-time* fora do modelo QROM (ramo `== 65536` em Python) |

---

## 6. Veredito Final Inequívoco

1. **Pronto para Pesquisa e Revisão Criptográfica Externa:** A suíte R5 estabeleceu um baseline reproduzível e honesto: a difusão SPN de 8 rodadas com `M_v5.1` (`B=33`) detecta `RSD 2R` deterministicamente em Integral/Square e ANF (margem `6R` / `75,0%` sobre `8R`), resiste a Boomerang (`>= 6R`), Diferencial Impossível (`>= 5R`) e ataques lineares/diferenciais em `8R`, e possui um rascunho formal QROM (`Teoremas 1 e 2`) pronto para escrutínio acadêmico externo.
2. **NÃO Aprovado para Produção:** A primitiva e sua implementação atual **não estão aprovadas para uso em produção**. Antes de qualquer adoção prática, é obrigatório:
   - Corrigir os **2 achados de severidade Alta** (`RT-F2-01` bypass Anti-DFA em R7; `RT-F2-02` data race em `init_cauchy_mds`) e os **3 achados de severidade Média** (`RT-F1-01` exposição literal de `keys[r]` em `rk[r][0..15]`; `RT-F2-03` retorno público de `s_priv_state`; `RT-F2-04` vazamento de timing no *folding* Python) em uma eventual revisão **v5.2**;
   - Submeter a especificação e o rascunho QROM à **revisão criptográfica externa independente**, em estrita observância a [`especificacao/RESTRICOES_DE_PROJETO.md`](../../especificacao/RESTRICOES_DE_PROJETO.md).
