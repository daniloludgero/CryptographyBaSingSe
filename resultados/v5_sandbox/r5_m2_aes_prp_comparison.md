# R5 — Marco M_R5_2: Baseline AES-128 / AES-256 PRP vs RSD-S v5.1

> **Escopo e Conformidade (`especificacao/RESTRICOES_DE_PROJETO.md`):**
> Este relatório compara empiricamente o núcleo SPN **RSD-S v5.1** (`8R`, bloco de 64 bytes / palavras de 16 bits em $GF(2^{16})$) contra um baseline genuíno **AES-128 (`10R`)** e **AES-256 (`14R`)** (bloco de 16 bytes / palavras de 8 bits em $GF(2^8)$), implementado em C99 conforme NIST FIPS 197 ([`testes/aes_prp_baseline.c`](../../testes/aes_prp_baseline.c)) e avaliado exatamente sob o mesmo harness [`testes/r5_metrics_harness.py`](../../testes/r5_metrics_harness.py).
> Os testes em domínio reduzido ($n \le 16$ bits) no proxy QROM-analog **não** constituem prova formal em QROM, **não** certificam segurança pós-quântica e **não** aprovam a RSD-S v5.1 para uso em produção. A RSD-S não se baseia nos problemas atacados por Shor, mas não deve ser declarada pós-quântica ou superior a padrões NIST sem prova formal QROM e revisão independente.

---

## 1. Validação Oficial NIST FIPS 197

O núcleo C99 [`testes/aes_prp_baseline.c`](../../testes/aes_prp_baseline.c) foi compilado sem warnings com `gcc -O3 -Wall -Wextra -Werror -shared -fPIC` em `/tmp/r5_build/lib_aes_prp_baseline.so` e validado em 100% dos vetores oficiais exigidos:

| Vetor NIST FIPS 197 | Algoritmo | Chave (prefixo) | Plaintext (prefixo) | Ciphertext Esperado = Observado | Status |
|---|---|---|---|---|---|
| **Apêndice B** | AES-128 (`10R`) | `2b7e151628aed2a6...` | `3243f6a8885a308d...` | `3925841d02dc09fbdc118597196a0b32` | **PASS** |
| **Apêndice C.1** | AES-128 (`10R`) | `0001020304050607...` | `0011223344556677...` | `69c4e0d86a7b0430d8cdb78070b4c55a` | **PASS** |
| **Apêndice C.3** | AES-256 (`14R`) | `0001020304050607...` | `0011223344556677...` | `8ea2b7ca516745bfeafc49904b496089` | **PASS** |

---

## 2. Comparação Lado a Lado: Alcance Máximo e Margem de Segurança

Dados reais extraídos de `/tmp/r5_build/r5_m1_results.json` (M_R5_1) e `/tmp/r5_build/r5_m2_results.json` (M_R5_2):

| Família de Ataque / Métrica | AES-128 (`10R`) Alcance / Margem | AES-256 (`14R`) Alcance / Margem | RSD-S v5.1 (`8R`) Alcance / Margem |
|---|---:|---:|---:|
| **Integral / Square (`Lambda-set`)** | **3R** / 7R (**70,0%**) | **3R** / 11R (**78,6%**) | **2R** / 6R (**75,0%**) |
| **Algébrico / ANF (grau não-saturado)** | **3R** / 7R (**70,0%**) | **3R** / 11R (**78,6%**) | **2R** / 6R (**75,0%**) |
| **Diferencial & Truncado ($N=4.096$)** | **2R** / 8R (**80,0%**) | **2R** / 12R (**85,7%**) | **1R** / 7R (**87,5%**) |
| **QROM-analog ($n=10..16$, $\|z\| > 4,0$)** | **3R** / 7R (**70,0%**) | **3R** / 11R (**78,6%**) | **1R** / 7R (**87,5%**) |
| **Linear / Walsh ($N=16.384$, 64 másc.)** | **1R** / 9R (**90,0%**) | **1R** / 13R (**92,9%**) | **0R** / 8R (**100,0%**) *(1R com másc. estr. em M_R5_1, 87,5%)* |

> **Análise Estrutural Honesta:**
> - **Por que o RSD-S v5.1 atinge difusão em menos rodadas (`1R..2R` vs `2R..3R` no AES)?**
>   No AES, a camada linear é composta por `ShiftRows` + `MixColumns` ($4 \times 4$ sobre colunas independentes), exigindo **2 rodadas** para que 1 byte ativo se propague para todos os 16 bytes do estado (explicando `1R`: 1 byte ativo, `2R`: 4 bytes ativos, `3R`: 16 bytes ativos e Integral/Square detectado até `3R`).
>   No RSD-S v5.1, a camada linear é uma matriz Cauchy MDS densa $32 \times 32$ (`Branch Number = 33`), que difunde 1 palavra ativa para todas as 32 palavras já em **1 rodada** (`avalanche = 0,50002` em `1R` vs `0,03157` em `1R` do AES).
> - **Contrapartida de Custo e Maturidade:**
>   Apesar da difusão por rodada mais rápida, o RSD-S v5.1 possui apenas 8 rodadas totais (margem absoluta de `6R` no Integral/ANF), frente a `7R` no AES-128 (`10R`) e `11R` no AES-256 (`14R`), e o AES conta com décadas de criptoanálise pública e aceleração por hardware (AES-NI).
> - **Escopo do Alcance `3R` no AES vs Literatura Pública:**
>   O alcance máximo `3R` observado aqui para o AES refere-se exclusivamente aos 5 ataques automatizados do harness `r5_metrics_harness.py` (sem extensão de recuperação de subchave). Na literatura pública (mais de 25 anos de estudo), existem ataques estruturais sobre versões reduzidas do AES — como Square estendido com recuperação de subchave, *Impossible Differential*, *Boomerang* e *Meet-in-the-Middle* — que alcançam mais rodadas reduzidas do AES, ao passo que a RSD-S v5.1 ainda carece de criptoanálise externa independente de longo prazo.

---

## 3. Resultados Detalhados do AES-128 (`1R..5R`, `10R`) e AES-256 (`1R..5R`, `14R`)

### 3.1. Integral / Square (`trials=4`, `final_no_mixcolumns=1` e `0`)

Tanto com `final_no_mixcolumns=1` quanto com `final_no_mixcolumns=0` em `1R..4R`, o comportamento observado foi idêntico para AES-128 e AES-256:
- **1R, 2R, 3R**: **16 / 16** palavras com `XOR == 0` consistente (`full_state_balanced = True`, `detected = True`).
- **4R, 5R, 10R/14R**: **0 / 16** palavras com `XOR == 0` (`detected = False`).

### 3.2. Diferencial, Linear, ANF, Avalanche, Uniformidade e QROM-analog

| Primitiva / Rodada | Dif. Palavras Ativas (média) | Dif. Colisões `z` | Dif. `max_bit_bias_z` | Linear `max_z` | ANF Grau Máx. (`sat/8`) | Avalanche (`média ± σ`) | Uniformidade (`χ²`, `p`) | QROM-analog (`max \|z\|`) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **AES-128 1R** | 1,000 | **+46.244,7** (`det`) | **64,000** | **11,672** (`det`) | **7** (`0/8`, `det`) | 0,03157 ± 0,01056 | 265,62 (`0,3108`) | **6.126,89** (`det`) |
| **AES-128 2R** | 4,000 | **+46.244,7** (`det`) | **64,000** | 3,219 | **7** (`0/8`, `det`) | 0,12472 ± 0,02213 | 253,10 (`0,5218`) | **5.739,85** (`det`) |
| **AES-128 3R** | 16,000 | +2,862 | 2,594 | 2,375 | **7** (`0/8`, `det`) | 0,50366 ± 0,04401 | 267,14 (`0,2882`) | **-11,75** (`det`) |
| **AES-128 4R** | 15,940 | +1,904 | 2,469 | 3,219 | 8 (`3/8`) | 0,49770 ± 0,04362 | 242,80 (`0,6982`) | 2,41 |
| **AES-128 10R** | 15,931 | +1,318 | 3,250 | 2,594 | — | 0,49886 ± 0,04296 | 273,66 (`0,2015`) | 2,45 |
| **AES-256 1R** | 1,000 | **+46.244,7** (`det`) | **64,000** | **12,688** (`det`) | **7** (`0/8`, `det`) | 0,03180 ± 0,01042 | 264,36 (`0,3304`) | **6.083,88** (`det`) |
| **AES-256 2R** | 4,000 | **+46.244,7** (`det`) | **64,000** | 2,328 | **7** (`0/8`, `det`) | 0,12560 ± 0,02245 | 252,43 (`0,5337`) | **7.091,60** (`det`) |
| **AES-256 3R** | 16,000 | +2,065 | 3,094 | 2,562 | **7** (`0/8`, `det`) | 0,50256 ± 0,04344 | 239,88 (`0,7434`) | **-9,29** (`det`) |
| **AES-256 4R** | 15,935 | +1,688 | 2,500 | 3,047 | 8 (`3/8`) | 0,50130 ± 0,04363 | 307,60 (`0,0134`) | 1,31 |
| **AES-256 14R** | 15,937 | +1,556 | 2,719 | 2,484 | — | 0,50100 ± 0,04429 | 261,01 (`0,3846`) | 1,81 |
| **RSD-S v5.1 8R** | 31,9998 | -1,146 | 3,219 | 2,344 | 16 (`5/16` em 4R) | 0,50039 ± 0,02195 | 271,59 (`0,2270`) | 1,67 |

---

## 4. Benchmark de Throughput (Latência e Vazão)

Medição executada na mesma máquina com `10.000` chamadas individuais (`eval_block` via `ctypes`) e `10.000` blocos em lote:

| Primitiva | Bloco | Modo `eval_block` (`µs/chamada`) | Modo `eval_block` (`MB/s`) | Modo Lote 10.000 (`µs/bloco`) | Modo Lote 10.000 (`MB/s`) |
|---|---:|---:|---:|---:|---:|
| **AES-128 (`10R`)** | 16 B | **1,486 µs** | **10,272 MB/s** | **0,1821 µs** (`aes_encrypt_batch_rounds` C puro) | **83,796 MB/s** |
| **AES-256 (`14R`)** | 16 B | **1,576 µs** | **9,680 MB/s** | **0,2352 µs** (`aes_encrypt_batch_rounds` C puro) | **64,882 MB/s** |
| **RSD-S v5.1 (`8R`)** | 64 B | **21,949 µs** | **2,781 MB/s** | **22,8221 µs** (`RSDKeyedV5.eval_words` loop Python) | **2,674 MB/s** |

> **Observação Metodológica de Desempenho:**
> 1. **Escopo da RSD-S v5.1 (`with_sha=False`):** A medição da RSD-S v5.1 foi feita com `with_sha=False`, isolando apenas o núcleo SPN de 64 bytes (sem a finalização SHA-256/SHAKE256).
> 2. **Assimetria na coluna "Modo Lote 10.000":** No AES, o lote executa `aes_encrypt_batch_rounds` em C puro com apenas 1 chamada `ctypes`; na RSD-S v5.1, executa `RSDKeyedV5.eval_words`, que realiza um loop Python de 10.000 iterações com 10.000 chamadas `ctypes` e indexação NumPy (por ausência de API *batch* em `rsd_s_v5_ct.c`). Por essa razão, a comparação justa de custo entre as implementações é a coluna `eval_block` (`~3,5×` em `MB/s`, `~10 MB/s` vs `2,78 MB/s`), na qual mesmo em C99 escalar portátil (sem AES-NI) o AES-128/256 é ~14× mais rápido por chamada (`~1,5 µs` vs `~21,9 µs`) devido ao custo inerente da multiplicação matricial MDS $32 \times 32$ em $GF(2^{16})$.

---

## 5. Execução da Suíte `pytest`

Comando executado:
```bash
pytest -v -s testes/test_r5_m2_aes_prp_comparison.py
```
Resultado: **3 passed in 37.77s**.
