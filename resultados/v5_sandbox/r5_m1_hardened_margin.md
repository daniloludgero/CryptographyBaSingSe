# R5 — Marco M_R5_1: Bateria Endurecida até Detectar RSD 2R & Margem de Segurança por Ataque

> **Escopo e Conformidade (`especificacao/RESTRICOES_DE_PROJETO.md`):**
> Este relatório apresenta medições empíricas de criptoanálise sobre versões com rodadas reduzidas (`1R..8R`) do núcleo **RSD-S v5.1** (`implementacao/c_core/rsd_s_v5_ct.c`, sem SHA-256 final para isolar a difusão SPN). Os testes de proxy análogo a QROM em domínio reduzido ($n \le 16$ bits) **não** constituem prova formal em QROM e **não** certificam segurança pós-quântica. A RSD-S não se baseia nos problemas atacados por Shor, mas não deve ser declarada pós-quântica ou pronta para produção sem prova formal QROM e revisão independente.

---

## 1. Metodologia e Endurecimento da Bateria

Para eliminar a limitação observada na rodada R4 (onde `y=12345` fixo não detectava o controle `RSD 2R`) e atender aos critérios de rigor criptoanalítico, foi implementado o harness reutilizável [`testes/r5_metrics_harness.py`](../../testes/r5_metrics_harness.py) e a suíte [`testes/test_r5_m1_hardened_margin.py`](../../testes/test_r5_m1_hardened_margin.py):

1. **Truncamento Real da Instância 8R (`RSDKeyedV5`)**:
   - A agenda de chaves completa (`rk_flat_8` com `9 * 32 = 288` palavras `uint16` e `rc_8` com `8` constantes) é derivada com `schedule_rounds=8`, e as variantes de `1R..8R` fatiam exatamente `rk_flat_8[:(r+1)*32]` e `rc_8[:r]`.
   - O núcleo C99 constant-time AVX2 (`implementacao/c_core/rsd_s_v5_ct.c`) é compilado com `gcc -O3 -mavx2 -Wall -Wextra -Werror -shared -fPIC`.
2. **Entradas Aleatórias Completas (512 bits)**:
   - Todos os testes diferenciais, lineares, de avalanche, uniformidade e QROM-analog operam sobre blocos completos de 64 bytes (512 bits) aleatórios, sem fixar `y=12345`.
3. **Cinco Famílias de Ataques / Métricas**:
   - **Integral / Square (`Lambda-set`, `trials=2`)**: varia 1 palavra de 16 bits por todos os $2^{16} = 65.536$ valores mantendo as 31 palavras restantes em valores base aleatórios distintos por trial (`trials=2` elimina o risco de falso positivo $32 \cdot 2^{-16}$ em `3R..8R`).
   - **Diferencial & Diferencial Truncado**: $N = 4.096$ pares `(pt, pt ^ delta)` com `pt` aleatório de 512 bits e `delta` fixo em 1 palavra; mede `max_bit_bias_z`, `word_diff_coll_z`, `truncated_active_words_mean` e `hw_mean_z`.
   - **Linear / Walsh Estrutural**: $N = 524.288$ ($2^{19}$) amostras aleatórias de 512 bits (piso de resolução estatística $1/\sqrt{N} = 2^{-9,5} \approx 0,001381$) com 40 pares de máscaras: 8 máscaras estruturais $(\Gamma_{\text{in}}, \Gamma_{\text{out}})$ onde $\Gamma_{\text{in}}$ ativa apenas a palavra 0 ($\alpha$) e $\Gamma_{\text{out}} = (M_{\text{bin}}^T)^{-1}(e_0 \cdot \beta)$ isola exatamente **1 S-box** na rodada 1 (pares $(\alpha, \beta)$ da `S_v5` com $|c| \ge 2^{-7}$), mais 32 máscaras esparsas/aleatórias.
   - **Algébrico / Higher-Order Differential (ANF)**: Transformada Rápida de Möbius em $\mathbb{F}_2^{16}$ sobre o `Lambda-set` de 1 palavra em `1R..4R`, medindo o grau algébrico máximo (`0..16`) e a saturação do monômio de grau 16.
   - **QROM-analog Endurecido**: tabelas de $n \in \{10, 12, 14, 16\}$ bits com bloco base aleatório de 512 bits por chave ($K_{\text{keys}} = 4$) contra ensemble de $K_{\text{RO}} = 40$ Oráculos Aleatórios, usando erro padrão de duas amostras $\text{SE} = s_{\text{RO}} \sqrt{1/K_{\text{keys}} + 1/K_{\text{RO}}}$ (limiar $|z| > 4,0$).

---

## 2. Tabela Resumo: Alcance Máximo e Margem de Segurança (sobre 8R)

| Família de Ataque / Métrica | Alcance Máximo Detectado | Total de Rodadas | Margem de Segurança | Margem (%) |
|---|---:|---:|---:|---:|
| **Integral / Square (`Lambda-set` $2^{16}$, `trials=2`)** | **2R** | 8R | **6R** | **75,0%** |
| **Algébrico / ANF (grau $< 16$)** | **2R** | 8R | **6R** | **75,0%** |
| **Diferencial & Truncado ($N=4.096$)** | **1R** | 8R | **7R** | **87,5%** |
| **Linear / Walsh (`(M^T)^{-1}`, $N=524.288$)** | **1R** | 8R | **7R** | **87,5%** |
| **QROM-analog ($n=10..16$)** | **1R** | 8R | **7R** | **87,5%** |

### Notas Críticas de Interpretação
1. **Equivalência Matemática ANF vs Integral/Square em `1R/2R`**: Na Transformada de Möbius sobre $\mathbb{F}_2^{16}$, o coeficiente do monômio de grau máximo $x_0 x_1 \cdots x_{15}$ (`anf[-1]`) é exatamente a soma XOR da tabela-verdade sobre todo o domínio $2^{16}$. Portanto, `anf[-1] == 0` (grau algébrico $< 16$) em todos os bits de saída e a propriedade Integral/Square (`XOR == 0` em `32/32` palavras) são **manifestações matematicamente equivalentes** do mesmo fenômeno estrutural em `1R` e `2R`.
2. **Escopo da Margem de `6R (75,0%)`**: A margem medida de **6R (75,0%)** refere-se exclusivamente a **distinguidores de 1 palavra sem *key-guessing*** na rodada seguinte. Ataques estendidos com *key-guessing* parcial em rodadas adjacentes ou *Lambda-sets* multidimensionais não foram avaliados nesta métrica base e são objeto de análise ofensiva específica (M_R5_4).
3. **Piso de Resolução Estatística do Linear/Walsh ($1/\sqrt{N}$)**: Com $N = 524.288$ amostras, o piso de ruído é $1/\sqrt{N} \approx 0,001381$. Em `1R`, as máscaras estruturais $(M_{\text{bin}}^T)^{-1}$ isolam uma única S-box e atingem correlação `0,009369` (**`z = 6,784`**, detectado). Em `2R..8R`, qualquer trilha linear precisa atravessar múltiplas S-boxes ativas pelo Branch Number $\mathcal{B} = 33$ do MDS Cauchy, derrubando a correlação teórica muito abaixo do piso $1/\sqrt{N} = 0,001381$ (observado `max_z` entre `1,842` e `3,019`).

---

## 3. Resultados Detalhados por Rodada (`1R..8R`)

### 3.1. Integral / Square, Diferencial, Linear, Avalanche e Uniformidade

| Rodada | Integral (`XOR==0` / 32, 2 trials) | Dif. Colisões (`obs` / `esp`, `z`) | Linear `max_abs_corr` (`max_z`, piso `0,001381`) | Avalanche (`média ± σ`) | Uniformidade (`χ²`, `p`) |
|---:|---:|---:|---:|---:|---:|
| **1R** | **32 / 32** (`detectado`) | **234** / 127,97 (**z = +9,373**) | **0,009369** (**z = 6,784**, `detectado`) | 0,50002 ± 0,02330 | 271,41 (`p=0,2294`) |
| **2R** | **32 / 32** (`detectado`) | 101 / 127,97 (`z = -2,384`) | 0,003407 (`z = 2,467`) | 0,49982 ± 0,02315 | 220,19 (`p=0,9439`) |
| **3R** | 0 / 32 | 137 / 127,97 (`z = +0,798`) | 0,002544 (`z = 1,842`) | 0,50031 ± 0,02153 | 221,12 (`p=0,9385`) |
| **4R** | 0 / 32 | 116 / 127,97 (`z = -1,058`) | 0,004169 (`z = 3,019`) | 0,50105 ± 0,02189 | 231,00 (`p=0,8573`) |
| **5R** | 0 / 32 | 141 / 127,97 (`z = +1,152`) | 0,003059 (`z = 2,215`) | 0,50015 ± 0,02287 | 224,25 (`p=0,9178`) |
| **6R** | 0 / 32 | 149 / 127,97 (`z = +1,859`) | 0,002781 (`z = 2,014`) | 0,50031 ± 0,02218 | 251,22 (`p=0,5552`) |
| **7R** | 0 / 32 | 101 / 127,97 (`z = -2,384`) | 0,002888 (`z = 2,091`) | 0,49943 ± 0,02236 | 253,91 (`p=0,5076`) |
| **8R** | 0 / 32 | 115 / 127,97 (`z = -1,146`) | 0,002640 (`z = 1,911`) | 0,50039 ± 0,02195 | 271,59 (`p=0,2270`) |

### 3.2. Algébrico / ANF (Transformada de Möbius 16-bit sobre `1R..4R`)

| Rodada | Grau Algébrico Máximo | Bits Saturados em Grau 16 (de 16) | Não-saturado Detectado? |
|---:|---:|---:|:---:|
| **1R** | **15** | 0 / 16 | **SIM** |
| **2R** | **15** | 0 / 16 | **SIM** |
| **3R** | **16** | 9 / 16 | não |
| **4R** | **16** | 5 / 16 | não |

### 3.3. QROM-analog Endurecido ($n \in \{10, 12, 14, 16\}$, erro padrão de duas amostras)

- **1R**: fortemente distinguido de RO via `collisions_N_minus_image` em $n=12$ (`z = -5,60`), $n=14$ (`z = -45,96`) e $n=16$ (`0,0` colisões vs `24083,475`, `z = -604,36`).
- **2R..8R**: nenhuma métrica ultrapassou $|z| > 4,0$. Em **8R**, os z-scores permaneceram dentro da faixa esperada de Oráculo Aleatório.

---

## 4. Execução da Suíte `pytest`

Comando executado:
```bash
pytest -v -s testes/test_r5_m1_hardened_margin.py
```
Resultado: **5 passed in 588.83s (0:09:48)**.
