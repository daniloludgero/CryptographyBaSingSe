# Relatório Técnico Lote B — Criptoanálise Diferencial, Linear e Algébrica do `RSD-S v5`

> **Nota de versão.** Este relatório é anterior à v5.2 e descreve medições da linha v5.1. Resultados de segurança e desempenho **não foram refeitos na v5.2** salvo onde o texto disser o contrário. Vetores de referência da v5.2: `testes/vetores_v52.json`.


**Data:** 2026-11-22  
**Alvo:** `implementacao/rsd_s_v5_hardened.py`, `implementacao/c_core/rsd_s_v5_ct.c`, `implementacao/mds_real.py`  
**Script reproduzível:** `testes/test_lote_b_cryptanalysis.py`  
**Métricas estruturadas:** `resultados/v5_sandbox/lote_b_cryptanalysis_results.json`

---

## 1. Resumo Executivo e Vereditos

| Objetivo | Resultado Empírico | Veredito |
| :--- | :--- | :--- |
| **1. DDT e LAT Exatas da S-Box v5 ($2^{16} \times 2^{16}$)** | $\Delta_{\max} = 4$ ($p_{\max} = 2^{-14}$), $NL = 32512$ ($\|W\|_{\max} = 512$, $\|C\|_{\max} = 2^{-7}$), 0 pontos fixos, grau ANF $= 15$ | **CONCLUÍDA** (ótimo teórico de Nyberg para inversão em $\mathbb{F}_{2^{16}}$) |
| **2a. Bloqueio do Ataque Bilinear $\mathbb{F}_{2^{16}}$ (v4 $\to$ v5)** | Relação bilinear $u \cdot y = 1$ falha em 1R (`0xf9a9 != 1`); $A_{16}$ possui todos os 16 termos no polinômio linearizado | **CONCLUÍDA** (VULN-04 mitigada contra ataque bilinear em $\mathbb{F}_{2^{16}}$) |
| **2b. Ataques Algébricos/Integrais em 1R, 2R e 3R (`pre_sha`)** | 1R quebrada em 0,244 s (word-decoupled); **3R quebrada integralmente (32/32 palavras = 512 bits de $M^{-1}rk_3 \oplus rc_3$) via Ataque Square/Integral** com $2^{17}$ entradas em 296,76 s; 4R destrói a propriedade integral | **PARCIALMENTE REFUTADA EM RODADAS REDUZIDAS** (3R `pre_sha` vulnerável; margem de 5 rodadas até 8R intacta) |
| **3. Clustering e Invariantes da Matriz `M_CAUCHY_32` e `A_16`** | Descoberta estrutural: `M_CAUCHY_32` é XOR-Toeplitz (diádica), satisfazendo **$M^2 = \text{0x5e26} \cdot I$** e soma de linha/coluna constante; `A_16` quebra subcorpos $\mathbb{F}_{2^k}$. Em 8R, o *Wide-Trail* ($\ge 132$ S-boxes ativas, $2^{-1848}$ dif., $2^{-924}$ lin.) permanece intacto | **CONCLUÍDA** (invariante diádico descoberto sem quebra do limite *Wide-Trail* em 8R) |

---

## 2. Objetivo 1 — DDT, LAT e ANF Exatas da S-Box `S_v5`

Executado em C99 (`-O3 -march=native -fopenmp`) sobre todos os $2^{16} = 65.536$ elementos de entrada e todas as máscaras não nulas ($\Delta x, \alpha, \beta \in [1, 65535]$):

- **Bijeção e Pontos Fixos:** 65.536 saídas distintas; `0` pontos fixos ($S_{v5}(u) = u$); `0` pontos fixos opostos ($S_{v5}(u) = \neg u$).
- **DDT Exata ($4{,}458\text{ s}$):**
  - $\Delta_{\max} = \mathbf{4}$ ($p_{\max} = 4 / 65536 = 2^{-14}$).
  - Histograma exato das $65535 \times 65536 = 4.294.901.760$ entradas para $\Delta x \neq 0$:
    - `0`: `2.147.516.415`
    - `2`: `2.147.319.810`
    - `4`: `65.535` (exatamente 1 entrada igual a 4 por diferença de entrada $\Delta x \neq 0$, em conformidade exata com o teorema de Nyberg para $n$ par).
    - Outros valores não nulos: `0`.
- **LAT Exata via FWHT ($18{,}688\text{ s}$):**
  - $\max_{\alpha,\beta \neq 0} |W(\alpha, \beta)| = \mathbf{512} = 2^9$.
  - Máximo valor absoluto da LAT: $|\text{LAT}(\alpha,\beta)|_{\max} = 256$ (viés máximo $|\epsilon| = 2^{-8}$, correlação máxima $|C| = 2^{-7}$).
  - **Não-linearidade exata:** $NL(S_{v5}) = 2^{15} - 2^8 = \mathbf{32.512}$ (limite ótimo para inversão em $\mathbb{F}_{2^{16}}$).
- **ANF Exata (Fast Möbius Transform nos 16 bits de saída):**
  - Grau algébrico de todos os 16 bits de saída: **`15`** (máximo possível para uma bijeção em $\mathbb{F}_2^{16}$).
  - Contagem de monômios por bit: entre `32.464` e `32.984` de `65.536` (~49,5%–50,3% de densidade).

---

## 3. Objetivo 2 — Criptoanálise Algébrica e Integral (1R, 2R, 3R e 8R)

### 3.1 Equações Quadráticas sobre $\mathbb{F}_2$ (Estilo Courtois–Pieprzyk / XSL)
Embora $A_{16}$ destrua a bilinearidade sobre $\mathbb{F}_{2^{16}}$, a inversão em $\mathbb{F}_{2^{16}}$ combinada com a transformação $\mathbb{F}_2$-linear $A_{16}$ ainda induz equações quadráticas implícitas sobre $\mathbb{F}_2$ nos 32 bits $(u_0 \dots u_{15}, y_0 \dots y_{15})$:
- Matriz de avaliação quadrática ($65.536 \times 529$ monômios de grau $\le 2$) tem posto exato **`450`** sobre $\mathbb{F}_2$.
- Logo, `S_v5` possui exatamente **$529 - 450 = 79$ equações quadráticas linearmente independentes sobre $\mathbb{F}_2$** ($5n - 1 = 79$ para $n = 16$).
- **Implicação para 8R:** Com $8 \times 32 = 256$ S-boxes, o sistema completo de 8R tem $20.224$ equações quadráticas em pelo menos $3.840$ variáveis (ou $8.192$ com subchaves independentes), resultando em matriz de Macaulay de grau $D=3$ com $\binom{3840}{3} \approx 9{,}4 \times 10^{9}$ a $\binom{8192}{3} \approx 9{,}1 \times 10^{10}$ colunas ($\gg 2^{128}$ operações para XL/Gröbner).

### 3.2 Resultados Empíricos em Rodadas Reduzidas (1R, 2R, 3R, 4R)
1. **1R (`rounds=1`):**
   - O ataque bilinear de v4 sobre $\mathbb{F}_{2^{16}}$ falha (`u0 * y0 = 0xf9a9 != 1`).
   - Entretanto, 1R sem mistura adicional de chave entre palavras desacopla palavra a palavra via $M^{-1}$, sendo quebrada em **0,244 s** em Python (3 pares conhecidos, $32 \times 2^{16}$ buscas).
2. **Crescimento de Grau ANF (palavra 0):**
   - `1R`: `min_deg = 15, max_deg = 15, avg_monomials = 32771.9`
   - `2R`: `min_deg = 15, max_deg = 15, avg_monomials = 32747.6`
   - `3R`: `min_deg = 15, max_deg = 16, avg_monomials = 32768.2` (saturação completa no grau máximo 16 em 3R).
3. **Ataque Square / Integral em 3R `pre_sha` (Quebra Empírica):**
   - Em **2R**, um $\Lambda$-conjunto de $2^{16}$ entradas (palavra 0 percorrendo $0 \dots 65535$, palavras $1 \dots 31$ fixas) produz soma XOR exatamente **`0x0000` em todas as 32 palavras** (`integral_2r_nonzero_words = 0`).
   - Em **3R** (`rsd_s_v5_core_ct(..., rounds=3)`), invertendo $M$ na saída ($z = M^{-1} \text{out}_{3R}$), cada palavra $j$ depende de apenas 16 bits da subchave equivalente $k^*_3[j] = (M^{-1} rk_3)_j \oplus rc_3$.
   - Usando 2 $\Lambda$-conjuntos (**131.072 textos claros escolhidos**), recuperamos **32/32 palavras (todos os 512 bits de $k^*_3$) com 0 falsos positivos em 296,763 s**.
   - Em **4R** (`rounds=4`), a propriedade integral é completamente destruída (`integral_4r_nonzero_words = 32`), preservando margem de segurança de **5 rodadas** até as 8 rodadas oficiais (e na API oficial `diffuse_rsd_s_v5`, o estado pós-8R ainda passa por SHA-256/SHAKE256).

---

## 4. Objetivo 3 — Clustering e Invariantes de `A_16` e `M_CAUCHY_32`

- **Camada afim `A_16`:** Posto 16/16 sobre $\mathbb{F}_2$, ordem multiplicativa $8$ ($A_{16}^8 = I$, $(A_{16} + I)^6 = 0$), polinômio linearizado sobre $\mathbb{F}_{2^{16}}$ com todos os 16 termos não nulos, e **quebra todas as invariâncias de subcorpos** $\mathbb{F}_{2^1}, \mathbb{F}_{2^2}, \mathbb{F}_{2^4}, \mathbb{F}_{2^8}$.
- **Descoberta estrutural em `M_CAUCHY_32`:** Como $M_{i,j} = (i \oplus (32 + j))^{-1}$, a matriz é **XOR-Toeplitz (diádica)** na álgebra de grupo $\mathbb{F}_{2^{16}}[C_2^5]$:
  1. Todas as 32 linhas e 32 colunas têm a **mesma soma** (1 soma distinta, não nula).
  2. **$M^2 = \text{0x5e26} \cdot I$** (involutiva a menos de escalar, implicando $M^{-1} = \text{0x5e26}^{-1} \cdot M$ e ordem multiplicativa $43.690$).
  3. O subespaço de palavras constantes $\{(a, a, \dots, a)\}$ é invariante sob $M$ (quebrado pelas subchaves independentes `rk_r`).
- **Impacto em 8R:** Apesar da estrutura diádica de $M$, seu *Branch Number* permanece $\mathcal{B} = 33$, garantindo $\ge 4 \times 33 = 132$ S-boxes ativas em 8R, probabilidade diferencial de trilha única $\le (2^{-14})^{132} = 2^{-1848}$ e correlação linear $\le (2^{-7})^{132} = 2^{-924}$.
