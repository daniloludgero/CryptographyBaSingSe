# Relatório Cirúrgico Rodada 3 (Métrica 3) — Álgebra Matricial de $M_{\text{v5.1}}$ (`MDS_COL_PERM_V51`) e Resistência Square/Integral em 1R–4R

> **Nota de versão.** Este relatório é anterior à v5.2 e descreve medições da linha v5.1. Resultados de segurança e desempenho **não foram refeitos na v5.2** salvo onde o texto disser o contrário. Vetores de referência da v5.2: `testes/vetores_v52.json`.


- **Data:** `2026-11-22`
- **Escopo Exclusivo:** Métrica 3 — Álgebra Matricial sobre $\text{GF}(2^{16})$ (módulo irredutível/primitivo `0x1100B` $= x^{16} + x^{12} + x^3 + x + 1$) de $M_{\text{v5.1}} = M_{\text{v5.0}} P$ após a permutação assimétrica de colunas `MDS_COL_PERM_V51` ($p(j) = (5j + 1) \bmod 32$), verificação de menores MDS e *Branch Number* $\mathcal{B} = 33$, quebra da involução escalar $M^2 = cI$, e resistência a ataques Square/Integral ($\Lambda$-set) e crescimento de grau algébrico (ANF) em 1R–4R.
- **Alvos Auditados:**
  - `implementacao/rsd_s_v5_hardened.py` (`MDS_COL_PERM_V51`, `M_CAUCHY_32`, `_mds_mult_v5_ref`)
  - `implementacao/c_core/rsd_s_v5_ct.c` (`CAUCHY_MDS`, `CAUCHY_BIT_BASIS`, `init_cauchy_mds`, `mds_mult_ct`)
- **Artefatos Reproduzíveis:**
  - Suíte de testes: `testes/test_r3_metric3_mds_algebra.py`
  - Evidência JSON: `resultados/v5_sandbox/r3_metric3_mds_algebra_20261122.json`

---

## 1. Resumo Executivo e Vereditos Cirúrgicos

| Sub-Métrica Auditada | Baseline `v5.0` ($M_{\text{v5.0}}$) | Correção Final `v5.1` ($M_{\text{v5.1}} = M_{\text{v5.0}} P$) | Veredito |
| :--- | :--- | :--- | :--- |
| **1.1 Sincronização Python $\leftrightarrow$ C99 (`CAUCHY_BIT_BASIS`)** | `M_CAUCHY_32` sem permutação | `1024/1024` entradas de `CAUCHY_MDS` e `16384/16384` entradas de `CAUCHY_BIT_BASIS[32][16][32]` idênticas bit a bit | **CONCLUÍDA (100% Paridade)** |
| **1.2 Estrutura de Ciclo de `MDS_COL_PERM_V51`** | Identidade ($p(j) = j$, 32 pontos fixos) | $p(j) = (5j + 1) \bmod 32$, $\gcd(5, 32) = 1$: bijeção com **ciclo único de comprimento 32** (0 pontos fixos) | **CONCLUÍDA (Transitiva em 32 palavras)** |
| **1.3 Densidade de $M^2, M^3, M^4$ e Quebra de $M^2 = cI$** | $M_{\text{v5.0}}^2 = \text{0x5e26}\cdot I_{32}$ (**`0/992`** fora da diagonal não-nulas) | Em $M_{\text{v5.1}}^2, M_{\text{v5.1}}^3, M_{\text{v5.1}}^4$ (e todo $k \not\equiv 0 \pmod{32}$): **`992/992`** fora da diagonal e **`32/32`** na diagonal não-nulas (**`1024/1024` = 100% densa**). Menor potência escalar ocorre apenas em $k = 32$ ($M_{\text{v5.1}}^{32} = \text{0xb54c}\cdot I_{32}$) | **CONCLUÍDA (Involução 2R Eliminada)** |
| **1.4 Determinante, Polinômio Mínimo e Ordem em $\text{GL}_{32}(\text{GF}(2^{16}))$** | $\det = \text{0xb54c}$, $\mu(x) = x^2 + \text{0x5e26}$ (grau 2), ordem $= 43.690$ | $\det = \text{0xb54c}$, $\mu(x) = \chi(x) = x^{32} + \text{0xb54c}$ (**grau 32**, matriz não-derrogatória), ordem multiplicativa exata $= \mathbf{699.040}$ (**aumento de $16\times$**) | **CONCLUÍDA (Grau Mínimo Máximo 32)** |
| **2. Menores MDS e *Branch Number* $\mathcal{B}(M_{\text{v5.1}})$** | $\mathcal{B} = 33$ | $1\times 1$: `1024/1024` $\neq 0$; $2\times 2$ exaustivo: **`246.016/246.016`** $\neq 0$; $31\times 31$ exaustivo (todos os cofatores): **`1024/1024`** invertíveis; amostras $k \in \{3,4,8,16,32\}$: **100% invertíveis**; $\mathcal{B}_d = \mathcal{B}_l = \mathbf{33}$ (4R $\ge 66$ S-boxes ativas, $p \le 2^{-924}$) | **CONCLUÍDA (Propriedade MDS 100% Preservada)** |
| **3. Simetria, Invariantes Diádicos e Square/Integral 1R–4R** | $M^T = M$, $M^{-1} = \text{0xaa9d}\cdot M$, comuta com `31/31` translações diádicas $D_a$ | $M^T \neq M$ (`904/992` pares assimétricos), $M^{-1}$ tem `153` razões distintas frente a $M$, comuta com apenas `1/31` translação diádica ($a=16$) sem chave e `0/31` com chave; em 3R e 4R, soma XOR de $\Lambda$-set tem **`32/32` palavras não-nulas** e grau ANF saturado em **`16`** | **CONCLUÍDA (Atalhos de Reflexão Eliminados)** |

---

## 2. Sincronização Exata e Estrutura Algébrica de $M_{\text{v5.1}}$ sobre $\text{GF}(2^{16})$

### 2.1 Sincronização Bit a Bit Python $\leftrightarrow$ C99 e Decomposição em Ciclo Único
Em `implementacao/rsd_s_v5_hardened.py` (linhas 47–49) e `implementacao/c_core/rsd_s_v5_ct.c` (linhas 178–193), a matriz de difusão linear $32 \times 32$ de `RSD-S v5.1` é definida aplicando a permutação afim de colunas $p(j) = (5j + 1) \bmod 32$ à matriz de Cauchy diádica base $(M_{\text{v5.0}})_{i,j} = (i \oplus (32 + j))^{-1}$ em $\text{GF}(2^{16}) / (\text{0x1100B})$:
$$(M_{\text{v5.1}})_{i,j} = (M_{\text{v5.0}})_{i,\,p(j)} = \bigl(i \oplus (32 + ((5j + 1) \bmod 32))\bigr)^{-1}.$$

1. **Teorema do Ciclo Único de $p(j) = (5j + 1) \bmod 32$:**
   Uma transformação afim $p(j) = (a j + b) \bmod 2^m$ sobre $\mathbb{Z}_{2^m}$ gera um único ciclo de comprimento máximo $2^m$ (polinômio gerador de período completo pelo Teorema de Hull–Dobell) se e somente se:
   - $\gcd(b, 2^m) = 1$ (aqui $b = 1 \implies \gcd(1, 32) = 1$);
   - $a \equiv 1 \pmod 4$ (aqui $a = 5 \equiv 1 \pmod 4$).
   Portanto, $p(j) = (5j + 1) \bmod 32$ é garantidamente uma bijeção transitiva de **ciclo único de comprimento 32** sem nenhum ponto fixo:
   $$(0 \to 1 \to 6 \to 31 \to 28 \to 13 \to 2 \to 11 \to 24 \to 25 \to 30 \to 23 \to 20 \to 5 \to 26 \to 3 \to 16 \to 17 \to 22 \to 15 \to 12 \to 29 \to 18 \to 27 \to 8 \to 9 \to 14 \to 7 \to 4 \to 21 \to 10 \to 19 \to 0).$$
2. **Paridade Python $\leftrightarrow$ C99 (`CAUCHY_BIT_BASIS`):**
   A exportação direta via FFI (`ctypes`) das tabelas estáticas de `rsd_s_v5_ct.c` confirmou:
   - `M_CAUCHY_32[i, j] == CAUCHY_MDS[i][j]` para todas as $32 \times 32 = 1.024$ entradas (`True`).
   - `CAUCHY_BIT_BASIS[j][bit][i] == gf16_mul_ct(M_CAUCHY_32[i, j], 1 << bit)` para todas as $32 \times 16 \times 32 = 16.384$ entradas (`True`).
   - Paridade exata entre `mds_mult_ct` (AVX2 decomposição binária em C99) e `_mds_mult_v5_ref` (Python) em 64/64 vetores aleatórios de 512 bits.

### 2.2 Densidade das Potências $M_{\text{v5.1}}^k$ ($k = 1 \dots 64$) e Resolução da Involução Escalar
Na versão `v5.0`, como $(M_{\text{v5.0}})_{i,j} = f(i \oplus j)$ pertence à álgebra de grupo comutativa $\text{GF}(2^{16})[C_2^5]$ de característica 2, o quadrado de qualquer matriz XOR-Toeplitz colapsa na diagonal:
$$M_{\text{v5.0}}^2 = \left(\sum_{k=0}^{31} f(k)^2\right) I_{32} = \text{0x5e26}\cdot I_{32} \quad (\text{0/992 entradas fora da diagonal não-nulas}).$$

Na versão `v5.1`, $M_{\text{v5.1}} = M_{\text{v5.0}} P$, onde $P$ é a matriz de permutação associada a $p(j) = (5j + 1) \bmod 32$. Como $P$ **não comuta** com $M_{\text{v5.0}}$, os termos cruzados de $M_{\text{v5.1}}^2 = M_{\text{v5.0}} P M_{\text{v5.0}} P$ não se cancelam em pares:

| Potência $k$ | Diagonal Não-Nula ($/32$) | Fora da Diagonal Não-Nula ($/992$) | Total Não-Nulo ($/1024$) | Tipo Estrutural |
| :---: | :---: | :---: | :---: | :--- |
| $M_{\text{v5.0}}^2$ (Baseline v5.0) | `32 / 32` | **`0 / 992`** (`0,0%`) | `32 / 1024` | Matriz Escalar $\text{0x5e26}\cdot I_{32}$ |
| **$M_{\text{v5.1}}^1$** (1R v5.1) | `32 / 32` | **`992 / 992`** (`100,0%`) | `1024 / 1024` | **100% Densa (MDS)** |
| **$M_{\text{v5.1}}^2$** (2R v5.1) | `32 / 32` | **`992 / 992`** (`100,0%`) | `1024 / 1024` | **100% Densa** |
| **$M_{\text{v5.1}}^3$** (3R v5.1) | `32 / 32` | **`992 / 992`** (`100,0%`) | `1024 / 1024` | **100% Densa** |
| **$M_{\text{v5.1}}^4$** (4R v5.1) | `32 / 32` | **`992 / 992`** (`100,0%`) | `1024 / 1024` | **100% Densa** |
| **$M_{\text{v5.1}}^k$ ($1 \le k \le 31$)** | `32 / 32` | **`992 / 992`** (`100,0%`) | `1024 / 1024` | **100% Densa para todo $1 \le k \le 31$** |
| **$M_{\text{v5.1}}^{32}$** | `32 / 32` | `0 / 992` (`0,0%`) | `32 / 1024` | Primeira potência escalar: $\text{0xb54c}\cdot I_{32}$ |
| **$M_{\text{v5.1}}^k$ ($33 \le k \le 63$)** | `32 / 32` | **`992 / 992`** (`100,0%`) | `1024 / 1024` | **100% Densa para todo $k \not\equiv 0 \pmod{32}$** |
| **$M_{\text{v5.1}}^{64}$** | `32 / 32` | `0 / 992` (`0,0%`) | `32 / 1024` | Segunda potência escalar: $\text{0xeb4d}\cdot I_{32}$ |

### 2.3 Determinante, Polinômio Característico/Mínimo e Ordem Multiplicativa Exata
1. **Determinante Exato sobre $\text{GF}(2^{16})$:**
   Como $\text{GF}(2^{16})$ tem característica 2 (onde $-1 = +1$), toda matriz de permutação $P$ satisfaz $\det(P) = 1 \in \text{GF}(2^{16})^\times$. Logo:
   $$\det(M_{\text{v5.1}}) = \det(M_{\text{v5.0}})\det(P) = \det(M_{\text{v5.0}}) = (\text{0x5e26})^{16} = \mathbf{\text{0xb54c}} \neq 0.$$
2. **Polinômio Mínimo e Polinômio Característico (Subespaço de Krylov e Berlekamp–Massey):**
   - Executando o algoritmo de **Berlekamp–Massey** sobre $\text{GF}(2^{16})$ na sequência de projeções escalares $s_k = u^T M_{\text{v5.1}}^k v$ ($k = 0 \dots 65$) e eliminando a matriz de Krylov $[v, Mv, M^2v, \dots, M^{32}v]$, obtivemos posto completo **`32`** para $[v, Mv, \dots, M^{31}v]$ e relação exata:
     $$M_{\text{v5.1}}^{32} = \text{0xb54c}\cdot I_{32} = (\text{0x5e26})^{16}\cdot I_{32}.$$
   - Como nenhuma potência $1 \le k < 32$ é escalar e o subespaço de Krylov tem dimensão 32, o polinômio mínimo $\mu_{M_{\text{v5.1}}}(x)$ coincide com o polinômio característico $\chi_{M_{\text{v5.1}}}(x)$ (matriz **não-derrogatória / cíclica**):
     $$\mu_{M_{\text{v5.1}}}(x) = \chi_{M_{\text{v5.1}}}(x) = x^{32} + \text{0xb54c} = (x + \text{0x835a})^{32} \in \text{GF}(2^{16})[x],$$
     onde $\text{0x835a} = (\text{0xb54c})^{2^{-5}} = (\text{0x5e26})^{2^{-1}}$ em $\text{GF}(2^{16})$. Em contraste, $M_{\text{v5.0}}$ possuía polinômio mínimo de grau apenas 2 ($\mu_{M_{\text{v5.0}}}(x) = x^2 + \text{0x5e26}$) com 16 blocos de Jordan $2 \times 2$ idênticos.
3. **Ordem Multiplicativa Exata em $\text{GL}_{32}(\text{GF}(2^{16}))$:**
   - Em $\text{GF}(2^{16})^\times$ (grupo cíclico de ordem $2^{16} - 1 = 65.535 = 3 \times 5 \times 17 \times 257$), tanto $c_0 = \text{0x5e26}$ quanto $c_{32} = c_0^{16} = \text{0xb54c}$ (visto que $\gcd(16, 65535) = 1$) possuem ordem multiplicativa exata:
     $$\text{ord}_{\text{GF}(2^{16})^\times}(\text{0xb54c}) = \frac{65535}{3} = 21.845 = 5 \times 17 \times 257.$$
   - Como $M_{\text{v5.1}}^k$ é escalar se e somente se $32 \mid k$, e $M_{\text{v5.1}}^{32m} = (\text{0xb54c})^m I_{32} = I_{32} \iff 21.845 \mid m$, a ordem multiplicativa exata de $M_{\text{v5.1}}$ é:
     $$\text{ord}_{\text{GL}_{32}(\text{GF}(2^{16}))}(M_{\text{v5.1}}) = 32 \times 21.845 = \mathbf{699.040},$$
     contra $\text{ord}(M_{\text{v5.0}}) = 2 \times 21.845 = 43.690$ (expansão exata de **$16\times$**).

---

## 3. Prova Matemática e Verificação Empírica da Propriedade MDS e $\mathcal{B}(M_{\text{v5.1}}) = 33$

### 3.1 Prova Matemática da Invariância MDS sob Permutação de Colunas
**Teorema:** Seja $M \in \text{GF}(2^n)^{W \times W}$ uma matriz de Cauchy definida por $M_{i,j} = (x_i + y_j)^{-1}$, onde $x_0, \dots, x_{W-1}, y_0, \dots, y_{W-1}$ são $2W$ elementos distintos de $\text{GF}(2^n)$. Para qualquer bijeção $p: \{0, \dots, W-1\} \to \{0, \dots, W-1\}$ com matriz de permutação $P$, a matriz $M' = M P$ é MDS e possui *Branch Number* diferencial e linear $\mathcal{B}_d(M') = \mathcal{B}_l(M') = W + 1$.

**Demonstração:**
1. Sejam $I = \{i_1 < \dots < i_k\} \subseteq \{0, \dots, W-1\}$ e $J = \{j_1 < \dots < j_k\} \subseteq \{0, \dots, W-1\}$ quaisquer subconjuntos de índices de linhas e colunas de cardinalidade $k \in \{1, \dots, W\}$.
2. A submatriz $k \times k$ de $M' = M P$ nas linhas $I$ e colunas $J$ tem entradas:
   $$(M'_{I,J})_{r,s} = M_{i_r,\, p(j_s)} = \frac{1}{x_{i_r} + y'_{j_s}}, \quad \text{onde } y'_j = y_{p(j)}.$$
3. Como $p$ é uma bijeção em $\{0, \dots, W-1\}$, os elementos $y'_{j_1}, \dots, y'_{j_k}$ são $k$ elementos mutuamente distintos de $\{y_0, \dots, y_{W-1}\}$, que permanece disjunto de $\{x_0, \dots, x_{W-1}\}$.
4. Pelo teorema clássico do determinante de Cauchy sobre qualquer corpo $\mathbb{F}$:
   $$\det(M'_{I,J}) = \frac{\prod_{1 \le r < s \le k} (x_{i_s} - x_{i_r})(y'_{j_s} - y'_{j_r})}{\prod_{r=1}^k \prod_{s=1}^k (x_{i_r} + y'_{j_s})} \neq 0 \quad \text{em } \text{GF}(2^{16}).$$
5. Como todo menor quadrado $k \times k$ ($1 \le k \le 32$) de $M_{\text{v5.1}}$ é não-nulo, o código linear $\mathcal{C} = \{(x, M_{\text{v5.1}} x) : x \in \text{GF}(2^{16})^{32}\}$ (e seu dual $\mathcal{C}^\perp$, gerado por $(I, M_{\text{v5.1}}^T)$) atinge o limite de Singleton com distância mínima:
   $$\mathcal{B}_d(M_{\text{v5.1}}) = \mathcal{B}_l(M_{\text{v5.1}}) = W + 1 = 32 + 1 = \mathbf{33}. \quad \blacksquare$$

### 3.2 Verificação Empírica Exaustiva ($1\times 1$, $2\times 2$, $31\times 31$, $32\times 32$) e Amostral ($k \times k$)

| Ordem do Menor ($k \times k$) | Total Possível $\binom{32}{k}^2$ | Submatrizes Testadas | Submatrizes Invertíveis ($\det \neq 0$) | Taxa de Não-Singularidade |
| :---: | :---: | :---: | :---: | :---: |
| **$1 \times 1$ (Exaustivo)** | $1.024$ | **`1.024`** | **`1.024`** | **`100,00%`** |
| **$2 \times 2$ (Exaustivo)** | $496^2 = 246.016$ | **`246.016`** | **`246.016`** | **`100,00%`** |
| **$3 \times 3$ (Amostral)** | $24.601.600$ | `250` | `250` | **`100,00%`** |
| **$4 \times 4$ (Amostral)** | $1.293.126.400$ | `250` | `250` | **`100,00%`** |
| **$8 \times 8$ (Amostral)** | $1{,}106 \times 10^{14}$ | `250` | `250` | **`100,00%`** |
| **$16 \times 16$ (Amostral)** | $3{,}613 \times 10^{17}$ | `150` | `150` | **`100,00%`** |
| **$31 \times 31$ (Exaustivo — todos os cofatores)** | $32^2 = 1.024$ | **`1.024`** | **`1.024`** | **`100,00%`** |
| **$32 \times 32$ (Exaustivo — matriz completa)** | $1$ | **`1`** | **`1`** ($\det = \text{0xb54c}$) | **`100,00%`** |

- **Verificação Direta de *Branch Number* $\mathcal{B} = 33$:**
  - Para todos os 32 vetores unitários $x = a \cdot e_j$ com $w_H(x) = 1$, verificou-se $w_H(M_{\text{v5.1}} x) = 32 \implies w_H(x) + w_H(M_{\text{v5.1}} x) = 33$.
  - Para todos os $\binom{32}{2} = 496$ pares de colunas $(j_1, j_2)$ com cancelamento forçado na linha 0 ($w_H(x) = 2$), exatamente 31 das 32 palavras de saída permanecem não-nulas ($w_H(M_{\text{v5.1}} x) = 31 \implies 2 + 31 = 33$).
  - **Consequência Wide-Trail:**
    - Em **4 rodadas (4R)**, qualquer trilha diferencial ou linear não-trivial ativa no mínimo $2 \times \mathcal{B} = \mathbf{66}$ S-boxes, limitando a probabilidade diferencial de trilha única a $\le (2^{-14})^{66} = \mathbf{2^{-924}}$ e a correlação linear a $\le (2^{-7})^{66} = \mathbf{2^{-462}}$.
    - Nas **8 rodadas oficiais (8R)**, o número mínimo de S-boxes ativas é $4 \times \mathcal{B} = \mathbf{132}$, limitando qualquer característica diferencial a $\le \mathbf{2^{-1848}}$ e correlação linear a $\le \mathbf{2^{-924}}$.

---

## 4. Impacto da Quebra de $M^2 = cI$ em Invariantes de Reflexão/Involução e Ataques Square/Integral (1R–4R)

### 4.1 Destruição dos Invariantes de Simetria, Autoinversão Escalar e Translação Diádica
Na versão `v5.0`, a matriz de Cauchy base possuía três simetrias algébricas fortes que facilitavam atalhos de reflexão e invariantes de subespaço:
1. **Simetria de Transposição ($M^T = M$):** Em `v5.0`, $M_{\text{v5.0}}$ era 100% simétrica (`0/992` pares fora da diagonal distintos). Em `v5.1`, $M_{\text{v5.1}}^T \neq M_{\text{v5.1}}$, com **`904/992` entradas fora da diagonal assimétricas** ($M_{i,j} \neq M_{j,i}$).
2. **Atalho de Autoinversão Escalar ($M^{-1} = c^{-1} M$):** Em `v5.0`, $M_{\text{v5.0}}^{-1} = \text{0xaa9d}\cdot M_{\text{v5.0}}$ (`1` única razão entrada a entrada entre $M^{-1}$ e $M$), permitindo inverter a camada linear usando a própria matriz $M$ escalonada. Em `v5.1`, $M_{\text{v5.1}}^{-1} = P^T M_{\text{v5.0}}^{-1} = \text{0xaa9d}\cdot P^{-1} M_{\text{v5.0}}$ possui **`153` razões distintas** entrada a entrada frente a $M_{\text{v5.1}}$, eliminando a autoinversão escalar.
3. **Grupo de Translações Diádicas ($D_a$ onde $(D_a)_{i,j} = \delta_{i \oplus j, a}$):**
   - Em `v5.0`, $M_{\text{v5.0}}$ comutava com todas as **`31/31`** matrizes de translação diádica não-triviais ($D_a M_{\text{v5.0}} D_a = M_{\text{v5.0}}$ para todo $a \in \{1, \dots, 31\}$). Assim, na ausência de assimetria de subchaves, qualquer subespaço de reflexão diádica $\{x : x_{i \oplus a} = x_i\}$ era preservado através de 1R, 2R, 3R e 4R (`31/31` subespaços invariantes).
   - Em `v5.1`, como $p(j \oplus a) = (5(j \oplus a) + 1) \bmod 32 \neq p(j) \oplus a$ para todo $a \neq 16$, **`30/31` simetrias diádicas são quebradas diretamente pela matriz $M_{\text{v5.1}}$** (`1/31` restante apenas para o MSB $a = 16$, onde $(5(j \oplus 16) + 1) \bmod 32 = ((5j + 1) \bmod 32) \oplus 16$), e no núcleo com chave (`diffuse_rsd_s_v5_pre_sha`) **`0/31` simetrias ou subespaços de reflexão sobrevivem em 1R, 2R, 3R ou 4R**.

### 4.2 Avaliação Empírica Square / Integral ($\Lambda$-Set Zero-Sum) e Grau Algébrico ANF (1R–4R)
Avaliamos um $\Lambda$-conjunto completo de $2^{16} = 65.536$ estados de entrada (palavra 0 percorrendo todos os elementos de $\text{GF}(2^{16})$, palavras $1 \dots 31$ ativas com constantes fixas) através de 1R, 2R, 3R e 4R, aplicando a **Transformada Rápida de Möbius (FMT)** de 16 variáveis para extrair a Forma Normal Algébrica (ANF) exata de todos os 16 bits da palavra 0 de saída:

| Rodadas | Métrica | `RSD-S v5.0` ($M_{\text{v5.0}}$) | `RSD-S v5.1` ($M_{\text{v5.1}} = M_{\text{v5.0}} P$) | Interpretação Criptanalítica |
| :---: | :--- | :---: | :---: | :--- |
| **1R** | Palavras com soma $\Lambda \neq 0$ ($/32$) | `0 / 32` (`0 / 512` bits) | `0 / 32` (`0 / 512` bits) | Bijeção S-box + combinação linear MDS preserves propriedade $\mathcal{A} \to \mathcal{B}$ em 1R |
| **1R** | Grau ANF (min..max) / Monômios médios | `15..15` / `32.724,5` | `15..15` / `32.717,6` | Grau algébrico ótimo 15 já na 1ª rodada (~50% densidade ANF) |
| **2R** | Palavras com soma $\Lambda \neq 0$ ($/32$) | `0 / 32` (`0 / 512` bits) | `0 / 32` (`0 / 512` bits) | Propriedade integral estrutural de 2R SPN (32 bijeções independentes pós-1R somadas linearmente) |
| **2R** | Grau ANF (min..max) / Monômios médios | `15..15` / `32.801,3` | `15..15` / `32.822,8` | Grau 15 em todas as 16 coordenadas binárias (0 termos de grau 16) |
| **3R** | Palavras com soma $\Lambda \neq 0$ ($/32$) | **`32 / 32`** (`273 / 512` bits) | **`32 / 32`** (`245 / 512` bits) | **Dissipação completa de soma zero em 100% das 32 palavras já na saída de 3R** (~47,9% dos 512 bits iguais a 1) |
| **3R** | Grau ANF (min..max) / Bits de grau 16 | `15..16` (`11 / 16` bits) | **`15..16`** (`6 / 16` bits, `32.776,7` monômios) | **Saturação no grau máximo teórico 16** ($\prod_{i=0}^{15} u_i$ presente na ANF em 3R) |
| **4R** | Palavras com soma $\Lambda \neq 0$ ($/32$) | **`32 / 32`** (`239 / 512` bits) | **`32 / 32`** (`255 / 512` bits) | **Dissipação pseudorrandômica total em 4R** (`255/512 = 49,80%` de bits ativos na soma XOR; propriedade integral 100% destruída) |
| **4R** | Grau ANF (min..max) / Bits de grau 16 | `15..16` (`8 / 16` bits) | **`15..16`** (`8 / 16` bits, `32.707,4` monômios) | **8/16 bits com grau 16 máximo (exatamente o valor esperado 50% de uma função aleatória uniforme)** |

---

## 5. Conclusão e Verificação Reproduzível

1. A permutação assimétrica de colunas `MDS_COL_PERM_V51` ($p(j) = (5j + 1) \bmod 32$) elimina completamente a involução escalar de 2 rodadas $M^2 = \text{0x5e26}\cdot I_{32}$, elevando o grau do polinômio mínimo de **2 para 32** ($\mu(x) = x^{32} + \text{0xb54c}$), expandindo a ordem multiplicativa em $16\times$ (de `43.690` para **`699.040`**) e tornando **`992/992` entradas fora da diagonal não-nulas** em $M_{\text{v5.1}}^2, M_{\text{v5.1}}^3, M_{\text{v5.1}}^4$ (e em toda potência $k \not\equiv 0 \pmod{32}$).
2. A propriedade MDS e o *Branch Number* máximo $\mathcal{B} = 33$ são 100% preservados matemática e empiricamente (`1024/1024` menores $1\times 1$, `246.016/246.016` menores $2\times 2$ e `1024/1024` cofatores $31\times 31$ não-singulares).
3. Em 3R e 4R, a soma XOR sobre $\Lambda$-conjuntos dissipa-se em **`32/32` palavras não-nulas** (`255/512` bits ativos em 4R) com saturação de grau algébrico $d = 16$, preservando uma margem de segurança de **5 rodadas completas** até as 8 rodadas oficiais de `RSD-S v5.1` (além da compressão terminal SHA-256 / SHAKE256).

### Comandos de Verificação Independente
```bash
python3 -m pytest testes/test_r3_metric3_mds_algebra.py -v
python3 testes/test_r3_metric3_mds_algebra.py
```
