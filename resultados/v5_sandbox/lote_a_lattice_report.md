# Lote A — Criptoanálise de Reticulados, NIST SP 800-22 em `y_pub_bytes`, Ataques de Chave Relacionada e Prova KEM/PKE vs PRF/Commitment

> **Nota de versão.** Este relatório é anterior à v5.2 e descreve medições da linha v5.1. Resultados de segurança e desempenho **não foram refeitos na v5.2** salvo onde o texto disser o contrário. Vetores de referência da v5.2: `testes/vetores_v52.json`.


**Alvo:** `implementacao/bandlimited_dual_key.py` (`BandlimitedDualKeyEngine`, $q = 65537$, $\dim = 32$)  
**Script Reproduzível:** `testes/lote_a_lattice_cryptanalysis.py`  
**Dados Brutos:** `resultados/v5_sandbox/lote_a_lattice_report.json`  
**Conformidade:** `implementacao/rsd_s_v4_final.py` preservado intacto; `especificacao/RESTRICOES_DE_PROJETO.md` respeitado.

---

## Sumário Executivo e Vereditos (CONCLUÍDA / REFUTADA)

| Sub-Reivindicação / Objetivo | Veredito | Evidência Empírica / Formal |
| :--- | :--- | :--- |
| **1A. Modo `linear_bandlimited_raw` resiste a inversão** | **REFUTADA** | $B_{K_j}$ tem posto cheio ($32/32$, $\det \equiv 31974 \pmod{65537}$); $B_{K_j}^{-1} Y_{\text{pub}} \bmod 65537$ recupera $S_{\text{priv}}$ 100% em $< 5$ ms. |
| **1B. Modo `dual_key_stochastic_hardened` resiste a LLL / Kannan / CVP** | **CONCLUÍDA** | Controle positivo (LWE ruído pequeno $\{-3..3\}$) recuperado 100% em $d=6,8,12$. No modo endurecido, $e_{\text{priv}}$ é uniforme em $\mathbb{Z}_{65537}^{32}$ (máscara OTP exata): recuperação 0/3; norma do vetor alvo verdadeiro ($141\,958{,}1$ em $d=32$) é **$309{,}6\times$ maior** que a Heurística Gaussiana ($458{,}6$). |
| **2. `y_pub_bytes` bruto passa na suíte NIST SP 800-22** | **REFUTADA** | `raw_y_pub_bytes_hardened` (1.000.000 bits) falha em **9/10 testes** ($p = 0{,}0$; proporção de bits `1` = **$0{,}3334$**). Causa raiz: serialização `to_bytes(3, "big")` introduz 7–8 bits zero por palavra de 24 bits. Sem padding (`16-bit unpadded`) e em `y_pub_digest_256`: **10/10 aprovados**. |
| **3A. Resistência a chaves relacionadas `(s, s ^ 1)` e `(s, s + 1)`** | **CONCLUÍDA** | Distância de Hamming média $\approx 0{,}4986$–$0{,}5014$ (sem viés diferencial em `e_priv` ou `Y_pub` sobre 500 pares). |
| **3B. Segurança sob reuso de `n_sess` com `(x, y)` distintos** | **REFUTADA (Vulnerabilidade Crítica)** | `_derive_dual_key_noise(s, n_sess)` não depende de `(x, y)`. Se `(s, n_sess)` for reutilizado em duas entradas, $Y_{\text{pub}}^{(1)} - Y_{\text{pub}}^{(2)} \equiv B_{K_j}(S_{\text{priv}}^{(1)} - S_{\text{priv}}^{(2)}) \pmod{65537}$, cancelando $e_{\text{priv}}$ e recuperando $\Delta S_{\text{priv}}$ em **20/20 tentativas (100%)**. |
| **4. Modelo Dupla-Chave suporta KEM / PKE** | **REFUTADA (Suporta apenas PRF / Commitment)** | Com $e_{\text{priv}} \sim \mathcal{U}(\mathbb{Z}_{65537}^{32})$, $I(S_{\text{priv}}; Y_{\text{pub}} \mid B_{K_j}) = 0$ e $B_{K_j}$ não possui trapdoor. Decapsulação estilo Regev obtém acurácia **$0{,}5040$** (cara-ou-coroa). O modelo é estritamente um **PRF chaveado / Commitment simétrico verificável**. |

---

## 1. Criptoanálise de Reticulados (LLL / Embedding de Kannan / CVP)

### 1.1 Propriedades Algébricas de $B_{K_j}$
- Dimensão: $32 \times 32$ sobre $\mathbb{Z}_{65537}$ ($q = 65537$, primo de Fermat).
- Posto modular: **32** (posto cheio); $\det(B_{K_j}) \equiv 31974 \pmod{65537} \neq 0$.
- Inversão exata em `linear_bandlimited_raw`: `B_inv @ Y_raw mod 65537 == S_priv` (**quebrado em 100%**).

### 1.2 Embedding de Kannan + LLL ($\delta = 0{,}99$)
Construímos a base de Kannan de dimensão $(2d + 1) \times (2d + 1)$ para $b \equiv A s + e \pmod{65537}$:
$$L = \begin{pmatrix} q I_d & 0 & 0 \\ A^T & I_d & 0 \\ b^T & 0 & 1 \end{pmatrix}$$
onde o vetor alvo é $(-e^T, s^T, -1)$.

| Regime | $d$ | Dimensão do Reticulado | Norma Alvo Verdadeira | Norma Mínima LLL | Heurística Gaussiana (GH) | Recuperação Exata |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Controle Positivo (LWE $\{-3..3\}$)** | 6 | 13 | $\le 11$ | `7.00` | `145.79` | **True (100%)** |
| **Controle Positivo (LWE $\{-3..3\}$)** | 8 | 17 | $\le 13$ | `7.14` | `184.32` | **True (100%)** |
| **Controle Positivo (LWE $\{-3..3\}$)** | 12 | 25 | $\le 15$ | `10.82` | `248.11` | **True (100%)** |
| **Hardened (`e_priv` uniforme)** | 6 | 13 | `58,078.8` | `190.38` | `145.79` ($398{,}4\times$) | **False (0%)** |
| **Hardened (`e_priv` uniforme)** | 8 | 17 | `58,731.5` | `211.15` | `184.32` ($318{,}6\times$) | **False (0%)** |
| **Hardened (`e_priv` uniforme)** | 12 | 25 | `76,817.5` | `302.33` | `248.11` ($309{,}6\times$) | **False (0%)** |
| **Hardened Completo ($d=32$ teórico)** | 32 | 65 | `141,958.1` | — | `458.58` ($309{,}6\times$) | **Impossível** |

**Conclusão Teórica & Empírica:** Em LWE padrão, o ruído pequeno garante $\|v_{\text{alvo}}\|_2 \ll \text{GH}(L)$. Aqui, como $e_{\text{priv}} \sim \mathcal{U}(\mathbb{Z}_{65537}^{32})$ (verificado sobre 32.000 amostras: $\mu = 33154{,}56$ vs esperado $32768{,}0$; $\sigma = 18908{,}65$ vs esperado $18918{,}90$; $\chi^2_{64\text{ bins}} = 62{,}71$), o vetor alvo é $\sim 310\times$ maior que a Heurística Gaussiana e $Y_{\text{pub}}$ constitui um **One-Time Pad exato em $\mathbb{Z}_{65537}^{32}$**. Nenhum ataque de reticulados (LLL, BKZ, CVP ou força bruta ilimitada) pode recuperar $S_{\text{priv}}$ ou $e_{\text{priv}}$ a partir de $(B_{K_j}, Y_{\text{pub}})$ isolado.

---

## 2. Auditoria NIST SP 800-22 Direta sobre `y_pub_bytes` Bruto

Executamos os 10 testes da suíte NIST SP 800-22 (`ferramentas/audit_nist_dieharder.py`, $1.000.000$ bits, $\alpha = 0{,}01$):

| Fluxo Testado | Proporção de `1`s | Aprovados | Detalhe dos P-Valores |
| :--- | :---: | :---: | :--- |
| **`raw_y_pub_bytes_hardened`** (saída bruta `bandlimited_dual_key.py`) | **`0.3334`** | **1 / 10** | Falha em 9/10 com $p = 0.0$ (Monobit, Block Freq, Runs, Longest Run, Spectral DFT, Non-overlapping Template, ApEn, Cusum, Serial). Único aprovado: Binary Matrix Rank ($p = 0.6338$). |
| **`raw_y_pub_bytes_linear`** | **`0.3342`** | **1 / 10** | Falha em 9/10 com $p = 0.0$. Binary Matrix Rank: $p = 0.1037$. |
| **`y_pub_16bit_unpadded_hardened`** (16 bits sem `v=65536`) | **`0.5001`** | **10 / 10** | Todos $p \in [0.1156, 0.9408]$. |
| **`y_pub_digest_256_hardened`** (`y_pub_digest_256`) | **`0.5010`** | **10 / 10** | Todos $p \in [0.0237, 0.5093]$. |

**Causa Raiz:** Na linha 261 de `implementacao/bandlimited_dual_key.py`, cada elemento $v \in [0, 65536]$ é serializado em **3 bytes (24 bits) big-endian**. O byte mais significativo é `0x00` em $65536/65537 \approx 99{,}9985\%$ dos casos e `0x01` nos demais $0{,}0015\%$. Logo, $\sim 33{,}3\%$ de todos os bits em `y_pub_bytes` bruto são zeros estruturais fixos, tornando `y_pub_bytes` bruto **inadequado para uso direto como bitstream pseudoaleatório** (apenas `y_pub_digest_256` / `y_pub_digest_512` ou codificação sem padding são estatisticamente uniformes).

---

## 3. Ataques de Chave Relacionada e Reuso de Nonce `(s, n_sess)`

1. **Chave Relacionada (`s_2 = s_1 ^ (1 << k)` e `s_2 = (s_1 + 1) mod 2^256`, 500 pares):**
   - `HD=1`: $\text{HD}_{\text{bit}}(e_{\text{priv}}) = 0{,}4986$, $\text{HD}_{\text{bit}}(Y_{\text{pub}}) = 0{,}4999$.
   - `+1`: $\text{HD}_{\text{bit}}(e_{\text{priv}}) = 0{,}4972$, $\text{HD}_{\text{bit}}(Y_{\text{pub}}) = 0{,}5014$.
   - Nenhuma correlação ou viés diferencial detectado (HMAC-SHA256 + SHAKE256 isolam as chaves derivadas).
2. **Vulnerabilidade Crítica de Reuso de Nonce (`n_sess`):**
   - `_derive_dual_key_noise(s, n_sess)` (linhas 201–222 de `bandlimited_dual_key.py`) depende **exclusivamente** de `(s, n_sess)` e não inclui `(x, y)` nem `S_priv`.
   - Se o par `(s, n_sess)` for reutilizado para duas entradas distintas $(x_1, y_1) \neq (x_2, y_2)$:
     $$\Delta Y_{\text{pub}} = Y_{\text{pub}}^{(1)} - Y_{\text{pub}}^{(2)} \equiv B_{K_j} \cdot \left(S_{\text{priv}}^{(1)} - S_{\text{priv}}^{(2)}\right) \pmod{65537}$$
   - Testado empiricamente em 20 pares: **$B_{K_j}^{-1} \Delta Y_{\text{pub}} \bmod 65537$ recuperou $\Delta S_{\text{priv}}$ exato em 20/20 casos (100%)**.
   - **Mitigação recomendada:** Vincular `e_priv` ao hash de `(x, y)` (ou exigir unicidade estrita de `n_sess` por invocação como contrato de segurança).

---

## 4. Prova Formal / Refutação: KEM/PKE vs PRF/Commitment

**Teorema (Impossibilidade de KEM/PKE):** O esquema `bandlimited_dual_key` com $Y_{\text{pub}} = (B_{K_j} S_{\text{priv}} + e_{\text{priv}}) \bmod q$ e $e_{\text{priv}} \sim \mathcal{U}(\mathbb{Z}_q^{32})$ **não pode** instanciar um KEM ou PKE.

**Prova:**
1. **Informação Mútua Nula:** Para qualquer $B_{K_j} \in \mathbb{Z}_q^{32 \times 32}$ e qualquer $S_{\text{priv}} \in \mathbb{Z}_q^{32}$, como $e_{\text{priv}}$ é uniforme e independente em $\mathbb{Z}_q^{32}$, a variável aleatória $Y_{\text{pub}}$ é exatamente uniforme em $\mathbb{Z}_q^{32}$, logo $I(S_{\text{priv}}; Y_{\text{pub}} \mid B_{K_j}) = 0$. A chave pública $(B_{K_j}, Y_{\text{pub}})$ não carrega nenhuma estrutura algébrica secreta utilizável por um remetente.
2. **Ausência de Região de Ruído Decapsulável:** Em PKE/KEM baseado em LWE (Regev), a correção depende de $\|e\|$ ser pequeno o suficiente para que $\langle r, e \rangle \bmod q$ permaneça próximo de $0$ após arredondamento. Aqui, $\langle r, e_{\text{priv}} \rangle \bmod q$ é uniforme em $\mathbb{Z}_q$, resultando em erro de decapsulação $\approx 50\%$ (medido empiricamente em 1.000 tentativas: acurácia **`0.5040`**).
3. **Ausência de Trapdoor em $B_{K_j}$:** $B_{K_j}$ é determinística e pública; qualquer parte pode invertê-la ($B_{K_j}^{-1} \bmod q$). Além disso, `verify_public_output` exige a chave simétrica secreta `(s, n_sess)`.

**Conclusão Funcional:** O módulo Dupla-Chave é estritamente uma primitiva **simétrica**: um **PRF chaveado** (sob unicidade de `n_sess`) ou **Commitment simétrico verificável** pelo detentor de `(s, n_sess)`.
