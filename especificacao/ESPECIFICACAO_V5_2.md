# Especificação Técnica — RSD-S v5.2 e Módulo de Dupla Chave (SIV)

**Versão do documento:** `0.6.0` (descreve o contrato da `RSD-S v5.2`)  
**Estado:** protótipo experimental de pesquisa. Sem revisão independente externa. Ver [`GARANTIAS_E_LIMITES`](../docs/evidencia/GARANTIAS_E_LIMITES.md).  
**Baseline histórico preservado:** `implementacao/rsd_s_v4_final.py` (inalterado).  
**Regras de redação:** [`RESTRICOES_DE_PROJETO.md`](RESTRICOES_DE_PROJETO.md).  
**Vetores de referência da v5.2:** [`testes/vetores_v52.json`](../testes/vetores_v52.json) (6 vetores; verificados por `testes/test_vetores_v52.py`).

> **Como ler as tabelas de evidência.** As colunas de "evidência" abaixo reúnem **medições empíricas internas** (testes estatísticos, simulações, contagens). Medição não é prova de segurança. Onde um número vem de campanha feita na linha v5.1, o relatório de origem diz isso na primeira linha.

---

## 1. Histórico de vulnerabilidades e correções (`v4` $\to$ `v5.0` $\to$ `v5.1` $\to$ `v5.2`)

Os ataques e auditorias internas sobre o **RSD-S v4** comprovaram cinco vulnerabilidades e duas lacunas estruturais (remediadas na **v5.0**). A análise da Rodada 2 identificou três lacunas adicionais no módulo de dupla chave, na simetria da matriz MDS e no desempenho escalar, tratadas na **v5.1** (Rodada 3, `2026-11-22`). A revisão ofensiva interna da **v5.2** corrigiu dois achados de severidade Alta e três de severidade Média (ver [`COBERTURA_DE_CRIPTOANALISE`](../docs/evidencia/COBERTURA_DE_CRIPTOANALISE.md)):

| ID | Vulnerabilidade / Lacuna (`v4` e `v5.0`) | Remediação Estrutural Obrigatória em `v5.1` | Critério Binário de Aprovação (Gate) & Evidência Datada (`2026-11-22`) |
| :--- | :--- | :--- | :--- |
| **VULN-01** | DFA recupera 100% de $K_4$ com 64 falhas na R4 (`v4`) | Execução redundante em dois fluxos (A e B) por todas as rodadas `R1..R` + comparação constante ao final; divergência aborta e zera a saída (`rc = -2`). Na v5.1 a redundância cobria só a rodada final (RT-F2-01, corrigido na v5.2) | `dfa_key_recovery_rate == 0.0` (`1.000/1.000` e `32/32` vetores C99/Python bloqueados) |
| **VULN-02** | TVLA $\|t\| = 42{,}20$ (`if v[j] != 0`) e $\|t\| = 817{,}37$ (`while b:`) (`v4`) | Núcleo C99 *branchless* e SIMD AVX2 (`rsd_s_v5_ct.c`) com laços públicos fixos e máscaras aritméticas/vetoriais | `tvla_max_abs_t < 4.5` ($N = 100.000$ pares = `200.000` traços/teste: **`\|t\| = 0,3194`** Fixed-vs-Random e **`\|t\| = 0,0441`** All-Zero-vs-All-Ones em `-O3 -mavx2`) — [`r3_metric4_avx2_tvla_20261122.md`](../resultados/v5_sandbox/r3_metric4_avx2_tvla_20261122.md) |
| **VULN-03** | Tabela LUT de 256 KiB ($8\times$ cache L1d) indexada por segredo (`v4`) | Inversão em $\mathbb{F}_{2^{16}}$ via cadeia de adição de Itoh–Tsujii (0 bytes de LUT dependente de segredo) + base pública `CAUCHY_BIT_BASIS` (32 KiB, alinhada a 32B) indexada apenas por `j` e `bit` | `secret_dependent_lut_bytes == 0` e `secret_dependent_cache_misses == 0` (`512` leituras sequenciais fixas por MDS) — [`r3_metric4_avx2_tvla_20261122.md`](../resultados/v5_sandbox/r3_metric4_avx2_tvla_20261122.md) |
| **VULN-04** | Quebra algébrica bilinear em 25,29 ms (3 pares, 1R) (`v4`) | Camada afim $\mathbb{F}_2$-linear invertível $16 \times 16$ na S-box ($S_{\text{v5}}(x) = A_{16} \cdot x^{-1} \oplus \text{0x63A9}$) + 8 rodadas | `algebraic_1r_recovered == false` (0 pontos fixos, DDT $\Delta_{\max}=4$, LAT $\|W\|_{\max}=512$, grau ANF `15`) |
| **VULN-05** | Retenção de chaves no heap (`v4`) | Limpeza segura via ponteiro `volatile` (`secure_wipe`) de todos os estados intermediários em cada rodada | `residual_key_bytes_after_wipe == 0` |
| **GAP-06** | `pre_sha` 4R falhou em NIST *Approximate Entropy* ($p = 0{,}00198$) (`v4`) | 8 rodadas oficiais ($\ge 132$ S-boxes ativas em 8 rodadas, limite diferencial de característica única $\le 2^{-1848}$) | 100% aprovação NIST SP 800-22 em `pre_sha` e `post_sha` |
| **GAP-07** | Assimetria `<u2` vs big-endian e ausência de separação de domínio (`v4`) | Serialização big-endian (`>u2`) unificada + domínio explícito `RSD-S-V5.1\|CORE\|<rounds>\|<n_sess>` | Paridade bit-a-bit Python $\equiv$ C99 (`-O0`, `-O2`, `-O3 -mavx2`) em `232/232` vetores |
| **FIX-R3-01 (Lote A)** | Reuso de `n_sess` no `Dupla-Chave` (`v5.0`) cancelava $e_{\text{priv}}$ e vazava $\Delta S_{\text{priv}}$ (`100%`) | Mecanismo **SIV (*Synthetic IV*)** em `_derive_dual_key_noise`: $K_{\text{priv}} = \text{HMAC-SHA256}(s, \text{"RSD-S-V5\|DUALKEY\|V5.1\|SIV\|"} \parallel n_{\text{sess}} \parallel S_{\text{priv}})$ | **`0/1.000`** vazamentos em pares aleatórios, **`0/2.048`** em `HW=1` de $S_{\text{priv}}$ e **`0/510`** em flips de $(x,y)$ — [`r3_metric1_siv_z65537_20261122.md`](../resultados/v5_sandbox/r3_metric1_siv_z65537_20261122.md) |
| **FIX-R3-02 (Lote A)** | Codificação de 3 bytes (`to_bytes(3, "big")`, 96B) em `y_pub_bytes` (`v5.0`) tinha MSB `0x00` em `99,9985%` dos casos, reprovando 9/10 no NIST SP 800-22 | Projeção compacta sem padding `_unpadded_z65537_to_bytes64` (64 bytes, 32 palavras `uint16` big-endian) com *folding* determinístico via PRF pública para o elemento de fronteira `65536` | PMF marginal exata $1/65536$ (**`TVD = 0,0`, `KL = 0,0`**), proporção de `1`s = **`0,500006`**, **`10/10` core e `12/12` estendidos do NIST SP 800-22 aprovados** — [`r3_metric2_nist_folding_20261122.md`](../resultados/v5_sandbox/r3_metric2_nist_folding_20261122.md) |
| **FIX-R3-03 (Lote B)** | Matriz Cauchy padrão $M_{i,j} = (i \oplus (32+j))^{-1}$ (`v5.0`) era simétrica e satisfazia involução escalar $M^2 = \text{0x5e26}\cdot I$ | Permutação assimétrica de colunas `MDS_COL_PERM_V51`: $p(j) = (5j + 1) \bmod 32$, preservando 100% da propriedade MDS ($\mathcal{B} = 33$) | **`992/992`** entradas fora da diagonal de $M^2$ não-nulas; 1º escalar em $k=32$ ($M^{32} = \text{0xb54c}\cdot I$); pol. mínimo grau **`32`** ($x^{32}+\text{0xb54c}$); ordem multiplicativa **`699.040` ($16\times$)** — [`r3_metric3_mds_algebra_20261122.md`](../resultados/v5_sandbox/r3_metric3_mds_algebra_20261122.md) |
| **FIX-R3-04 (Lote C)** | Multiplicação MDS escalar (`16.384` passos/rodada) limitava C99 `v5.0` a `~216–224 µs/call` (`~0,20–0,28 MiB/s`) | Vetorização SIMD AVX2 *constant-time* (`gf16_mul_avx2`, `sbox_v5_avx2`) + decomposição binária vetorial sobre `CAUCHY_BIT_BASIS[32][16][32]` | Latência não-contendida de **`16,2649 µs/call` (`3,7526 MiB/s`, `61.482 calls/s`, `559,11 cpb`)** em 8R (`13,30x` speedup) e **`8,9463 µs/call`** em 4R — [`r3_metric5_benchmark_20261122.md`](../resultados/v5_sandbox/r3_metric5_benchmark_20261122.md) |

---

## 2. Contrato matemático do núcleo `RSD-S v5.2`

### 2.1 Espaços e Parâmetros
- **Entradas:** $x, y \in \mathbb{F}_p$ com $p = 2^{255} - 19$; chave secreta $s \in \{0,1\}^{256}$ (32 bytes); contador de sessão/nonce $n_{\text{sess}} \in [0, 2^{64}-1]$.
- **Estado Interno:** $W = 32$ palavras de $B = 16$ bits em $\mathbb{F}_{2^{16}} \cong \mathbb{F}_2[z]/(z^{16} + z^{12} + z^3 + z + 1)$ (`GF16_POLY = 0x1100B`), totalizando 512 bits (64 bytes).
- **Rodadas Oficiais:** $R = 8$. Mínimo de S-boxes ativas (wide-trail) $= \lfloor R/2 \rfloor \cdot 33$: **66 em 4 rodadas, 99 em 6, 132 em 8**. Limite diferencial de **característica única** $\le 2^{-1848}$ e correlação linear $\le 2^{-924}$ em 8 rodadas. Esses limites valem para **uma** característica; não somam trilhas e **não constituem prova de segurança**.

### 2.2 S-Box Afim em $\mathbb{F}_{2^{16}}$ (Sem Pontos Fixos, Vetorizada em AVX2)
Para cada palavra $u \in \mathbb{F}_{2^{16}}$:
1. **Inversão Multiplicativa *Constant-Time* (`gf16_inv_ct` / `sbox_v5_avx2`):** $v = u^{2^{16}-2} = u^{65534}$ em $\mathbb{F}_{2^{16}}$ ($0 \mapsto 0$), computada via cadeia de adição de Itoh–Tsujii (15 elevações ao quadrado e **6** multiplicações em $\mathbb{F}_{2^{16}}$). Na compilação `-O3 -mavx2`, `sbox_v5_avx2` avalia 16 S-boxes de 16 bits simultaneamente por registrador `ymm` (`__m256i`) usando exclusivamente instruções vetoriais *constant-time* (`vpand`, `vpxor`, `vpsllw`, `vpsrlw`, `vpcmpeqw`, `vpcmpgtw`).
2. **Transformação Afim $\mathbb{F}_2$-Linear $A_{16}$:** Matriz circulante invertível de peso de Hamming 9 por linha:
   $$A_{16}(v) = v \oplus \text{rotl}_{16}(v, 1) \oplus \text{rotl}_{16}(v, 2) \oplus \text{rotl}_{16}(v, 3) \oplus \text{rotl}_{16}(v, 4) \oplus \text{rotl}_{16}(v, 5) \oplus \text{rotl}_{16}(v, 7) \oplus \text{rotl}_{16}(v, 11) \oplus \text{rotl}_{16}(v, 13)$$
   Com $\det(A_{16}) = 1 \pmod 2$ (bijeção exata sobre $\{0,1\}^{16}$).
3. **Constante Afim:** $c_{16} = \text{0x63A9}$ (0 pontos fixos e 0 pontos fixos opostos em $\{0, \dots, 65535\}$).
4. **Saída da S-Box:** $S_{\text{v5}}(u) = A_{16}(u^{-1}) \oplus c_{16}$.

### 2.3 Camada linear MDS assimétrica $M_{\text{v5.1}}$ (usada na v5.2) e base vetorial `CAUCHY_BIT_BASIS`
- **Matriz MDS Assimétrica (`M_CAUCHY_32`):** Definida sobre $\mathbb{F}_{2^{16}}$ aplicando a permutação afim de colunas $p(j) = (5j + 1) \bmod 32$ (um único ciclo de comprimento 32, pois $\gcd(5, 32) = 1$):
  $$(M_{\text{v5.1}})_{i,j} = \left(i \oplus (32 + ((5j + 1) \bmod 32))\right)^{-1}$$
  - **Propriedade MDS Preservada:** Todos os $1.024$ menores $1 \times 1$ e todos os $246.016$ menores $2 \times 2$ são não-nulos; *Branch Number* diferencial e linear exato $\mathcal{B}_d = \mathcal{B}_l = 33$.
  - **Quebra da Involução Escalar:** Enquanto $M_{\text{v5.0}}^2 = \text{0x5e26}\cdot I$ tinha polinômio mínimo de grau 2 e ordem $43.690$, $M_{\text{v5.1}}$ possui $992/992$ entradas fora da diagonal não-nulas em $M_{\text{v5.1}}^k$ para todo $k \not\equiv 0 \pmod{32}$, primeiro múltiplo escalar em $k = 32$ ($M_{\text{v5.1}}^{32} = \text{0xb54c}\cdot I$), polinômio mínimo irredutível no grau máximo $m(x) = x^{32} + \text{0xb54c}$ e ordem multiplicativa $699.040$ ($16\times$ maior).
- **Decomposição Binária Vetorial (`CAUCHY_BIT_BASIS[32][16][32]`):**
  - Pré-computa $\text{CAUCHY\_BIT\_BASIS}[j][\text{bit}][i] = (M_{\text{v5.1}})_{i,j} \cdot 2^{\text{bit}}$ em $\mathbb{F}_{2^{16}}$ (tabela pública de $32.768$ bytes alinhada a 32 bytes via `__attribute__((aligned(32)))`, residente na cache L1d).
  - Em `mds_mult_ct`, a tabela é varrida em ordem estritamente sequencial pelas variáveis de laço públicas `j = 0..31` e `bit = 0..15` (512 pares de loads AVX2 alinhados `_mm256_load_si256`), enquanto o bit secreto `(in_vec[j] >> bit) & 1` é convertido aritmeticamente em máscara vetorial de 256 bits (`vmask = _mm256_set1_epi16(-(int16_t)bit_val)`) e acumulado via `vpand` + `vpxor`.

### 2.4 Escalonamento de chaves (`RSD-S-V5.1|CORE|`) e proteção Anti-DFA
- **Tag de domínio:** `DOM_V5 = b"RSD-S-V5.1|CORE|"` + `rounds` (1 B) + `n_sess` (8 B big-endian). O rótulo textual `V5.1` foi **mantido de propósito** na v5.2: trocá-lo mudaria todas as saídas e invalidaria os vetores congelados.
- **Chaves de rodada:** $K_0 = \text{HMAC-SHA256}(s, \text{DOM\_V5} \parallel \text{0x00})$ e $K_r = \text{HMAC-SHA256}(s, K_{r-1} \parallel \text{DOM\_V5} \parallel r)$ para $r = 1, \dots, R$. Cada $K_r$ é expandida em 32 palavras `>u2` (64 B) por `HMAC-SHA256(K_r, "EXP|" || uint32_be(block_idx))` para `block_idx = 0, 1` (v5.2, mitigação RT-F1-01: nenhuma palavra de subchave é cópia literal de $K_r$).
- **Constantes de rodada:** $rc_r = \text{uint16\_be}(\text{HMAC-SHA256}(s, \text{DOM\_V5} \parallel \text{"RC"} \parallel r)[:2])$. A mesma $rc_r$ é somada às 32 palavras da rodada $r$.
- **Proteção Anti-DFA (v5.2, RT-F2-01).** Dois fluxos, **A** e **B**, partem do mesmo estado (após o *whitening*) e executam **todas** as rodadas $r = 1, \dots, R$ com as mesmas chaves e constantes. Ao final comparam-se os dois estados em tempo constante: $\text{diff} = \bigvee_{i=0}^{31} (S_A[i] \oplus S_B[i])$. Se $\text{diff} \ne 0$, os buffers são zerados e a chamada falha (`FaultDetectedError` em Python; `rc = -2` no C99).
  - **O que detecta:** falha que atinja **apenas um** dos fluxos em **qualquer** rodada (a v5.1 só cobria a rodada final).
  - **O que não detecta:** falha que atinja os dois fluxos da mesma forma, como erro na entrada, nas chaves de rodada ou nas constantes, que são compartilhadas pelos dois fluxos no modelo de referência em Python. Também não protege contra quem consegue falhar os dois fluxos de modo coordenado. O custo é cerca de 2× o de uma execução simples.

### 2.5 Definição completa da permutação e da saída
Para $x, y \in \mathbb{F}_p$, chave $s$ (32 B), sessão $n_{\text{sess}}$ e $R$ rodadas:
1. **Fragmentação.** $x = \sum_{j=0}^{15} x_j 2^{16j}$ e $y = \sum_{j=0}^{15} y_j 2^{16j}$. O estado inicial é $W = (x_0, \dots, x_{15}, y_0, \dots, y_{15}) \in (\mathbb{F}_{2^{16}})^{32}$.
2. **Whitening.** $W \leftarrow W \oplus rk_0$, com $rk_0$ = expansão de $K_0$.
3. **Rodada $r = 1, \dots, R$** (para cada palavra $i$): $U_i = S_{\text{v5}}(W_i) \oplus rc_r$; $Z = M_{\text{v5.1}} \cdot U$ sobre $\mathbb{F}_{2^{16}}$; $W \leftarrow Z \oplus rk_r$.
4. **Serialização.** $\text{raw} = \text{uint16\_be}(W_0) \parallel \dots \parallel \text{uint16\_be}(W_{31})$ (64 B).
5. **Compressão final.** Com $\text{dom} = \text{DOM\_V5}$ (incluindo `rounds` e `n_sess`):
   - saída de 32 B: $\text{SHA-256}(\text{dom} \parallel \text{raw})$;
   - saída de 64 B: $\text{SHAKE256}(\text{dom} \parallel \text{"|XOF512|"} \parallel \text{raw})$ com 64 B de saída.

---

## 3. Módulo espectral de banda limitada e operando final de dupla chave (SIV)

### 3.1 Pipeline Determinístico de Banda Limitada (Ponto Fixo Q24 em $\mathbb{Z}_{65537}$)
1. Parâmetros: altura $T = 1000{,}0$, expoente $\alpha = 0{,}5$, corte $X = T^\alpha$, largura de banda $\ell = \frac{\log X}{2\pi}$, primo de Fermat $q = 65537 = 2^{16} + 1$.
2. Aproximação par $g_j \in C_c^\infty(-1, 1)$ normalizada em $L^2$, kernel positivo $K_j = |\mathcal{F}^{-1} g_j|^2$ e autocorrelação $\widehat{K}_j = g_j * \tilde{g}_j$ (suporte compacto em $[-2, 2]$).
3. Soma aritmética finita de Guinand–Weil sobre potências de primos $n = p^k \le X^2$ quantizada em inteiros de 64 bits (escala $2^{24} \bmod 65537$) com deslocamento diagonal estrutural, formando $B_{K_j} \in \mathbb{Z}_{65537}^{32 \times 32}$ invertível ($\det(B_{K_j}) \equiv 31974 \pmod{65537}$).

> **Limite de reprodutibilidade.** A matriz $B_{K_j}$ é construída em ponto flutuante `float64` (somas de cosenos, convolução, FFT) e só depois quantizada em inteiros. Plataformas, bibliotecas numéricas ou versões diferentes podem, em princípio, arredondar de modo diferente e produzir outra $B_{K_j}$. Por isso os vetores de referência fixam as saídas esperadas (que dependem de $B_{K_j}$) e `testes/test_matriz_b.py` confere $\det(B_{K_j}) \bmod 65537 = 31974$. Observação em Linux x86_64, Python 3.13.18 e NumPy 2.5.3: SHA-256 da matriz como 1024 inteiros `int64` little-endian, em ordem de linhas, igual a `e39ccb3f0f325562e48923427c02beb6b8a91b7b867b6d351ad121c4437b35de`. Essa observação **não foi comparada** entre outras plataformas. Uma versão futura deve substituir o `float64` por aritmética inteira ou racional exata.

### 3.2 Operando Final `dual_key_stochastic_hardened` com SIV e Serialização 64B Sem Padding
Dado o estado interno privado pós-SPN $S_{\text{priv}} \in (\mathbb{F}_{2^{16}})^{32}$ e sua serialização canônica de 64 bytes `s_priv_bytes`:
1. **Derivação SIV (*Synthetic IV*) Resistente a Reuso de Nonce (`_derive_dual_key_noise`):**
   $$K_{\text{priv}} = \text{HMAC-SHA256}\!\left(s, \, \text{"RSD-S-V5|DUALKEY|V5.1|SIV|"} \parallel \text{uint64\_be}(n_{\text{sess}}) \parallel \text{s\_priv\_bytes}\right)$$
   O vetor de máscara $e_{\text{priv}} \in \mathbb{Z}_{65537}^{32}$ é extraído de `SHAKE256("RSD-S-V5|DUALKEY|NOISE|V5.1|" || K_priv)` via *rejection sampling* exato sobre palavras de 32 bits com limiar $\text{limit} = 2^{32} - (2^{32} \bmod 65537) = 4.294.967.295 = 65537 \times 65535$, garantindo distribuição perfeitamente uniforme sobre $\mathbb{Z}_{65537}^{32}$ e independência pseudoaleatória para cada par distinto $(n_{\text{sess}}, S_{\text{priv}})$.
2. **Compromisso Modular em $\mathbb{Z}_{65537}^{32}$:**
   $$Y_{\text{pub}} = \left(B_{K_j} \cdot S_{\text{priv}} + e_{\text{priv}}\right) \bmod 65537$$
3. **Serialização Compacta de 64 Bytes Sem Padding (`_unpadded_z65537_to_bytes64`):**
   Para cada coordenada $Y_{\text{pub}}[i] \in \{0, \dots, 65536\}$ ($i \in \{0, \dots, 31\}$):
   - Se $Y_{\text{pub}}[i] < 65536$, emite diretamente `uint16_be(Y_pub[i])`.
   - Se $Y_{\text{pub}}[i] = 65536$ (evento de fronteira com probabilidade $1/65537$), aplica *folding* determinístico via PRF. Na **v5.2** a implementação deriva as 32 palavras de *folding* de **um único fluxo** $F = \text{SHAKE256}(\text{"RSD-S-V5|DUALKEY|FOLD16|V5.2|"} \parallel \text{uint64\_be}(n_{\text{sess}}) \parallel \text{s\_priv\_bytes})$ de 64 B, lido como 32 palavras `>u2`, e escolhe entre $Y_{\text{pub}}[i]$ e $F_i$ por **máscara aritmética, sem desvio dependente de dados** (mitigação RT-F2-04; na v5.1 era um `SHA-256` por coordenada com desvio):
     $$W_i = \begin{cases} Y_{\text{pub}}[i], & Y_{\text{pub}}[i] \le 65535, \\ F_i, & Y_{\text{pub}}[i] = 65536. \end{cases}$$
     A função valida a faixa: coordenadas fora de $\{0,\dots,65536\}$ ou vetor que não seja 1-D levantam `ValueError`.
   - Pela Lei da Probabilidade Total, cada palavra de 16 bits resultante tem probabilidade marginal exata $\frac{1}{65537} + \frac{1}{65537}\cdot\frac{1}{65536} = \frac{1}{65536}$ ($\text{TVD} = 0$, entropia de Shannon e min-entropia iguais a $16{,}0000$ bits/palavra), aprovando `10/10` testes core e `12/12` testes estendidos da bateria NIST SP 800-22.
4. **Representações adicionais retornadas.** Além dos 64 B acima, `refactor_public_output` devolve:
   - `y_pub_z65537_bytes`: representação algébrica **exata** em $\mathbb{Z}_{65537}^{32}$, com 3 B big-endian por coordenada (96 B);
   - `y_pub_digest_256 = SHA-256(DOMAIN_DUALKEY || modo || y_pub_z65537_bytes)` e `y_pub_digest_512 = SHAKE256(DOMAIN_DUALKEY || "XOF512|" || modo || y_pub_z65537_bytes)` (64 B);
   - o estado privado só aparece com `include_private_debug=True` (RT-F2-03).
5. **Não injetividade (RT-F2-05).** A serialização de 64 B mapeia 65537 valores possíveis por coordenada em 65536 palavras, logo **não é injetiva**: com `s_priv_bytes` fixo, o valor `65536` e o valor `F_i` colidem na saída de 64 B. No motor completo, `(x, y)` distintos produzem `s_priv_bytes` distintos, o que muda `F_i`; a colisão é uma propriedade da função isolada. A representação exata (`y_pub_z65537_bytes`) é injetiva.

---

## 4. Modelo quântico e conformidade com `RESTRICOES_DE_PROJETO.md`

Em observância a [`RESTRICOES_DE_PROJETO.md`](RESTRICOES_DE_PROJETO.md):
- O projeto **pode declarar** que a `RSD-S v5.2` **não se baseia** nos problemas atacados pelo algoritmo de Shor (fatoração de inteiros ou logaritmo discreto em grupos abelianos).
- O projeto **não declara** que "supera Shor", nem que tem certificação pós-quântica, nem segurança incondicional. Isso exigiria revisão independente externa e uma prova formal no modelo QROM, que hoje existe apenas como [rascunho condicional](REDUCAO_QROM_RASCUNHO_V5_1.md).
- Custos **genéricos** conhecidos de ataque, citados como referência e **não como garantia** de segurança da construção:
  1. busca de chave por Grover sobre $s$ de 256 bits: $\approx 2^{128}$ consultas quânticas;
  2. colisão quântica (BHT): $O(2^{85{,}3})$ com saída de 32 B (`SHA-256`) e $O(2^{170{,}7})$ com saída de 64 B (`SHAKE256`);
  3. medição empírica: ausência de pico espectral detectável por FFT na saída pública $Y_{\text{pub}}$ do módulo de banda limitada (`z_peak < 6,5`). É um teste de sanidade, não uma prova de ausência de estrutura oculta.
