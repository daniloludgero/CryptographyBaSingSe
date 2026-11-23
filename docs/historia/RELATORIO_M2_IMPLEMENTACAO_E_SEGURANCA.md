# Relatório Técnico de Auditoria: Segurança de Implementação e Canais Laterais (Milestone 2)

> **Histórico da v4.** Este relatório descreve a primitiva **v4** e os ataques contra ela. A v5 corrigiu os achados aqui listados; mantemos o texto como registro. Ele não descreve a v5.2.


**Primitiva Alvo**: BaSingSe / RSD-S v4 (`implementacao/rsd_s_v4_final.py`, `implementacao/mds_real.py`)  
**Escopo**: Auditoria de Implementação Física/Software — Canais Laterais de Tempo (TVLA), Microarquitetura de Cache, Segurança de Memória e Criptanálise por Injeção de Falhas Diferenciais (DFA)  
**Data da Avaliação**: 07 de Novembro de 2026  
**Status**: CONCLUÍDO — VULNERABILIDADES CRÍTICAS CONFIRMADAS EMPIRICAMENTE  

---

## 1. Sumário Executivo

A versão RSD-S v4 da primitiva BaSingSe corrigiu com êxito os defeitos estruturais e matemáticos de versões preliminares (notadamente o truncamento silencioso de 127 bits da v1 e o rank deficitário da matriz linear original). A estrutura matemática foi estabilizada como uma Rede de Substituição-Permutação (SPN) de 4 rodadas sobre o corpo finito $\mathbb{F}_{2^{16}}$, com estado interno de 512 bits (32 palavras $\times$ 16 bits), difusão por matriz de Cauchy MDS 32×32 ($BN = 33$), camada não-linear de inversão no corpo $S(x) = x^{-1}$, e compressão terminal via SHA-256.

Entretanto, uma avaliação rigorosa de **segurança de implementação** demonstra que o código de referência apresenta vulnerabilidades severas que inviabilizam seu emprego em ambientes de produção e em dispositivos de hardware/embarcados:

1. **Vazamento Massivo por Canal Lateral de Tempo (TVLA)**: A implementação do produto matriz-vetor e da aritmética em $\mathbb{F}_{2^{16}}$ contém desvios condicionais dependentes de dados secretos (`if v[j] != 0` e `while b:`). O teste estatístico de Welch (TVLA) rejeitou a hipótese nula com $|t| = 42.20$ e $|t| = 817.37$ ($p \ll 10^{-5}$), comprovando que o tempo de execução vaza diretamente o segredo.
2. **Exposição Microarquitetural de Cache**: A tabela de consulta da S-box possui 256 KiB, superando em **8 vezes** a capacidade da cache L1 de dados (L1d de 32 KiB). As 4.096 linhas de cache da tabela provocam colisões sistemáticas nos 64 conjuntos de cache, viabilizando ataques de *Prime+Probe* e *Flush+Reload* que expõem os 12 bits superiores de cada palavra de estado.
3. **Insegurança de Memória no Runtime CPython**: A gerência de memória do Python retém chaves mestras e palavras expandidas em pools de `obmalloc` (PyMalloc) sem capacidade de sobrescrita forçada (`explicit_bzero`), sem travamento de páginas físicas (`mlock`), e com persistência de dados sensíveis em partição de swap de disco e arquivos de core dump.
4. **Criptanálise por Falhas Diferenciais (DFA) Catastrófica**: Uma injeção de 2 falhas por palavra ($\le 64$ falhas no total) na entrada da Rodada 4 permite inverter analiticamente a camada de difusão Cauchy via $M^{-1}$, isolar os diferenciais do S-box e **recuperar 100% da chave expandida de rodada $K_4^*$ e do estado interno de 512 bits** no estado pré-SHA.

---

## 2. Auditoria de Canais Laterais de Tempo (TVLA)

### 2.1 Análise de Código dos Pontos Críticos Não-Constantes

A auditoria identificou dois pontos de código com dependência direta do tempo de execução em relação a variáveis secretas:

#### Hotspot 1: Desvio Condicional no Produto Matriz-Vetor (`rsd_s_v4_final.py:93`)
```python
def gf_matrix_vector_mult(M: np.ndarray, v: np.ndarray, n: int) -> np.ndarray:
    result = np.zeros(n, dtype=np.uint32)
    for i in range(n):
        acc = 0
        row = M[i]
        for j in range(n):
            if row[j] != 0 and v[j] != 0:  # <--- VULNERABILIDADE CRÍTICA (Linha 93)
                acc = gf_add(acc, gf_mult(int(row[j]), int(v[j])))
        result[i] = acc
    return result
```

**Mecanismo Algébrico**:
- Pela construção da matriz de Cauchy em `mds_real.py`, $M[i, j] = (x_i \oplus y_j)^{-1}$ com conjuntos disjuntos $\{x_i\} \cap \{y_j\} = \emptyset$. Portanto, $M[i, j] \ne 0$ para todos os 1024 elementos da matriz $32 \times 32$.
- A cláusula `row[j] != 0` é identicamente verdadeira. O desvio reduz-se a `if v[j] != 0:`.
- O vetor $v$ é o estado intermediário após o S-box e a adição da constante de rodada:
  $$v[j] = S(S^{(r-1)}[j]) \oplus rc_r$$
- Se $v[j] = 0$, o processador pula **32 chamadas completas** a `gf_mult` e `gf_add` (uma para cada linha $i$).
- Se todas as palavras forem nulas, **todas as 1024 multiplicações são ignoradas**, gerando um desvio de execução superior a 2,8 milissegundos.

#### Hotspot 2: Aritmética de Galois de Tempo Variável (`mds_real.py:24–33`)
```python
def gf_mult(a: int, b: int, poly: int = GF16_POLY, bits: int = GF16_BITS) -> int:
    result = 0
    while b:                             # <--- LAÇO DEPENDENTE DO MSB (Linha 26)
        if b & 1:                        # <--- DESVIO DEPENDENTE DO PESO (Linha 27)
            result ^= a
        b >>= 1
        a <<= 1
        if a & (1 << bits):              # <--- REDUÇÃO CONDICIONAL (Linha 31)
            a ^= poly
    return result & ((1 << bits) - 1)
```

**Mecanismo Microarquitetural**:
- O laço `while b:` termina assim que os bits restantes de $b$ tornam-se zero. O número de iterações é $N_{\text{iter}} = \lfloor \log_2(b) \rfloor + 1$. Para $b \in [1, 3]$, executa 1–2 iterações; para $b \in [0x8000, 0xFFFF]$, executa 16 iterações.
- A linha `if b & 1:` acumula `result ^= a` condicionalmente ao peso de Hamming de $b$.
- Em `gf_matrix_vector_mult`, o argumento $b$ recebe a palavra secreta $v[j]$. Assim, o tempo de cada multiplicação individual expõe a magnitude e o peso de Hamming do estado interno.

---

### 2.2 Metodologia Estatística TVLA e Dudect

Para verificar a existência de vazamento sem hipóteses prévias sobre a modelagem de consumo (Non-Specific Leakage Assessment), implementou-se o arcabouço em `ferramentas/audit_sidechannel_timing.py`, aderente aos padrões NIST SP 800-22 e à metodologia *dudect* (Reparaz et al., USENIX Security 2017):

1. **Amostragem Entrelaçada (Interleaved Acquisition)**: As execuções das classes A e B são alternadas pseudo-aleatoriamente para anular derivas térmicas e ruído de fundo do sistema operacional.
2. **Isolamento de Runtime**: O coletor de lixo (GC) do Python é forçado via `gc.collect()` antes do ensaio e desativado com `gc.disable()` durante os laços de medição com `time.perf_counter_ns()`.
3. **Filtragem de Outliers (Dudect Percentile Crop)**: Descarta-se o percentil superior (0.5%) de tempos extremos, correspondentes a interrupções de hardware e trocas de contexto de processo.
4. **Acumulação Estável via Algoritmo de Welford**: Atualização em fluxo contínuo de média e variância para evitar erros de cancelamento catastrófico de ponto flutuante:
   $$\mu_k = \mu_{k-1} + \frac{x_k - \mu_{k-1}}{k}, \quad M_{2, k} = M_{2, k-1} + (x_k - \mu_{k-1})(x_k - \mu_k)$$
5. **Estatística t de Welch**:
   $$t = \frac{\bar{T}_A - \bar{T}_B}{\sqrt{\frac{s_A^2}{N_A} + \frac{s_B^2}{N_B}}}$$
   Critério de decisão: $|t| > 4.5 \implies$ Rejeição de $H_0$ com probabilidade $p < 10^{-5}$ (Vazamento confirmado).

---

### 2.3 Resultados Experimentais Consolidados

Os testes executados pelo script `ferramentas/audit_sidechannel_timing.py` produziram os seguintes dados empíricos reais (armazenados em `resultados/sidechannel_timing_results.json`):

| Identificador do Teste | Descrição da Hipótese | Amostras ($N_A / N_B$) | Média Classe A | Média Classe B | Diferença ($\Delta\mu$) | Estatística $t$ de Welch | Veredito Oficial |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **TVLA-SUITE-1** | Matrix Zero Branch Bypass ($v = 0$ vs $v \ne 0$) | 1.000 / 990 | 2.432,55 µs | 5.256,10 µs | **-2.823,55 µs** | **-42.20** | **FAIL (LEAKAGE DETECTED)** |
| **TVLA-SUITE-1B** | Single-Word Zero Bypass ($v[0] = 0$ vs $v[0] \ne 0$) | 998 / 992 | 5.022,36 µs | 5.057,65 µs | -35,29 µs | -0.45 | PASS (Ruído de SO em 1k) |
| **TVLA-SUITE-2** | NIST TVLA Fixed vs Random Input (1 Rodada) | 496 / 499 | 7.794,21 µs | 7.816,25 µs | -22,04 µs | -0.12 | PASS (Ruído de SO em 500) |
| **TVLA-SUITE-3** | Galois Field Arithmetic (Low MSB vs High MSB) | 9.991 / 9.909 | 0,422 µs | 2,138 µs | **-1,716 µs** | **-817.37** | **FAIL (LEAKAGE DETECTED)** |

#### Interpretação Criptanalítica dos Resultados:
- **Suíte 1 ($|t| = 42.20 \gg 4.5$)**: Quando o vetor $v$ possui palavras nulas, o ganho de velocidade é de **$2.16\times$** ($2,43\text{ ms}$ vs $5,26\text{ ms}$). Essa discrepância de quase 3 milissegundos é gigantesca para criptografia e permite que um invasor remoto determine se o estado interno atingiu palavras zero através de medições na rede.
- **Suíte 3 ($|t| = 817.37 \gg 4.5$)**: A multiplicação de Galois é mais de **5 vezes mais lenta** para operandos com MSB alto em relação a operandos baixos (421,78 ns vs 2.137,53 ns). Como a multiplicação é executada milhões de vezes ao longo das rodadas, este vazamento domina a dispersão temporal total da cifra.

---

## 3. Análise Microarquitetural de Cache

### 3.1 Pegada de Memória da S-Box vs Hierarquia de Cache

Em `rsd_s_v4_final.py:39–48`, a tabela de substituição é pré-computada em um arranjo unidimensional:
- Dimensão: $2^{16} = 65.536$ entradas de 32 bits (`np.uint32`, 4 bytes cada).
- Tamanho total da tabela:
  $$\text{Tamanho} = 65.536 \times 4\text{ bytes} = 262.144\text{ bytes} = 256\text{ KiB}$$

Em processadores modernos (x86_64 Intel Core / AMD Zen / ARM Cortex-A):
- **Cache L1 de Dados (L1d)**: tipicamente $32\text{ KiB}$ (ou $48\text{ KiB}$).
- **Linha de Cache ($L$)**: $64\text{ bytes}$.
- **Associatividade ($W$)**: 8 vias (8-way set associative).
- **Número de Conjuntos de Cache ($S$)**:
  $$S = \frac{32 \times 1024}{64 \times 8} = 64\text{ conjuntos}$$

```
+-----------------------------------------------------------------------------------+
|                            CPU L1d Cache (32 KiB)                                 |
|  64 Conjuntos x 8 Vias = 512 Linhas de Cache (Total: 32.768 Bytes)                |
+-----------------------------------------------------------------------------------+
                                          ^
                                          | Apenas 1/8 da tabela cabe na L1d (12,5%)
                                          v
+-----------------------------------------------------------------------------------+
|                     RSD-S v4 base_sbox Lookup Table (256 KiB)                     |
|  65.536 entradas x 4 bytes = 4.096 Linhas de Cache (Total: 262.144 Bytes)         |
|  64 Linhas da Tabela mapeadas concorrentemente para cada Conjunto de 8 Vias!       |
+-----------------------------------------------------------------------------------+
```

### 3.2 Conflito de Conjuntos e Auto-Evicção

1. **Taxa de Sobre-inscrição**: A tabela de 256 KiB ocupa exatamente $4.096$ linhas de 64 bytes. Como a L1d possui apenas 64 conjuntos:
   $$\frac{4.096\text{ linhas}}{64\text{ conjuntos}} = 64\text{ linhas por conjunto}$$
   Cada conjunto de 8 vias recebe 64 linhas da tabela. A taxa de sobre-inscrição é de **8:1** ($800\%$).
2. **Entradas por Linha**: Cada linha de cache armazena $\frac{64\text{ bytes}}{4\text{ bytes}} = 16$ inversos consecutivos:
   $$\text{Linha } k = \{S(16k), S(16k + 1), \dots, S(16k + 15)\}$$
3. **Auto-Evicção Sistemática**: Em cada rodada, 32 palavras são consultadas no S-box ($4 \times 32 = 128$ consultas na cifra completa). Pelo paradoxo do aniversário generalizado, a probabilidade de colisão em um mesmo conjunto de cache entre as 32 palavras da rodada 1 excede $99.99\%$. Assim, o algoritmo gera tráfego contínuo e imprevisível de evicção para as caches L2 e L3.

### 3.3 Modelagem de Ataques Microarquiteturais

#### Vetor 1: Prime+Probe (Processos Concorrentes / SMT Co-residentes)
Em ambiente de nuvem compartilhada ou com Simultaneous Multithreading (Hyper-Threading):
1. **Prime**: O invasor aloca um buffer de 32 KiB e preenche todas as 8 vias dos 64 conjuntos de L1d.
2. **Vítima**: O alvo executa uma rodada de `diffuse_rsd_s_final`. A leitura `base_sbox[state[i]]` força o desalojamento das linhas do invasor no conjunto correspondente:
   $$\text{conjunto} = (state[i] \gg 4) \ \& \ 0x3F$$
3. **Probe**: O invasor relê seu buffer com `RDTSC`. Os conjuntos que sofreram falha de cache (miss) revelam diretamente os **6 bits intermediários** do valor $state[i] = X[i] \oplus K_0^*[i]$, permitindo isolar a chave de pré-branqueamento $K_0^*$.

#### Vetor 2: Flush+Reload (Bibliotecas Compartilhadas e Páginas Deduplicadas)
Se o módulo for carregado via biblioteca compartilhada ou memória compartilhada:
1. O invasor invalida (`clflush`) uma linha específica $k$ da tabela `_INVERSION_SBOX_CACHE`.
2. Após a execução da vítima, o invasor cronometra a leitura da linha $k$.
3. Um tempo de acerto (hit de ~4 ciclos) indica que o estado da vítima satisfez:
   $$state[i] \in [16k, 16k + 15] \iff (state[i] \gg 4) = k$$
4. Isso expõe **12 bits de uma única palavra de estado em uma única cifragem**, reduzindo o espaço de busca da palavra de chave de 16 bits ($65.536$) para apenas 4 bits ($16$ candidatos).

---

## 4. Auditoria de Segurança de Memória e Higiene de Segredos

### 4.1 Ciclo de Vida dos Segredos no Runtime CPython

O rastreamento do fluxo de dados sensíveis na implementação demonstrou fragilidades intrínsecas ao modelo de gerência de memória do CPython:

```
+-----------------------------------------------------------------------------+
|                            CPYTHON PROCESS HEAP                             |
|                                                                             |
|  Master Key s (32 B)  ========> [ HMAC Key Derivation ]                     |
|  [PyBytesObject: Imutável]       |                                          |
|                                  v                                          |
|  Round Keys K0..K4    ========> [ _expand_key_words() ]                     |
|  [5x PyBytesObject: Imutáveis]   |                                          |
|                                  v                                          |
|  Material Intermediário ======> [ np.ndarray (uint64) ]                     |
|  [Fragmentos x, y, S-box]        |                                          |
|                                  v                                          |
|  Sem explicit_bzero()  =======> Pools de PyMalloc retidos                   |
|  Sem mlock()           =======> Paginado para Swap de Disco (/dev/dm-0)     |
|  Sem PR_SET_DUMPABLE   =======> Exposto em ELF Core Dumps                   |
+-----------------------------------------------------------------------------+
```

### 4.2 Falhas Estruturais Identificadas

1. **Imutabilidade de `PyBytesObject`**: Os objetos de chave (`s`, `keys`, `material`) são instâncias de `bytes`, cuja estrutura interna `ob_sval` é imutável no runtime do Python. Não existe mecanismo em código puro Python para sobrescrever esses buffers com zeros antes que as variáveis saiam de escopo.
2. **Retenção no Alocador PyMalloc**: O CPython aloca objetos menores que 512 bytes em blocos organizados em *arenas* de 256 KiB e *pools* de 4 KiB. Quando o contador de referências chega a zero, a memória não é devolvida ao sistema operacional e nem zerada; o bloco é simplesmente colocado em uma lista livre (`free list`). O material de chave permanece legível na memória do processo por tempo indefinido.
3. **Ausência de Travamento de Memória (`mlock`)**: O runtime não executa a chamada de sistema `mlock(2)` ou `VirtualLock`. Sob pressão de memória, o daemon `kswapd` do Linux transfere as páginas de heap contendo as chaves para a partição de swap em disco não-volátil (SSD/NVMe), onde persistem após o encerramento do processo e reinicializações do sistema.
4. **Vulnerabilidade a Despejos de Memória (Core Dumps)**: Em caso de terminação anormal (`SIGSEGV`, `SIGABRT` ou OOM killer), o kernel gera um arquivo ELF de core dump contendo a íntegra da heap. Qualquer usuário com acesso forense ao disco pode extrair as chaves de 512 bits com utilitários simples (`strings`, `hexdump`).

---

## 5. Criptanálise por Injeção de Falhas Diferenciais (DFA)

### 5.1 Formulação Matemática do Ataque

O ataque de falhas diferenciais contra o RSD-S v4 explora a estrutura linear da matriz Cauchy MDS combinada com o inverso algébrico no corpo finito $\mathbb{F}_{2^{16}}$:

```
+-----------------------------------------------------------------------------------+
|                        PIPELINE DA RODADA 4 SOB FALHA (DFA)                       |
|                                                                                   |
|  Estado S^(3) ------------> [ S-Box Layer ] --------> V^(4) -------> [ Cauchy MDS ]|
|     ^                              ^                    |              |          |
|     |                              |                    v              v          |
|  Falha delta injetada              |                 Delta V^(4)   Delta W^(4)    |
|  (na palavra k)                    |                (1 palavra)   (32 palavras)   |
|                                    |                    |              |          |
|                                    +--------------------+--------------+          |
|                                                         |                         |
|                                                         v                         |
|                                         Saída Pré-SHA Z = W^(4) ^ K4*             |
|                                         Saída com Falha Z_tilde                   |
|                                                         |                         |
|                                                         v                         |
|                                    Diferença Delta Z = Delta W^(4)                |
|                                    Inversão Cauchy: Delta V^(4) = M^(-1) * Delta Z|
|                                    Equação Quadrática: X^2 ^ delta*X ^ c = 0      |
+-----------------------------------------------------------------------------------+
```

#### Passo 1: Propagação Diferencial no S-Box
Ao injetar uma falha $\delta \in \mathbb{F}_{2^{16}}^*$ na palavra $k$ do estado de entrada $S^{(3)}$:
$$\tilde{S}^{(3)}_k = S^{(3)}_k \oplus \delta, \quad \tilde{S}^{(3)}_i = S^{(3)}_i \quad (\forall i \ne k)$$
Após a camada de substituição e constante de rodada $rc_4$:
$$\tilde{V}^{(4)}_i = S(\tilde{S}^{(3)}_i) \oplus rc_4, \quad V^{(4)}_i = S(S^{(3)}_i) \oplus rc_4$$
A diferença $\Delta V^{(4)} = \tilde{V}^{(4)} \oplus V^{(4)}$ cancela a constante $rc_4$:
$$\Delta V^{(4)}_k = S(S^{(3)}_k \oplus \delta) \oplus S(S^{(3)}_k), \quad \Delta V^{(4)}_i = 0 \quad (\forall i \ne k)$$
O vetor $\Delta V^{(4)}$ possui suporte estritamente unitário (apenas a palavra $k$ é não-nula).

#### Passo 2: Difusão Linear e Cancelamento da Chave de Rodada
Pela linearidade da multiplicação matricial sobre $\mathbb{F}_{2^{16}}$:
$$\Delta W^{(4)} = M \cdot \Delta V^{(4)}$$
Na saída do estado pré-SHA $Z = W^{(4)} \oplus K_4^*$:
$$\Delta Z = \tilde{Z} \oplus Z = (\tilde{W}^{(4)} \oplus K_4^*) \oplus (W^{(4)} \oplus K_4^*) = \Delta W^{(4)} = M \cdot \Delta V^{(4)}$$
**A chave de rodada $K_4^*$ cancela-se de forma exata e universal.**

#### Passo 3: Inversão Linear via Matriz Inversa de Cauchy $M^{-1}$
Como $M$ é Cauchy MDS, sua inversa $M^{-1}$ sobre $\mathbb{F}_{2^{16}}$ existe e é pré-computável. Multiplicando a diferença observada $\Delta Z$ por $M^{-1}$:
$$D = M^{-1} \cdot \Delta Z = M^{-1} \cdot (M \cdot \Delta V^{(4)}) = \Delta V^{(4)}$$
Propriedades de $D$:
1. $D_i = 0$ para todo $i \ne k$, identificando automaticamente o índice exato da palavra falhada.
2. $D_k = \Delta V^{(4)}_k = S(S^{(3)}_k \oplus \delta) \oplus S(S^{(3)}_k)$.

#### Passo 4: Resolução Algébrica do S-Box
Substituindo $S(x) = x^{-1}$ sobre $\mathbb{F}_{2^{16}}$ para a incógnita $X = S^{(3)}_k$:
$$(X \oplus \delta)^{-1} \oplus X^{-1} = D_k$$
Multiplicando por $X(X \oplus \delta) \ne 0$:
$$\delta = D_k (X^2 \oplus \delta X) \iff X^2 \oplus \delta X \oplus \delta D_k^{-1} = 0$$

**Teorema de Multiplicidade**:
Para qualquer equação quadrática da forma $X^2 \oplus \delta X \oplus c = 0$ sobre $\mathbb{F}_{2^{16}}$:
Se $X_0$ é uma solução, então $X_0 \oplus \delta$ é também solução:
$$(X_0 \oplus \delta)^2 \oplus \delta(X_0 \oplus \delta) \oplus c = X_0^2 \oplus \delta^2 \oplus \delta X_0 \oplus \delta^2 \oplus c = X_0^2 \oplus \delta X_0 \oplus c = 0$$
Portanto, uma única falha $\delta_1$ reduz o espaço de busca para **no máximo 2 candidatos**:
$$C_1 = \{X_0, X_0 \oplus \delta_1\}$$

#### Passo 5: Recuperação Unívoca com 2 Falhas por Palavra
Injetando uma segunda falha $\delta_2 \ne \delta_1$ na mesma palavra $k$:
$$C_2 = \{X_0, X_0 \oplus \delta_2\}$$
A interseção dos conjuntos fornece a palavra genuína com 100% de certeza:
$$C_1 \cap C_2 = \{X_0\} \implies S^{(3)}_k = X_0$$
Repetindo o procedimento para as 32 palavras $k \in [0, 31]$, o atacante reconstrói todo o estado $S^{(3)}$ com **exatamente $32 \times 2 = 64$ falhas**.

#### Passo 6: Extração da Chave de Rodada $K_4^*$
Com $S^{(3)}$ inteiramente conhecido:
1. Calcula-se a rodada nominal forward:
   $$V^{(4)}_i = S(S^{(3)}_i) \oplus rc_4 \quad (\forall i \in [0, 31]), \quad W^{(4)} = M \cdot V^{(4)}$$
2. Como $Z$ é conhecido da cifragem sem falha:
   $$K_4^* = W^{(4)} \oplus Z$$
A chave expandida de rodada de 512 bits é completamente extraída.

---

### 5.2 Validação Experimental do DFA

O script `ferramentas/audit_dfa_simulation.py` foi executado contra instâncias genuínas do RSD-S v4 com chaves aleatórias distintas. Os resultados (registrados em `resultados/dfa_simulation_results.json`) confirmam a previsão teórica:

| Teste | Chave Mestra $s$ (prefixo) | Falhas Injetadas | Taxa de Recuperação de $S^{(3)}$ | Taxa de Recuperação de $K_4^*$ | Chave Recuperada == Genuína | Média Avalanche SHA-256 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Run 1** | `34e1614210060f3d...` | 64 | 100% (32/32 palavras) | 100% (512 bits) | **True** (Idênticas) | 49.90% (127.73 bits) |
| **Run 2** | `57e9c9b6359c8fdd...` | 64 | 100% (32/32 palavras) | 100% (512 bits) | **True** (Idênticas) | 50.03% (128.08 bits) |
| **Run 3** | `408219688436dbcb...` | 64 | 100% (32/32 palavras) | 100% (512 bits) | **True** (Idênticas) | 50.71% (129.81 bits) |

### 5.3 Análise de Mascaramento Pós-SHA-256

Uma questão arquitetural essencial é a fronteira entre o estado interno pré-SHA e a saída pública pós-SHA:
- Na função oficial `diffuse_rsd_s_final()`, a saída é $C = \text{SHA-256}(Z)$.
- A injeção de falha produz $\Delta C = \text{SHA-256}(\tilde{Z}) \oplus \text{SHA-256}(Z)$.
- Como demonstrado experimentalmente, $\Delta C$ exibe **$50.21\%$ de avalanche** (~128 bits invertidos em 256). A não-linearidade do SHA-256 impede a inversão direta de $\Delta C$ para recuperar $\Delta Z$.
- **Conclusão de Auditoria**: O SHA-256 terminal atua como um escudo opaco que esconde a fraqueza interna na API pública. No entanto, em implementações de circuito físico (ASIC/FPGA/Smartcard), o registrador de 512 bits de $Z$ fica fisicamente exposto no barramento antes da compressão do coprocessador de hash, permitindo a extração via sondagem eletromagnética (EMA), análise de energia (DPA/CPA) ou leitura de memória. Confiar em um hash final para compensar a fragilidade intrínseca da primitiva viola os princípios de defesa em profundidade.

---

## 6. Recomendações de Hardening para Produção

Para elevar a segurança de implementação do RSD-S v4 ao nível exigido por padrões como FIPS 140-3 e ISO/IEC 19790, recomendam-se as seguintes intervenções arquiteturais:

### 6.1 Implementação em Tempo Constante (Constant-Time)
1. **Eliminação do Desvio de Linha 93**: Remover incondicionalmente a checagem `if row[j] != 0 and v[j] != 0:` em `gf_matrix_vector_mult`. A multiplicação e o acúmulo devem ser executados para todos os $1024$ pares $(i, j)$ de forma estritamente invariante.
2. **Multiplicação de Galois em Tempo Constante**: Substituir o laço `while b:` por 16 iterações estáticas invariantes, utilizando máscaras bitwise sem saltos condicionais (`branchless arithmetic`):
   ```c
   uint32_t gf_mult_ct(uint32_t a, uint32_t b) {
       uint32_t res = 0;
       for (int i = 0; i < 16; i++) {
           uint32_t mask = -(b & 1);
           res ^= (a & mask);
           b >>= 1;
           uint32_t hi_mask = -((a >> 15) & 1);
           a = (a << 1) ^ (0x1100B & hi_mask);
       }
       return res & 0xFFFF;
   }
   ```
3. **S-Box sem Tabelas de Consulta (Bit-Sliced S-Box)**: Substituir o arranjo de 256 KiB por lógica booleana sintetizada ou cálculo algorítmico de inversão via torre de corpos $\mathbb{F}_{(2^8)^2}$ (algoritmo de Itoh-Tsujii com instruções puras de lógica vetorial), eliminando totalmente acessos a memória dependentes de chaves e neutralizando ataques de cache.

### 6.2 Higiene e Proteção de Memória
1. **Reescrita do Núcleo Crítico em C11 ou Rust**: Migrar os procedimentos de expansão de chave e difusão interna para bibliotecas nativas de baixo nível.
2. **Zeroização Garantida**: Utilizar `explicit_bzero` (POSIX.1-2024), `memset_s` (C11 Anexo K) ou o trait `ZeroizeOnDrop` em Rust para assegurar que o compilador não otimize a limpeza de chaves como código morto.
3. **Travamento e Proteção contra Core Dumps**: Invocar `mlock()` para fixar buffers de chave em RAM física e chamar `prctl(PR_SET_DUMPABLE, 0)` ou `madvise(MADV_DONTDUMP)` para bloquear vazamentos via swap de disco e arquivos de despejo.

### 6.3 Contra-Medidas contra Injeção de Falhas (DFA Countermeasures)
1. **Cálculo Duplo com Verificação (Dual-Rail Execution)**: Executar a computação da Rodada 4 duas vezes (ou em canais redundantes independentes) e abortar a operação se os estados divergirem antes da compressão SHA-256.
2. **Injeção de Ruído Aleatório (Infective Countermeasures)**: Se uma divergência for detectada, infestar deliberadamente o estado com entropia pseudo-aleatória em vez de emitir o estado alterado, impedindo a obtenção do diferencial linear $\Delta Z = M \cdot \Delta V$.

---

## 7. Referências Normativas e Bibliográficas

1. **Reparaz, J. M., Balasch, J., & Verbauwhede, I.** (2017). *Dude, is my code constant time?* Proceedings of the 2017 Conference on Cryptographic Hardware and Embedded Systems (CHES).
2. **NIST SP 800-22 Rev. 1a**. *A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications*. National Institute of Standards and Technology.
3. **Biham, E., & Shamir, A.** (1997). *Differential Fault Analysis of Secret Key Cryptosystems*. Advances in Cryptology — CRYPTO '97, LNCS 1294, pp. 513–525.
4. **Piret, G., & Quisquater, J. J.** (2003). *A Differential Fault Attack Technique against SPN Structures, with Application to the AES and KHAZAD*. CHES 2003, LNCS 2779, pp. 77–88.
5. **Osvik, D. A., Shamir, A., & Tromer, E.** (2006). *Cache Attacks and Countermeasures: The Case of AES*. Cryptographers' Track at the RSA Conference (CT-RSA), LNCS 3860, pp. 1–20.
6. **FIPS PUB 140-3**. *Security Requirements for Cryptographic Modules*. National Institute of Standards and Technology (2019).
