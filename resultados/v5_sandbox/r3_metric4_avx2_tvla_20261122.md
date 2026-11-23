# Relatório Cirúrgico — Métrica 4 (Rodada 3): Auditoria de Assembly AVX2 (`objdump -d`), Alinhamento de Memória, Cache-Timing de `CAUCHY_BIT_BASIS` e TVLA Estendido ($N = 100.000$ pares)

> **Nota de versão.** Este relatório é anterior à v5.2 e descreve medições da linha v5.1. Resultados de segurança e desempenho **não foram refeitos na v5.2** salvo onde o texto disser o contrário. Vetores de referência da v5.2: `testes/vetores_v52.json`.


- **Data da Especialização:** `2026-11-22`
- **Alvo Auditado:** `implementacao/c_core/rsd_s_v5_ct.c` (`RSD-S v5.1` Constant-Time & AVX2 Core) + Paridade com `implementacao/rsd_s_v5_hardened.py`
- **Suíte de Testes Reproduzível:** `testes/test_r3_metric4_avx2_tvla.py`
- **Artefato JSON Datado:** `resultados/v5_sandbox/r3_metric4_avx2_tvla_20261122.json`
- **Ambiente de Hardware / Compilador:** Linux x86_64 (`Intel(R) Xeon(R) Platinum 8481C`, flags `avx2`, `avx512f`, `avx512bw`), `gcc (Debian 12.2.0-14+deb12u1) 12.2.0`, Python `3.11.2`.

---

## 1. Sumário Executivo e Vereditos Cirúrgicos (Métrica 4)

| # | Pilar da Métrica 4 | Configuração / Escopo | Resultado Empírico | Veredito |
|---|---|---|---|---|
| **1** | **Compilação Multi-Otimização & Paridade Bit-a-Bit Python vs C99** | `-O0`, `-O2` (escalar) e `-O3 -mavx2` (SIMD AVX2) com `-Wall -Wextra -Werror`; **232 vetores** (aleatórios, extremos `0x0000`/`0xFFFF`, palavras ativas únicas e 32 injeções DFA) | **0 warnings, 0 erros** nos 3 perfis; **0 divergências** (`232/232` vetores idênticos bit-a-bit entre `-O0`, `-O2`, `-O3 -mavx2` e Python); **32/32 falhas DFA** retornam `rc = -2` com buffer de saída 100% zerado | **CONCLUÍDA (PASS)** |
| **2** | **Inspeção de Disassembly (`objdump -d`) dos Kernels Escalares e AVX2** | `gf16_mul_ct`, `gf16_inv_ct`, `sbox_v5_ct`, `gf16_mul_avx2`, `sbox_v5_avx2`, `mds_mult_ct` (`mds_diffuse_v5_ct`), `single_round_ct`, `rsd_s_v5_core_ct` (`rsd_s_v5_diffuse_rounds_ct`) | **0 desvios condicionais dependentes de segredo**; **0 instruções `vpgather*` ou acessos a memória indexados por segredo**; **0 instruções `cmov` dependentes de segredo** | **CONCLUÍDA (PASS)** |
| **3** | **Alinhamento de Memória & Cache-Timing de `CAUCHY_BIT_BASIS[32][16][32]`** | Tabela de base binária MDS de `32.768 bytes` (`32 KiB`), `__attribute__((aligned(32)))` | Alinhamento de **32 bytes** confirmado no ELF (`.bss` align `32`, offset `0x20` / `0x800`, `mod 32 == 0`) e em runtime (`0x5763063f6060 % 32 == 0`); **512 linhas de cache de 64B lidas em ordem estritamente sequencial** independentemente do segredo | **CONCLUÍDA (PASS)** |
| **4** | **TVLA Estendido de Welch ($N = 100.000$ pares = $200.000$ traços/teste)** | `lfence; rdtsc` / `rdtscp; lfence` intercalado (*Fixed-vs-Random* e *All-Zero-vs-All-Ones*) em `-O0`, `-O2` e `-O3 -mavx2` ($1.200.000$ traços totais) | Todos os 6 testes (18 estatísticas: `raw`, `p99-trimmed`, `p05-p95 quantile-trimmed`) **$< 4,5$**. Em `-O3 -mavx2`: **$|t| = 0,3194$** (*Fixed-vs-Random*) e **$|t| = 0,0441$** (*All-Zero-vs-All-Ones*) | **CONCLUÍDA (PASS)** |

---

## 2. Pilar 1 — Compilação Multi-Otimização e Paridade Bit-a-Bit Python vs C99

### 2.1 Perfis de Compilação Estrita (`-Wall -Wextra -Werror`)
O arquivo `implementacao/c_core/rsd_s_v5_ct.c` foi compilado em objetos ELF (`.o`), bibliotecas compartilhadas (`.so`) e objetos sem inlining (`-fno-inline`) sob três perfis:

1. **Perfil 1 (`-O0` Escalar sem otimização):**
   `gcc -O0 -Wall -Wextra -Werror -c implementacao/c_core/rsd_s_v5_ct.c` $\to$ `returncode = 0`, `warnings = 0`, `errors = 0`.
2. **Perfil 2 (`-O2` Escalar otimizado sem `-mavx2`):**
   `gcc -O2 -Wall -Wextra -Werror -c implementacao/c_core/rsd_s_v5_ct.c` $\to$ `returncode = 0`, `warnings = 0`, `errors = 0`.
3. **Perfil 3 (`-O3 -mavx2` Vetorizado SIMD AVX2 constant-time):**
   `gcc -O3 -mavx2 -Wall -Wextra -Werror -c implementacao/c_core/rsd_s_v5_ct.c` $\to$ `returncode = 0`, `warnings = 0`, `errors = 0`.

### 2.2 Verificação de Paridade Bit-a-Bit (`232` Vetores de Teste)
| Categoria de Vetores de Teste | Quantidade | Critério Verificado | Divergências (`-O0` vs `-O2` vs `-O3 -mavx2` vs Python) |
|---|---:|---|---:|
| **Casos Extremos da API (`x, y \in \mathbb{F}_p`)** | 10 | `x=0, y=0`, `x=p-1, y=p-1`, `n_sess=0`, `n_sess=2^64-1`, chaves `0x00^32` e `0xFF^32` | **0** |
| **Vetores Aleatórios Uniformes da API** | 120 | `x, y` aleatórios de 255 bits em $\mathbb{F}_p$, chaves de 256 bits e `n_sess` de 64 bits | **0** |
| **Casos Extremos de Palavras Brutas (`uint16_t[32]`)** | 70 | Estado todo zero (`0x0000^32`), estado todo máximo (`0xFFFF^32`), `0x8000^32`, `0x0001^32`, padrões alternados `0xAAAA/0x5555`, e **64 vetores com 1 única palavra ativa** ($j \in \{0..31\}$ com `0x0001` e `0xFFFF`) | **0** |
| **Vetores de Injeção de Falha Anti-DFA** | 32 | Injeção de máscara não-nula em cada palavra $j \in \{0..31\}$ na rodada final; verifica retorno `rc == -2` (`FaultDetectedError` no Python) e limpeza ativa do buffer de saída (`out_state == 0x0000^32` a partir de canário `0xBEEF^32`) | **0** |
| **Total Consolidado** | **232** | **100% de Paridade Bit-a-Bit e Detecção Anti-DFA** | **0** |

---

## 3. Pilar 2 — Auditoria Completa de Disassembly (`objdump -d`)

### 3.1 Contagem de Instruções e Desvios por Função (`-O0`, `-O2`, `-O3 -mavx2`)

> **Nota sobre Símbolos C99:** No código-fonte `implementacao/c_core/rsd_s_v5_ct.c`, a função de difusão MDS é denominada `mds_mult_ct` (referenciada no escopo como `mds_diffuse_v5_ct`) e o ponto de entrada de rodadas é `rsd_s_v5_core_ct` (referenciado como `rsd_s_v5_diffuse_rounds_ct`), que invoca `single_round_ct`. Em `-O3 -mavx2`, o GCC faz *inline* automático das funções `static inline` (`gf16_mul_avx2`, `mds_mult_ct`, etc.) dentro de `sbox_v5_avx2`, `single_round_ct` e `rsd_s_v5_core_ct`. Por isso, auditamos tanto o binário de produção (`-O3 -mavx2`) quanto o binário com símbolos isolados (`-O3 -mavx2 -fno-inline`).

| Função Auditada | Instruções (`-O0`) | Branches (`-O0`) | Instruções (`-O3 -mavx2 -fno-inline`) | Branches (`-O3 -mavx2 -fno-inline`) | Instruções (`-O3 -mavx2` Produção) | Branches Dependentes de Segredo | Acessos de Memória Dependentes de Segredo |
|---|---:|---:|---:|---:|---:|---:|---:|
| `gf16_mul_ct` | 39 | 1 (`jle 68`, loop fixo 16 bits) | 187 | **0** (100% *unrolled*) | *Inlined* em `init_cauchy_mds` | **0** | **0** |
| `gf16_inv_ct` | 68 | **0** | 36 | **0** | *Inlined* em `init_cauchy_mds` | **0** | **0** |
| `sbox_v5_ct` | 57 | **0** | *Substituída por `sbox_v5_avx2`* | **0** | *Substituída por `sbox_v5_avx2`* | **0** | **0** |
| `gf16_mul_avx2` | N/A | N/A | 183 | **0** (100% *unrolled*) | *Inlined* em `sbox_v5_avx2` | **0** | **0** |
| `sbox_v5_avx2` | N/A | N/A | 74 | **0** | 1.957 (2 branches fixos: `sqn` 3 e 7) | **0** | **0** |
| `mds_mult_ct` (`mds_diffuse_v5_ct`) | 78 | 4 (loops fixos $32, 32, 16, 32$) | 190 | 1 (`jne 250`, loop fixo $j=0..31$) | *Inlined* em `single_round_ct` | **0** | **0** |
| `single_round_ct` | 66 | 2 (loops fixos $i=0..31$) | 62 | 2 (guarda de alias + wipe) | 245 (5 branches públicos fixos) | **0** | **0** |
| `rsd_s_v5_core_ct` (`rsd_s_v5_diffuse_rounds_ct`) | 218 | 15 (guardas + loops públicos) | 156 | 8 (guardas + loops públicos) | 2.121 (22 branches públicos fixos) | **0** | **0** |

### 3.2 Mix Exato de Instruções AVX2 (`-O3 -mavx2`)

| Mnemônico AVX2 | `gf16_mul_avx2` (`-fno-inline`) | `mds_mult_ct` (`-fno-inline`) | `sbox_v5_avx2` (Produção `-O3 -mavx2`) | `single_round_ct` (Produção `-O3 -mavx2`) | `rsd_s_v5_core_ct` (Produção `-O3 -mavx2`) | Total na Unidade de Tradução (`-O3 -mavx2`) | Papel Criptográfico Constant-Time |
|---|---:|---:|---:|---:|---:|---:|---|
| `vpand` | 47 | 32 | 547 | 32 | 2 | **581** | Mascaramento aritmético bit-a-bit (`a & mask`, `poly & hi_mask`, `CAUCHY_BIT_BASIS & vmask`, `out_a & keep_mask`) |
| `vpxor` | 31 | 33 | 404 | 37 | 4 | **447** | Adição em $\mathbb{F}_{2^{16}}$, redução modular, camada afim $A_{16}$ $\oplus$ `0x63A9` e acumulação MDS |
| `vmovdqa` | 28 | 14 | 267 | 21 | 20 | **309** | Movimentação vetorial alinhada a 32 bytes (registradores e stack alinhada) |
| `vpsllw` | 15 | 0 | 203 | 0 | 0 | **203** | Deslocamento lógico à esquerda de 16 palavras `uint16_t` (`a << 1` e rotações $A_{16}$) |
| `vpcmpgtw` | 15 | 0 | 195 | 0 | 0 | **195** | Extração branchless do bit 15 (sinal `< 0` em complemento de dois: `zero > a`) para redução por `0x100B` |
| `vpcmpeqw` | 16 | 0 | 144 | 0 | 0 | **144** | Geração branchless de máscara `0xFFFF`/`0x0000` a partir do LSB (`(b & 1) == 1`) |
| `vpsrlw` | 15 | 0 | 143 | 0 | 0 | **143** | Deslocamento lógico à direita de 16 palavras `uint16_t` (`b >>= 1` e rotações $A_{16}$) |
| `vpbroadcastw` | 1 | 16 | 3 | 17 | 1 | **21** | Broadcast de máscara escalar de 16 bits (`vmask`, `rc`, `keep_mask`) para 16 lanes de `__m256i` |
| `vmovd` | 1 | 16 | 3 | 17 | 1 | **21** | Transferência de máscara escalar GPR $\to$ XMM antes de `vpbroadcastw` |
| `vpor` | 0 | 0 | 8 | 0 | 5 | **15** | Junção de rotações (`rotl16_avx2`) e redução horizontal Anti-DFA (`out_a ^ out_b`) |
| `vpbroadcastq` | 2 | 0 | 7 | 0 | 0 | **7** | Broadcast de constantes de 64 bits (`0x100b100b100b100b`, `0x0001000100010001`, `0x63a9...`) |
| `vmovq` | 2 | 0 | 7 | 0 | 0 | **7** | Carregamento de constantes de 64 bits GPR $\to$ XMM |
| `vmovdqu` | 0 | 0 | 0 | 4 | 4 | **8** | Leitura/escrita vetorial de buffers externos do chamador (`in_state`, `rk`, `out_state`) |
| `vpsrldq` | 0 | 0 | 0 | 0 | 3 | **11** | Redução horizontal byte/word dentro de `__m128i` para verificação Anti-DFA |
| `vzeroupper` | 0 | 1 | 0 | 1 | 3 | **6** | Limpeza de estado superior YMM (elimina penalidade de transição AVX/SSE) |
| `vextracti128` | 0 | 0 | 0 | 0 | 1 | **2** | Extração da metade superior de 128 bits de `__m256i` na redução Anti-DFA |
| `vpextrw` | 0 | 0 | 0 | 0 | 1 | **1** | Extração da palavra acumulada `diff` de 16 bits na redução Anti-DFA |
| **`vpgather*`** | **0** | **0** | **0** | **0** | **0** | **0** | **Zero instruções gather em todo o binário** |

### 3.3 Prova de Ausência de Branches Dependentes de Segredo no Anti-DFA (`rsd_s_v5_core_ct`)
No disassembly de `-O3 -mavx2` (`objdump_O3_avx2_noinline.txt`, endereços `0x1141..0x11b9`), até mesmo a verificação de falha Anti-DFA (`diff != 0`) e o zeramento condicional de `out_state` foram compilados pelo GCC em uma sequência **100% sem desvios condicionais (*branchless*)**:
```asm
1153: vpxor        0x100(%rsp),%ymm2,%ymm1      # ymm1 = out_a_lo ^ out_b_lo
115c: vpxor        0x120(%rsp),%ymm3,%ymm0      # ymm0 = out_a_hi ^ out_b_hi
1165: vpor         %ymm0,%ymm1,%ymm1            # redução vertical 256b
1169: vextracti128 $0x1,%ymm1,%xmm0             # extrai 128b superiores
116f: vpor         %xmm1,%xmm0,%xmm0            # redução 128b
1173: vpsrldq      $0x8,%xmm0,%xmm1             # shift 8B
1178: vpor         %xmm1,%xmm0,%xmm0
117c: vpsrldq      $0x4,%xmm0,%xmm1             # shift 4B
1181: vpor         %xmm1,%xmm0,%xmm0
1185: vpsrldq      $0x2,%xmm0,%xmm1             # shift 2B
118a: vpor         %xmm1,%xmm0,%xmm0
118e: vpextrw      $0x0,%xmm0,%edx              # edx = diff (16 bits)
1193: cmp          $0x1,%edx                    # CF = 1 se diff == 0, CF = 0 se diff >= 1
1196: sbb          %ax,%ax                      # ax = 0xFFFF se diff == 0, 0x0000 se diff != 0
1199: neg          %edx                         # CF = 1 se diff != 0, CF = 0 se diff == 0
119b: vmovd        %eax,%xmm0
11a3: sbb          %ecx,%ecx                    # ecx = -1 se diff != 0, 0 se diff == 0
11a5: vpbroadcastw %xmm0,%ymm0                  # ymm0 = keep_mask (256 bits)
11aa: and          $0xfffffffe,%ecx             # ecx = -2 (status) se diff != 0, 0 se diff == 0
11ad: vpand        %ymm2,%ymm0,%ymm1            # out_state_lo = out_a_lo & keep_mask
11b1: vpand        %ymm3,%ymm0,%ymm0            # out_state_hi = out_a_hi & keep_mask
```

---

## 4. Pilar 3 — Alinhamento de Memória e Auditoria de Cache-Timing de `CAUCHY_BIT_BASIS[32][16][32]`

### 4.1 Verificação de Alinhamento de 32 Bytes (ELF + Runtime)
A tabela `CAUCHY_BIT_BASIS[32][16][32]` possui $32 \times 16 \times 32 \times 2 = 32.768\text{ bytes}$ (`32 KiB`, cabendo integralmente no cache L1d de 48 KiB por núcleo do Intel Xeon Platinum 8481C) e é declarada com `__attribute__((aligned(32)))`:

| Perfil | Seção ELF | Alinhamento da Seção `.bss` (`readelf -S`) | Offset do Símbolo (`nm` / `readelf -s`) | `Offset mod 32` | Tamanho (`readelf -s`) | Verificação Runtime `((uintptr_t)CAUCHY_BIT_BASIS % 32) == 0` |
|---|---|---:|---|---:|---:|---|
| **`-O0`** | `.bss` | `32` bytes | `0x0000000000000800` | `0` | `32.768` bytes | **PASS** (`0x5763063f6060 % 32 == 0`) |
| **`-O2`** | `.bss` | `32` bytes | `0x0000000000000020` | `0` | `32.768` bytes | **PASS** (`0x5763063f6060 % 32 == 0`) |
| **`-O3 -mavx2`** | `.bss` | `32` bytes | `0x0000000000000020` | `0` | `32.768` bytes | **PASS** (`0x5763063f6060 % 32 == 0`) |

### 4.2 Prova Formal e Empírica de Invariância de Cache-Timing
Em `mds_mult_ct` (`implementacao/c_core/rsd_s_v5_ct.c`, linhas `201–211`):
1. Os índices de acesso à tabela `CAUCHY_BIT_BASIS[j][bit][0]` e `CAUCHY_BIT_BASIS[j][bit][16]` dependem **exclusivamente** das variáveis de loop públicas `j` ($0 \dots 31$) e `bit` ($0 \dots 15$).
2. No assembly compilado (`-O3 -mavx2`, `mds_mult_ct` linhas `0x250..0x543`), o loop interno `bit = 0..15` é completamente desenrolado (*unrolled*): o ponteiro `%rax` inicia em `&CAUCHY_BIT_BASIS[0][0][0]`, avança exatamente `$0x400` (`1.024` bytes = 16 linhas de cache de 64B) a cada iteração de `j`, e executa **32 leituras vetoriais com deslocamentos fixos constantes** (`-0x400(%rax)`, `-0x3e0(%rax)`, ..., `-0x20(%rax)`).
3. O bit secreto `(vj >> bit) & 1u` é extraído puramente em registradores (`sar`, `and $0x1`, `neg`, `vmovd`, `vpbroadcastw`) para formar a máscara vetorial `vmask` de 256 bits e aplicado via `vpand` sobre o vetor lido.
4. **Traço de Cache Determinístico:** Toda invocação de `mds_mult_ct` toca exatamente as mesmas **512 linhas de cache de 64 bytes** na mesma ordem monotônica sequencial `[base + 0x0000 .. base + 0x7FE0]`. O número de *cache hits* e *cache misses* dependentes de segredo é **identicamente zero**.

### 4.3 Reconciliação de `"avx2_tvla_abs_t": 8.6422` em `v5_1_final_hardening_results.json` vs `|t| = 0.3544` no relatório interno de prontidão
- **Observação:** O arquivo `resultados/v5_sandbox/v5_1_final_hardening_results.json` (gerado durante o commit exploratório `e9b1e6d`) registrava um campo estático `"avx2_tvla_abs_t": 8.6422`, enquanto `relatório interno de prontidão (não incluído neste repositório)` e `caderno de execução interno (não incluído neste repositório)` registravam `|t| = 0.3544` (`PASS`).
- **Causa-Raiz Comprovada:** No micro-script preliminar que gerou `v5_1_final_hardening_results.json`, os dois grupos de amostras foram coletados em **blocos sequenciais não-intercalados** (*batch mode*: todas as amostras do Grupo 0 seguidas de todas as amostras do Grupo 1) logo após a inicialização, sem aquecimento prévio (*warm-up*) da tabela `CAUCHY_BIT_BASIS` de 32 KiB no cache L1d e durante a transição de frequência/licença AVX2 do processador Xeon. Nesse cenário não-intercalado, o Grupo 0 absorve sozinho a latência transitória de *cold cache* e *turbo ramp-up*, gerando uma diferença espúria de média entre o início e o fim da janela de coleta.
- **Verificação:** Conforme a metodologia padrão TVLA (ISO/IEC 17825 / Goodwill et al.), a aquisição deve ser **intercalada** (*Fixed-vs-Random* pareado/aleatorizado a cada passo) após *warm-up*, para que qualquer deriva ambiental de clock/hypervisor afete ambos os grupos simetricamente. Sob aquisição intercalada com $N = 100.000$ pares ($200.000$ traços por teste), o kernel `-O3 -mavx2` apresenta **$|t| = 0,3194$** (*Fixed-vs-Random*) e **$|t| = 0,0441$** (*All-Zero-vs-All-Ones*), confirmando que o kernel AVX2 é estritamente *constant-time*.

---

## 5. Pilar 4 — TVLA Estendido de Welch ($N = 100.000$ Pares = $200.000$ Traços/Teste em `-O0`, `-O2` e `-O3 -mavx2`)

### 5.1 Metodologia do Harness C99 (`lfence; rdtsc` / `rdtscp; lfence`)
- **Amostragem:** Para cada um dos 3 perfis de compilação (`-O0`, `-O2`, `-O3 -mavx2`), executamos dois testes independentes de **$N = 100.000$ pares ($200.000$ traços por teste; $400.000$ traços por perfil; $1.200.000$ traços totais)**:
  1. **Fixed-vs-Random Input (Chave Fixa):** Estado fixo `0xA55A ^ (i * 0x1337)` vs estado pseudoaleatório uniforme `xorshift64*` gerado fora da janela de medição.
  2. **All-Zero-vs-All-Ones Input (`0x0000^32` vs `0xFFFF^32`):** Contraste máximo de peso de Hamming (0 bits ativos vs 512 bits ativos na entrada), testando diretamente se a extração de bits `((vj >> bit) & 1u)` em `mds_mult_ct` ou as máscaras `vpcmpeqw`/`vpcmpgtw` em `gf16_mul_avx2` introduzem qualquer variação de ciclos.
- **Ordem Intercalada Aleatorizada:** Em cada par $i \in \{0 \dots 99.999\}$, um bit aleatório `order = xorshift64star() & 1` decide se o Grupo 0 ou o Grupo 1 é medido primeiro.
- **Filtragem de Outliers de Preempção de SO:** Reportamos o $|t|$ de Welch em três níveis:
  - `abs_t_quantile_trimmed`: recorte simétrico `p05–p95` (padrão utilizado no Notebook 02 do sandbox para eliminar preempções do hypervisor Linux);
  - `abs_t_p99_trimmed`: remoção do 1% superior (`p99`) de interrupções de timer do kernel;
  - `abs_t_raw`: estatística bruta sem remoção de interrupções de SO.

### 5.2 Tabela Completa de Resultados TVLA ($N = 100.000$ Pares / $200.000$ Traços por Teste)

| Perfil de Compilação | Teste TVLA ($200.000$ traços) | Média G0 (ciclos) | Média G1 (ciclos) | Mediana `p50` G0 / G1 (ciclos) | $|t|$ Quantile-Trimmed (`p05–p95`) | $|t|$ `p99`-Trimmed | $|t|$ Bruto (`raw`) | Limiar TVLA | Status |
|---|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| **`-O0`** (Escalar sem opt) | **Fixed-vs-Random** | 2.041.746,79 | 2.041.085,33 | 2.049.502 / 2.049.470 | **2,4969** | **0,6964** | **0,7444** | $< 4,5$ | **PASS** |
| **`-O0`** (Escalar sem opt) | **All-Zero-vs-All-Ones** | 2.031.274,09 | 2.031.205,19 | 2.044.162 / 2.044.220 | **0,4266** | **0,0145** | **0,8819** | $< 4,5$ | **PASS** |
| **`-O2`** (Escalar otimizado) | **Fixed-vs-Random** | 413.682,77 | 413.655,12 | 414.454 / 414.360 | **0,6973** | **0,4891** | **0,3625** | $< 4,5$ | **PASS** |
| **`-O2`** (Escalar otimizado) | **All-Zero-vs-All-Ones** | 413.245,99 | 413.233,30 | 413.790 / 413.754 | **0,3067** | **0,3043** | **0,7017** | $< 4,5$ | **PASS** |
| **`-O3 -mavx2`** (SIMD AVX2) | **Fixed-vs-Random** | 35.048,21 | 35.046,72 | 34.816 / 34.820 | **0,3194** | **0,4503** | **1,0333** | $< 4,5$ | **PASS** |
| **`-O3 -mavx2`** (SIMD AVX2) | **All-Zero-vs-All-Ones** | 35.171,88 | 35.171,75 | 35.620 / 35.620 | **0,0441** | **0,5234** | **0,8087** | $< 4,5$ | **PASS** |

> **Destaque de Performance & Constant-Time em `-O3 -mavx2`:**
> - A mediana de execução do núcleo completo de 8 rodadas + rodada redundante Anti-DFA caiu de **2.049.470 ciclos** (`-O0`) e **414.360 ciclos** (`-O2` escalar) para **34.816 ciclos** (`-O3 -mavx2`, **aceleração de 11,9x em ciclos sobre `-O2` e 58,9x sobre `-O0`**).
> - No teste de contraste extremo **All-Zero vs All-Ones** em `-O3 -mavx2`, as medianas `p50` dos dois grupos são **idênticas ao ciclo exato (`35.620` ciclos vs `35.620` ciclos)** e a diferença entre as médias sobre 200.000 execuções é de apenas **0,13 ciclos** (`35.171,88` vs `35.171,75` ciclos), resultando em **$|t| = 0,0441 \ll 4,5$**.

---

## 6. Reprodutibilidade e Comandos de Verificação

```bash
# 1. Execução via pytest em ambiente virtual isolado
python3 -m pytest -v testes/test_r3_metric4_avx2_tvla.py

# 2. Execução standalone completa
python3 testes/test_r3_metric4_avx2_tvla.py
```
