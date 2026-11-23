# Relatório Técnico — Lote C (Round 2): TVLA Estendido ($N \ge 100.000$) & Benchmarks de Throughput vs AES-256-GCM / ChaCha20-Poly1305

> **Nota de versão.** Este relatório é anterior à v5.2 e descreve medições da linha v5.1. Resultados de segurança e desempenho **não foram refeitos na v5.2** salvo onde o texto disser o contrário. Vetores de referência da v5.2: `testes/vetores_v52.json`.


**Data:** 2026-11-22  
**Ambiente:** Linux x86_64 (`Intel(R) Xeon(R) Platinum 8481C`, flags `avx2`, `avx512f`, `avx512bw`, `gfni`, `vpclmulqdq`, `aes`, `sha_ni`), GCC 12.2.0, OpenSSL 3.0.22 (`libcrypto`), Python 3.11.2 (ambiente virtual com `cryptography 50.0.2`, `numpy 2.4.6`, `scipy 1.17.1`).  
**Alvos avaliados:** `implementacao/c_core/rsd_s_v5_ct.c` (núcleo C99) e `implementacao/rsd_s_v5_hardened.py` (referência Python).  
**Harness reproduzível:** `testes/lote_c_tvla_and_bench.c` + `testes/run_lote_c_benchmarks.py`  
**Métricas brutas (JSON):** `resultados/v5_sandbox/lote_c_sidechannel_bench_results.json`

---

## 1. Sumário Executivo e Vereditos (CONCLUÍDA / REFUTADA)

| Meta / Alegação Avaliada | Veredito | Evidência Principal |
|---|---|---|
| **Resistência Constant-Time do núcleo C99 (`rsd_s_v5_ct.c`) sob TVLA estendido ($N = 100.000$ amostras/teste) em `-O0`, `-O2` e `-O3`** | **CONCLUÍDA** | Todos os 24 testes Welch's $t$-test (TVLA-A entrada fixa vs aleatória; TVLA-B chave+entrada fixa vs aleatória; ciclos `RDTSC` e `CLOCK_MONOTONIC_RAW`; bruto e `p99`-trimmed) ficaram muito abaixo do limiar $|t| < 4.5$. Máximo global observado: **$|t| = 1.8443$** (`-O3`, TVLA-B `p99_trimmed`). Zero saltos condicionais ou `cmov` dependentes de segredo no assembly gerado. |
| **Competitividade de throughput do `RSD-S v5` frente a `AES-256-GCM` e `ChaCha20-Poly1305`** | **REFUTADA** | O núcleo C99 (`rsd_s_v5_ct.c`) atinge apenas **~0.20 MiB/s** (`~10.200–11.230 ciclos/byte`, `~302–315 µs` por bloco de 64B) em `-O2`/`-O3`/`-O3 -march=native`. Em payloads de 1 MB, é **15.513x–22.894x mais lento** que `OpenSSL AES-256-GCM` (`3.110–4.593 MiB/s`, `0.46–0.67 ciclos/byte`) e **13.184x–16.310x mais lento** que `OpenSSL ChaCha20-Poly1305` (`2.643–3.280 MiB/s`, `0.64–0.79 ciclos/byte`). Em Python puro (`rsd_s_v5_hardened.py`), atinge **0.00179 MiB/s** (`34.1 ms` por bloco de 64B). |
| **Viabilidade de aceleração SIMD para `rsd_s_v5_ct.c`** | **CONCLUÍDA (com ressalva arquitetural)** | Vetorização SIMD constant-time via `VPSHUFB` (AVX2/AVX-512BW), `VPCLMULQDQ` ou *bitslicing* multi-bloco é viável e estimada em **15x–50x de ganho** (`~3–10 MiB/s`), mantendo 0 bytes de LUT em memória. Contudo, mesmo após SIMD, permanecerá ~300x–500x abaixo de AES-GCM/ChaCha20 devido às 14.976 multiplicações em $GF(2^{16})$ por bloco de 64B. |

---

## 2. TVLA Estendido ($N = 100.000$ amostras por teste) e Inspeção de Assembly

### 2.1 Metodologia
- Para cada nível de otimização (`-O0`, `-O2`, `-O3`), o arquivo `implementacao/c_core/rsd_s_v5_ct.c` foi compilado isoladamente e linkado ao harness `testes/lote_c_tvla_and_bench.c`.
- **Intercalação aleatorizada:** As 50.000 amostras *Fixed* e 50.000 amostras *Random* ($N = 100.000$ por teste; $200.000$ por nível de otimização; $600.000$ amostras totais) foram executadas em ordem aleatorizada por `xorshift64*` fora da janela de medição, após *warm-up* de 2.000 chamadas (inicializando `CAUCHY_MDS`).
- **Sensores de tempo:** `lfence; rdtsc` / `rdtscp; lfence` (ciclos de CPU) e `clock_gettime(CLOCK_MONOTONIC_RAW)` (nanossegundos).
- **Estatística:** Teste $t$ de Welch bicaudal com limiar padrão TVLA $|t| < 4.5$. Reportamos tanto $|t|$ bruto (todas as 100.000 amostras) quanto $|t|$ *p99-trimmed* (removendo o 1% superior de *outliers* causados por interrupções de SO/hypervisor).

### 2.2 Resultados TVLA (`-O0`, `-O2`, `-O3`)

| Otimização | Teste TVLA ($N=100.000$) | Ciclos `p50` (Fixed / Random) | $|t|$ Ciclos (Bruto) | $|t|$ Ciclos (`p99`-trimmed) | $|t|$ ns (Bruto) | $|t|$ ns (`p99`-trimmed) | Status ($< 4.5$) |
|---|---|---|---|---|---|---|---|
| **`-O0`** | **TVLA-A** (Entrada Fixa vs Aleatória) | 2.477.166 / 2.476.398 | 0.3267 | 0.5246 | 0.3548 | 0.5545 | **PASS** |
| **`-O0`** | **TVLA-B** (Chave+Entrada Fixa vs Aleatória) | 2.470.500 / 2.471.484 | 1.0273 | 1.3912 | 1.0405 | 1.3980 | **PASS** |
| **`-O2`** | **TVLA-A** (Entrada Fixa vs Aleatória) | 465.532 / 465.544 | 0.1714 | 0.1855 | 0.1577 | 0.1700 | **PASS** |
| **`-O2`** | **TVLA-B** (Chave+Entrada Fixa vs Aleatória) | 465.646 / 465.648 | 0.8380 | 1.1522 | 0.8106 | 1.1204 | **PASS** |
| **`-O3`** | **TVLA-A** (Entrada Fixa vs Aleatória) | 675.900 / 675.944 | 0.1786 | 0.0982 | 0.1701 | 0.1076 | **PASS** |
| **`-O3`** | **TVLA-B** (Chave+Entrada Fixa vs Aleatória) | 674.958 / 674.914 | 1.5868 | 1.8436 | 1.5874 | 1.8443 | **PASS** |

### 2.3 Inspeção Estática de Assembly (`gcc -S`)
- **`-O0`**: 824 linhas, **0** saltos condicionais dependentes de dados, **0** `cmov`.
- **`-O2`**: 1.103 linhas, **0** saltos condicionais dependentes de dados, **0** `cmov`. O GCC auto-vetorizou o laço fixo de 16 iterações de `gf16_mul_ct` em `mds_mult_ct` usando instruções SSE2 (`psrld`, `psubd`, `pand`, `pxor`, `pslld`).
- **`-O3` / `-O3 -march=native`**: 4.761 / 4.767 linhas, **0** saltos condicionais dependentes de dados, **1** `cmovne` localizado exclusivamente na função auxiliar `rsd_s_v5_verify_wipe_ct(buf, len)` (verificação do tamanho público `len`, linha 4644 de `rsd_O3.s`), sem relação com dados secretos.

---

## 3. Benchmarks Reais de Throughput vs AES-256-GCM & ChaCha20-Poly1305

> **Nota metodológica de transparência:** `AES-256-GCM` e `ChaCha20-Poly1305` são cifras AEAD completas (confidencialidade + tag de autenticação de 16 bytes), enquanto `rsd_s_v5_core_ct` é uma primitiva de difusão por blocos de 64 bytes (512 bits) com 8 rodadas e proteção Anti-DFA na rodada final (sem custo de KDF/HMAC por bloco no loop C99). Cada payload de tamanho $L$ bytes executa $\lceil L / 64 \rceil$ chamadas ao núcleo `rsd_s_v5_core_ct`.

### 3.1 C99 Core (`-O2`, `-O3`, `-O3 -march=native`) vs OpenSSL 3.0.22 (`libcrypto`)

| Payload | Primitiva | MiB/s (`-O2` / `-O3` / `-O3 -march=native`) | Ciclos/Byte (`-O3`) | Latência (`-O3`) | Razão de Latência (`RSD-S / Ref` em `-O3`) |
|---|---|---|---|---|---|
| **64 B** (1 bloco) | `RSD-S v5 C99` | 0.1955 / 0.2019 / 0.1938 | 10.391,33 | 302.294 µs | 1.00x |
| **64 B** | `OpenSSL AES-256-GCM` | 59.45 / 74.91 / 73.07 | 28.01 | 0.815 µs | **371.03x mais lento** |
| **64 B** | `OpenSSL ChaCha20-Poly1305` | 33.27 / 45.48 / 44.03 | 46.13 | 1.342 µs | **225.24x mais lento** |
| **1 KB** (16 blocos) | `RSD-S v5 C99` | 0.2023 / 0.2059 / 0.1952 | 10.190,10 | 4.743,031 µs | 1.00x |
| **1 KB** | `OpenSSL AES-256-GCM` | 482.51 / 954.02 / 917.65 | 2.20 | 1.024 µs | **4.633,54x mais lento** |
| **1 KB** | `OpenSSL ChaCha20-Poly1305` | 299.65 / 631.08 / 608.66 | 3.32 | 1.547 µs | **3.065,06x mais lento** |
| **64 KB** (1.024 blocos) | `RSD-S v5 C99` | 0.1868 / 0.2029 / 0.2014 | 10.338,87 | 307.985,907 µs | 1.00x |
| **64 KB** | `OpenSSL AES-256-GCM` | 2.579,28 / 4.366,60 / 4.446,68 | 0.48 | 14.313 µs | **21.517,63x mais lento** |
| **64 KB** | `OpenSSL ChaCha20-Poly1305` | 3.238,82 / 3.046,64 / 3.132,69 | 0.69 | 20.514 µs | **15.013,17x mais lento** |
| **1 MB** (16.384 blocos) | `RSD-S v5 C99` | 0.2005 / 0.2000 / 0.2011 | 10.492,69 | 5.001.082,718 µs (5.00 s) | 1.00x |
| **1 MB** | `OpenSSL AES-256-GCM` | 3.110,21 / 4.577,73 / 4.593,01 | 0.46 | 218.449 µs | **22.893,63x mais lento** |
| **1 MB** | `OpenSSL ChaCha20-Poly1305` | 2.643,22 / 3.256,61 / 3.280,09 | 0.64 | 307.067 µs | **16.286,60x mais lento** |

### 3.2 Python (`rsd_s_v5_hardened.py`) vs `cryptography` (`AESGCM` / `ChaCha20Poly1305`)

| Payload | `Python RSD-S v5` | `cryptography AES-256-GCM` | `cryptography ChaCha20-Poly1305` |
|---|---|---|---|
| **64 B** | 0.00179 MiB/s (`34.089 ms`) [medido] | 107.90 MiB/s (`0.566 µs`) | 46.09 MiB/s (`1.324 µs`) |
| **1 KB** | 0.001795 MiB/s (`544.014 ms`) [medido] | 1.695,91 MiB/s (`0.576 µs`) | 642.65 MiB/s (`1.520 µs`) |
| **64 KB** | 0.001795 MiB/s (`~34.82 s`) [extrapolado] | 9.710,70 MiB/s (`6.436 µs`) | 3.020,53 MiB/s (`20.692 µs`) |
| **1 MB** | 0.001795 MiB/s (`~557.07 s`) [extrapolado] | 7.195,15 MiB/s (`138.982 µs`) | 2.527,35 MiB/s (`395.672 µs`) |

---

## 4. Análise de Viabilidade SIMD para `rsd_s_v5_ct.c`

1. **Gargalo identificado:** Cada chamada de 64 bytes a `rsd_s_v5_core_ct` executa 9 rodadas (7 normais + 2 redundantes Anti-DFA). Cada rodada realiza $32 \times 20 = 640$ multiplicações em `sbox_v5_ct` e $32 \times 32 = 1.024$ multiplicações em `mds_mult_ct` = **14.976 chamadas a `gf16_mul_ct`**, cada uma com um laço de 16 bits ($\approx 240.000$ iterações de deslocamento/máscara por bloco).
2. **Estratégias SIMD constant-time (zero LUT em memória):**
   - **Tabelas em registrador via `VPSHUFB` (AVX2 / AVX-512BW):** Decompor a multiplicação em $GF(2^{16})$ em nibbles de 4 bits usando `_mm256_shuffle_epi8` / `_mm512_shuffle_epi8`. Como `vpshufb` opera exclusivamente em registradores vetoriais em latência fixa de 1 ciclo, preserva 100% a propriedade *cache-timing-free* e elimina o laço de 16 bits. Todo o estado de 32 palavras `uint16_t` cabe em **1 registrador AVX-512 (`__m512i`)** ou **2 registradores AVX2 (`__m256i`)**.
   - **`VPCLMULQDQ` (disponível nesta CPU):** Multiplicação *carry-less* vetorial seguida de redução modular constante por `0x1100B`.
   - ***Bitslicing* multi-bloco (16x AVX2 / 32x AVX-512):** Processamento paralelo de 16 ou 32 blocos independentes em modo CTR/PRF.
3. **Impacto esperado e limite estrutural:** Estima-se aceleração de **15x a 50x** (`~3–10 MiB/s`, `~200–350 ciclos/byte`). Mesmo assim, devido à densidade algébrica da matriz MDS Cauchy $32 \times 32$ sobre $GF(2^{16})$ e à duplicação Anti-DFA, o `RSD-S v5` **não é adequado para criptografia em massa (*bulk encryption*)**, devendo ser posicionado exclusivamente como **PRF de baixa taxa / derivação de chave / difusão com separação de domínio**, em conformidade com `especificacao/RESTRICOES_DE_PROJETO.md`.
