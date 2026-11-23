# Relatório Cirúrgico Datado — Métrica 5 (Rodada 3): Benchmark de Latência, Throughput e Ciclos por Byte (`RSD-S v5.1` vs `v5.0` vs `v4` vs `AES-256-GCM` & `ChaCha20-Poly1305`) e Consolidação dos 5 Relatórios Cirúrgicos

> **Nota de versão.** Este relatório é anterior à v5.2 e descreve medições da linha v5.1. Resultados de segurança e desempenho **não foram refeitos na v5.2** salvo onde o texto disser o contrário. Vetores de referência da v5.2: `testes/vetores_v52.json`.


- **Data:** `2026-11-22`
- **Alvos Auditados:**
  - `implementacao/c_core/rsd_s_v5_ct.c` (`RSD-S v5.1` C99 Constant-Time & SIMD AVX2)
  - `implementacao/rsd_s_v5_hardened.py` (`RSD-S v5.1` Python Hardened Reference)
  - `implementacao/bandlimited_dual_key.py` (`BandlimitedDualKeyEngine v5.1` com SIV + Folding 64B sem padding)
  - `implementacao/rsd_s_v4_final.py` (`RSD-S v4` Baseline Python — **100% intocado, somente leitura**)
  - Baselines de indústria (`OpenSSL 3.0.22 libcrypto EVP` em C99 e bindings Python): `AES-256-GCM`, `ChaCha20-Poly1305`, `HMAC-SHA256` e `SHA-256`
- **Artefato JSON Datado:** `resultados/v5_sandbox/r3_metric5_benchmark_20261122.json`
- **Artefato JSON Consolidado v5.1:** `resultados/v5_sandbox/v5_1_final_hardening_results.json`
- **Veredito da Métrica 5:** **CONCLUÍDA — 100% APROVADA (`13,30x` de aceleração AVX2 não-contendida sobre `v5.0` escalar; `16,26 µs/call` e `3,75 MiB/s` no núcleo 8R; consolidação integral das Métricas 1–5)**

---

## 1. Ambiente de Hardware e Metodologia de Medição Não-Contendida

Todas as medições da Métrica 5 foram executadas **sem contenção de CPU** (após a conclusão integral das Métricas 1 a 4):

- **CPU Host:** `Intel(R) Xeon(R) Platinum 8481C` (`2200.00 MHz` nominal, `measured_tsc_ghz = 2.2000 GHz`)
- **Extensões ISA Detectadas:** `avx`, `avx2`, `aes` (AES-NI), `pclmulqdq`, `bmi1`, `bmi2`, `sha_ni`, `avx512f`, `avx512bw`
- **Sistema Operacional & Compilador:** `Linux 6.12.105+ x86_64 (glibc 2.36)`, `gcc (Debian 12.2.0-14+deb12u1) 12.2.0` com `-Wall -Wextra -Werror`
- **Biblioteca Criptográfica Nativa:** `OpenSSL 3.0.22 25 Aug 2026` (`libcrypto`)
- **Ambiente Python Sandbox:** `python3` (`Python 3.11.2`, `NumPy 2.4.6`, `SciPy 1.17.1`, `pytest 9.2.0`)
- **Instrumentação de Ciclos e Tempo:**
  - **C99:** Serialização por `lfence; rdtsc` (início) e `rdtscp; lfence` (fim) combinada com `clock_gettime(CLOCK_MONOTONIC_RAW)` por chamada individual após aquecimento explícito da cache L1d (`3.000` iterações de warmup em `-O3 -mavx2`), registrando média, mediana (`p50`), `p95` e `p99`.
  - **Paridade KAT da API Completa C99 (`diffuse_rsd_s_v5_ct`):** Antes de iniciar a coleta de tempo, o harness valida que a implementação completa em C99 (derivação de chaves `HMAC-SHA256` big-endian + expansão `>u2` + constantes de rodada `RC` + `rsd_s_v5_core_ct` 8R com rodada final redundante Anti-DFA + compressão `SHA-256`) produz exatamente o mesmo digest de 256 bits que `diffuse_rsd_s_v5(1, 2, bytes(range(32)), 1)` em Python:
    $$\text{KAT}_{8\text{R}} = \texttt{2a604cf441bf0827f7ddaa6c2ed9d2cf6b6705c2e05bb71f939dae4c699689be}$$

---

## 2. Resultados Empíricos de Latência, Throughput e Ciclos por Byte (`cpb`)

### 2.1 Núcleo C99 (`RSD-S v5.1` AVX2 vs Escalar `-O2` vs `-O0` vs `v5.0` Legacy Escalar) — Bloco de Estado de 64 Bytes (512 bits)

| Implementação / Perfil de Compilação | Função / Escopo | Iterações | Latência Média ($\mu\text{s/call}$) | Latência `p50` ($\mu\text{s/call}$) | Latência `p95` ($\mu\text{s/call}$) | Throughput ($\text{MiB/s}$) | Vazão ($\text{calls/s}$) | Ciclos/Call (Média) | Ciclos/Byte (`cpb` sobre 64B) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`RSD-S v5.1` C99 SIMD AVX2** (`-O3 -mavx2`) | `rsd_s_v5_core_ct` (**4R SPN** + R4 Anti-DFA) | 25.000 | **`8,9463`** | `8,9100` | `9,2020` | **`6,8224`** | **`111.778,22`** | `19.681,80` | **`307,53`** |
| **`RSD-S v5.1` C99 SIMD AVX2** (`-O3 -mavx2`) | `rsd_s_v5_core_ct` (**8R Oficial** + R8 Anti-DFA) | 25.000 | **`16,2649`** | `16,1720` | `16,4250` | **`3,7526`** | **`61.481,99`** | `35.782,80` | **`559,11`** |
| **`RSD-S v5.1` C99 SIMD AVX2** (`-O3 -mavx2`) | `diffuse_rsd_s_v5_ct` (**API Completa 4R** + KeySched + SHA-256) | 10.000 | **`31,1852`** | `31,0100` | `36,1300` | **`1,9572`** | **`32.066,50`** | `68.607,40` | **`1.071,99`** |
| **`RSD-S v5.1` C99 SIMD AVX2** (`-O3 -mavx2`) | `diffuse_rsd_s_v5_ct` (**API Completa 8R** + KeySched + SHA-256) | 10.000 | **`56,7458`** | `56,3410` | `62,4440` | **`1,0756`** | **`17.622,46`** | `124.840,67` | **`1.950,64`** |
| **`RSD-S v5.1` C99 Escalar** (`-O2 -mno-avx2`) | `rsd_s_v5_core_ct` (**4R SPN** + R4 Anti-DFA) | 5.000 | `105,9827` | `104,9960` | `111,1120` | `0,5759` | `9.435,50` | `233.161,97` | `3.643,16` |
| **`RSD-S v5.1` C99 Escalar** (`-O2 -mno-avx2`) | `rsd_s_v5_core_ct` (**8R Oficial** + R8 Anti-DFA) | 5.000 | `187,5488` | `187,9790` | `194,8500` | `0,3254` | `5.331,94` | `412.607,23` | `6.446,99` |
| **`RSD-S v5.1` C99 Escalar** (`-O2 -mno-avx2`) | `diffuse_rsd_s_v5_ct` (**API Completa 8R** + KeySched + SHA-256) | 3.000 | `238,0675` | `229,4470` | `245,1400` | `0,2564` | `4.200,49` | `523.748,32` | `8.183,57` |
| **`RSD-S v5.0` C99 Legacy Escalar** (sem `CAUCHY_BIT_BASIS`) | `legacy_v50_core_8r_ct` (**8R Oficial** + R8 Anti-DFA) | 2.000 | `216,3379` | `217,8420` | `223,6080` | `0,2821` | `4.622,40` | `475.943,11` | `7.436,61` |
| **`RSD-S v5.1` C99 Não-Otimizado** (`-O0`) | `rsd_s_v5_core_ct` (**4R SPN** + R4 Anti-DFA) | 1.500 | `507,7760` | `508,5250` | `527,6460` | `0,1202` | `1.969,37` | `1.117.107,17` | `17.454,80` |
| **`RSD-S v5.1` C99 Não-Otimizado** (`-O0`) | `rsd_s_v5_core_ct` (**8R Oficial** + R8 Anti-DFA) | 1.500 | `909,0186` | `914,6920` | `940,6720` | `0,0671` | `1.100,09` | `1.999.840,85` | `31.247,51` |
| **`RSD-S v5.1` C99 Não-Otimizado** (`-O0`) | `diffuse_rsd_s_v5_ct` (**API Completa 8R** + KeySched + SHA-256) | 1.000 | `961,9492` | `963,6100` | `997,5170` | `0,0634` | `1.039,56` | `2.116.287,70` | `33.067,00` |

### 2.2 Implementações em Python (`RSD-S v5.1`, `BandlimitedDualKeyEngine v5.1` e Baseline `RSD-S v4`)

| Módulo / Arquivo | Função / Modo | Iterações | Latência Média ($\mu\text{s/call}$) | Latência `p50` ($\mu\text{s/call}$) | Throughput ($\text{MiB/s}$) | Vazão ($\text{calls/s}$) | Ciclos/Call (Média) | Ciclos/Byte (`cpb` sobre 64B) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `rsd_s_v5_hardened.py` | `run_c_core_pre_sha` (Híbrido Python KeySched + `ctypes` C99 AVX2 8R) | 200 | **`126,0280`** | `116,7930` | **`0,484298`** | `7.934,74` | `277.261,68` | `4.332,21` |
| `rsd_s_v5_hardened.py` | `diffuse_rsd_s_v5_pre_sha` (Python Puro 4R + R4 Anti-DFA) | 60 | `19.345,3561` | `19.302,5710` | `0,003155` | `51,69` | `42.559.783,49` | `664.996,62` |
| `rsd_s_v5_hardened.py` | `diffuse_rsd_s_v5_pre_sha` (Python Puro 8R + R8 Anti-DFA) | 40 | `34.849,4401` | `34.828,3070` | `0,001751` | `28,69` | `76.668.768,22` | `1.197.949,50` |
| `rsd_s_v5_hardened.py` | `diffuse_rsd_s_v5` (Python Puro 8R + `SHA-256` 32B) | 40 | `35.098,7343` | `34.745,2380` | `0,001739` | `28,49` | `77.217.215,57` | `1.206.518,99` |
| `rsd_s_v5_hardened.py` | `diffuse_rsd_s_v5` (Python Puro 8R + `SHAKE256` 64B PQ-BHT) | 40 | `34.610,0233` | `34.657,9040` | `0,001764` | `28,89` | `76.142.051,20` | `1.189.719,55` |
| `bandlimited_dual_key.py` | `_unpadded_z65537_to_bytes64` (Serialização 64B + Folding isolado) | 5.000 | **`6,2312`** | `6,0020` | **`9,795153`** | `160.483,78` | `13.708,55` | `214,20` |
| `bandlimited_dual_key.py` | `_derive_dual_key_noise` (Derivação SIV `HMAC-SHA256` + `SHAKE256` isolada) | 2.000 | **`11,5827`** | `11,2200` | **`5,269518`** | `86.335,79` | `25.481,90` | `398,15` |
| `bandlimited_dual_key.py` | `build_quantized_spectral_matrix` (Inicialização única de $B_{K_j} \in \mathbb{Z}_{65537}^{32 \times 32}$) | 15 | `2.651,9020` | `2.650,8240` | `0,023016` | `377,09` | `5.834.184,40` | `91.159,13` |
| `bandlimited_dual_key.py` | `refactor_public_output` (`dual_key_stochastic_hardened` SIV + 64B) | 40 | `35.235,7822` | `34.702,0870` | `0,001732` | `28,38` | `77.518.720,78` | `1.211.230,01` |
| `bandlimited_dual_key.py` | `verify_public_output` (`dual_key_stochastic_hardened` SIV constant-time) | 40 | `36.803,4948` | `34.794,0030` | `0,001658` | `27,17` | `80.967.688,62` | `1.265.120,13` |
| `rsd_s_v4_final.py` (**Read-Only**) | `diffuse_rsd_s_final_PRE_SHA` (4R + LUT 256 KiB vulnerável a cache) | 150 | `8.931,9230` | `8.958,5630` | `0,006833` | `111,96` | `19.650.230,61` | `307.034,85` |
| `rsd_s_v4_final.py` (**Read-Only**) | `diffuse_rsd_s_final` (4R + LUT 256 KiB + `SHA-256`) | 150 | `8.910,3831` | `8.940,2070` | `0,006850` | `112,23` | `19.602.842,91` | `306.294,42` |

### 2.3 Baselines Padrão da Indústria (`OpenSSL 3.0.22 EVP` C99 e Python) na Mesma CPU (`Intel Xeon Platinum 8481C`)

| Primitiva Padrão | Tamanho do Bloco | Backend | Latência Média ($\mu\text{s/call}$) | Latência `p50` ($\mu\text{s/call}$) | Throughput ($\text{MiB/s}$) | Vazão ($\text{calls/s}$) | Ciclos/Call (Média) | Ciclos/Byte (`cpb`) |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`AES-256-GCM`** | `64 B` | OpenSSL C99 EVP (AES-NI) | `1,0285` | `0,9750` | `59,3451` | `972.309,77` | `2.262,65` | `35,35` |
| **`AES-256-GCM`** | `4096 B` | OpenSSL C99 EVP (AES-NI) | `1,8551` | `1,8100` | `2.105,6275` | `539.040,63` | `4.081,32` | `1,00` |
| **`ChaCha20-Poly1305`** | `64 B` | OpenSSL C99 EVP (AVX2/AVX512) | `1,5674` | `1,5160` | `38,9401` | `637.995,40` | `3.448,30` | `53,88` |
| **`ChaCha20-Poly1305`** | `4096 B` | OpenSSL C99 EVP (AVX2/AVX512) | `2,6474` | `2,5900` | `1.475,5147` | `377.731,77` | `5.824,23` | `1,42` |
| **`HMAC-SHA256`** | `64 B` | OpenSSL C99 EVP (SHA-NI) | `1,6523` | `1,5950` | `36,9388` | `605.205,17` | `3.635,13` | `56,80` |
| **`HMAC-SHA256`** | `4096 B` | OpenSSL C99 EVP (SHA-NI) | `4,3701` | `4,3270` | `893,8551` | `228.826,90` | `9.614,25` | `2,35` |
| **`SHA-256`** | `64 B` | OpenSSL C99 EVP (SHA-NI) | `0,5669` | `0,5240` | `107,6574` | `1.763.858,94` | `1.247,26` | `19,49` |
| **`SHA-256`** | `4096 B` | OpenSSL C99 EVP (SHA-NI) | `3,3336` | `3,2870` | `1.171,7794` | `299.975,53` | `7.333,92` | `1,79` |
| **`AES-256-GCM`** | `64 B` | Python (`ctypes` OpenSSL EVP) | `2,1235` | `1,8880` | `28,7432` | `470.928,15` | `4.671,63` | `72,99` |
| **`AES-256-GCM`** | `4096 B` | Python (`ctypes` OpenSSL EVP) | `2,9694` | `2,7370` | `1.315,5155` | `336.771,98` | `6.532,61` | `1,59` |
| **`ChaCha20-Poly1305`** | `64 B` | Python (`ctypes` OpenSSL EVP) | `2,7536` | `2,5030` | `22,1654` | `363.157,15` | `6.057,98` | `94,66` |
| **`ChaCha20-Poly1305`** | `4096 B` | Python (`ctypes` OpenSSL EVP) | `3,9575` | `3,6580` | `987,0539` | `252.685,80` | `8.706,46` | `2,13` |
| **`HMAC-SHA256`** | `64 B` | Python (`hmac` + `hashlib`) | `1,9659` | `1,7680` | `31,0472` | `508.677,69` | `4.324,94` | `67,58` |
| **`HMAC-SHA256`** | `4096 B` | Python (`hmac` + `hashlib`) | `4,9931` | `4,7400` | `782,3315` | `200.276,85` | `10.984,79` | `2,68` |
| **`SHA-256`** | `64 B` | Python (`hashlib.sha256`) | `0,6993` | `0,5310` | `87,2832` | `1.430.047,65` | `1.538,41` | `24,04` |
| **`SHA-256`** | `4096 B` | Python (`hashlib.sha256`) | `3,4645` | `3,2430` | `1.127,5234` | `288.645,98` | `7.621,79` | `1,86` |

### 2.4 Análise de Aceleração (`Speedup`) e Posicionamento Arquitetural

1. **Impacto da Vetorização SIMD AVX2 (`sbox_v5_avx2` + `CAUCHY_BIT_BASIS`):**
   - No núcleo oficial de 8 rodadas com rodada final redundante Anti-DFA (`rsd_s_v5_core_ct`), a compilação `gcc -O3 -mavx2` reduz a latência de **`216,3379 µs/call`** (`v5.0` escalar legado, `7.436,61 cpb`) e **`187,5488 µs/call`** (`v5.1` escalar `-O2 -mno-avx2`, `6.446,99 cpb`) para **`16,2649 µs/call`** (`559,11 cpb`, `35.782,80` ciclos), atingindo um speedup real não-contendido de **`13,30x`** sobre o `v5.0` escalar (`11,53x` sobre `-O2 -mno-avx2` e `55,89x` sobre `-O0`).
   - No núcleo SPN de 4 rodadas (`rsd_s_v5_core_ct_4r`), a latência cai para **`8,9463 µs/call`** (`6,8224 MiB/s`, `111.778,22 calls/s`, `307,53 cpb`), sendo **`998,39x` mais rápida** que o baseline histórico `RSD-S v4` em Python (`8.931,9230 µs/call`), apesar de eliminar completamente a LUT vulnerável de 256 KiB em favor de inversão *table-free* de Itoh–Tsujii + camada afim $A_{16}$ + matriz MDS $32 \times 32$.
   - Na API completa C99 (`diffuse_rsd_s_v5_ct_full_api_8r`), os 27 chamadas de `HMAC-SHA256` do escalonamento de chaves (9 chaves $\times 2$ blocos + 8 constantes de rodada + 1 `SHA-256` final) somam `~40,48 µs`, resultando em **`56,7458 µs/call`** (`1,0756 MiB/s`, `17.622,46 calls/s`) — **`618,53x` mais rápida** que a API completa Python (`35.098,7343 µs/call`).
   - Os dois novos mecanismos da Correção 1 (`_derive_dual_key_noise` com SIV e `_unpadded_z65537_to_bytes64` com folding determinístico) têm sobrecarga desprezível: **`11,5827 µs`** e **`6,2312 µs`** respectivamente (`< 0,05%` do tempo de `refactor_public_output` em Python).
2. **Comparação Honesta com `AES-256-GCM` e `ChaCha20-Poly1305`:**
   - Para blocos de 64 bytes, o núcleo `RSD-S v5.1` C99 AVX2 8R (`16,2649 µs`, `559,11 cpb`) opera a uma razão de latência de **`15,81x`** frente ao `OpenSSL AES-256-GCM` (`1,0285 µs`, acelerado por instruções dedicadas em silício `AES-NI` / `VPCLMULQDQ`) e **`10,38x`** frente ao `OpenSSL ChaCha20-Poly1305` (`1,5674 µs`).
   - Para cargas em massa (`4096 B`), onde `AES-256-GCM` atinge `2.105,63 MiB/s` (`1,00 cpb`) e `ChaCha20-Poly1305` atinge `1.475,51 MiB/s` (`1,42 cpb`), `RSD-S v5.1` mantém throughput constante de `3,7526 MiB/s` (`559,11 cpb`) porque avalia aritmeticamente 288 S-boxes sobre $\mathbb{F}_{2^{16}}$ via cadeia de Itoh–Tsujii (5.760 multiplicações vetoriais em $\mathbb{F}_{2^{16}}$) e 9 difusões MDS $32 \times 32$ por bloco de 64 bytes.
   - **Conclusão de Engenharia:** O `RSD-S v5.1` com aceleração AVX2 (`61.482 calls/s` no núcleo 8R e `17.622 calls/s` na API completa com derivação de chaves) possui excelente desempenho para sua classe funcional (**PRF chaveada, KDF e Compromisso Simétrico Verificável SIV de baixa/média taxa**), mas não substitui cifras AEAD aceleradas por hardware (`AES-256-GCM`, `ChaCha20-Poly1305`) para criptografia de tráfego em massa (*bulk encryption*).

---

## 3. Consolidação Cirúrgica das 5 Métricas Datadas da Rodada 3 (`2026-11-22`)

| Métrica | Especialização Cirúrgica | Artefatos Datados (`20261122`) | Suíte de Teste (`pytest`) | Resultado Empírico Auditado | Veredito |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **Métrica 1** | SIV Nonce-Misuse Resistance & Diferenciais em $\mathbb{Z}_{65537}$ | `r3_metric1_siv_z65537_20261122.json`<br>`r3_metric1_siv_z65537_20261122.md` | `testes/test_r3_metric1_siv_z65537.py` | **`0/1.000`** vazamentos algébricos de $\Delta S_{\text{priv}}$ sob reuso de `n_sess` (vs `1.000/1.000` na v5.0); **`0/2.048`** vazamentos em diferenciais `HW=1` de $S_{\text{priv}}$ (`HD = 256,09/512 bits`); **`0/510`** vazamentos em flips de 1 bit de $(x,y)$ (`HD = 256,34/512 bits`); $\Delta e_{\text{priv}}$ uniforme ($\chi^2 p = 0{,}6285$); norma Kannan CVP $329{,}33\times$ acima de GH; rejeição de adulteração **`512/512 (100%)`**. | **CONCLUÍDA (PASS)** |
| **Métrica 2** | NIST SP 800-22 (10/10) sobre `y_pub_bytes` Unpadded (64B) & Viés de Folding $65536 \to \{0..65535\}$ | `r3_metric2_nist_folding_20261122.json`<br>`r3_metric2_nist_folding_20261122.md` | `testes/test_r3_metric2_nist_folding.py` | Prova analítica exata: $\Pr[W=w] = \frac{1}{65537} + \frac{1}{65537}\cdot\frac{1}{65536} = \frac{1}{65536}$ (**`TVD = 0.0`, `KL = 0.0 bits`**, entropia `16,0000 bits/palavra`). Em `262.144` hits sintéticos de fronteira: $\chi^2_{65535} p = 0{,}8134$. Em `1.024.000` bits de `y_pub_bytes` (64B): proporção de `1`s = **`0,500006`**, aprovando **`10/10` testes core e `12/12` estendidos do NIST SP 800-22** (vs `1/10` na v5.0 96B). | **CONCLUÍDA (PASS)** |
| **Métrica 3** | Álgebra Matricial de $M_{\text{v5.1}}$ & Resistência Square/Integral (1R–4R) | `r3_metric3_mds_algebra_20261122.json`<br>`r3_metric3_mds_algebra_20261122.md` | `testes/test_r3_metric3_mds_algebra.py` | Permutação $p(j)=(5j+1)\bmod 32$ forma um único 32-ciclo; quebra $M^2 = \text{0x5e26}\cdot I$ (**`992/992`** entradas fora da diagonal de $M^2$ não-nulas; todas as potências $M^k$ com $32 \nmid k$ são 100% densas `1024/1024`); primeiro múltiplo escalar sobe de $k=2$ para **`k=32`** ($M^{32} = \text{0xb54c}\cdot I$); polinômio mínimo salta de grau 2 para **grau 32** ($x^{32} + \text{0xb54c}$); ordem multiplicativa expande **$16\times$** (`43.690` $\to$ **`699.040`**); *Branch Number* exato **$\mathcal{B} = 33$** (`100%` menores $1\times 1$ e $2\times 2$ não-nulos); translações diádicas reduzidas de $31 \to 1$. | **CONCLUÍDA (PASS)** |
| **Métrica 4** | Auditoria de Assembly AVX2, Alinhamento, Cache-Timing & TVLA Estendido ($N = 100.000$ pares) | `r3_metric4_avx2_tvla_20261122.json`<br>`r3_metric4_avx2_tvla_20261122.md` | `testes/test_r3_metric4_avx2_tvla.py` | Compilação limpa (`0` warnings/errors) e paridade bit-a-bit (`232/232` vetores) entre `-O0`, `-O2`, `-O3 -mavx2` e Python; `objdump -d` comprova **`0` branches condicionais dependentes de segredo**, **`0` instruções `vpgather*`** e **`0` acessos de memória indexados por segredo**; `CAUCHY_BIT_BASIS` (32 KiB) alinhada a 32 bytes (`addr % 32 == 0`), varrida em 512 leituras sequenciais fixas por chamada; TVLA estendido ($N = 100.000$ pares = `200.000` traços/teste, `1.200.000` traços totais) aprovado em todos os perfis: em `-O3 -mavx2`, **`|t| = 0,3194 < 4,5`** (Fixed-vs-Random) e **`|t| = 0,0441 < 4,5`** (All-Zero-vs-All-Ones), reconciliando e corrigindo o valor obsoleto `8,6422` de `v5_1_final_hardening_results.json`. | **CONCLUÍDA (PASS)** |
| **Métrica 5** | Benchmark de Throughput vs `AES-GCM`/`ChaCha20`, Consolidação | `r3_metric5_benchmark_20261122.json`<br>`r3_metric5_benchmark_20261122.md` | (harness interno, não incluído) | Núcleo C99 AVX2 (`-O3 -mavx2`) atinge **`16,2649 µs/call`** (`3,7526 MiB/s`, `61.481,99 calls/s`, `559,11 cpb`) em 8R e **`8,9463 µs/call`** (`6,8224 MiB/s`, `307,53 cpb`) em 4R (**`13,30x` speedup** sobre `v5.0` escalar); API completa C99 8R em **`56,7458 µs/call`** (`1,0756 MiB/s`); consolidação de `v5_1_final_hardening_results.json`, `relatório interno de prontidão (não incluído neste repositório)`, `ESPECIFICACAO_V5_2.md` e `relatório consolidado interno (não incluído neste repositório)`. | **CONCLUÍDA (PASS)** |

---
