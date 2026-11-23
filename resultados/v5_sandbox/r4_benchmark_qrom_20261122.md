# R4 — Benchmark RSD-S v5.1 vs SHA/HMAC/BLAKE2 + testes análogos a QROM (2026-11-22)

> **Nota de versão.** Este relatório é anterior à v5.2 e descreve medições da linha v5.1. Resultados de segurança e desempenho **não foram refeitos na v5.2** salvo onde o texto disser o contrário. Vetores de referência da v5.2: `testes/vetores_v52.json`.


> **Escopo:** proxy empírico. **Não** é prova em QROM, **não** certifica segurança pós-quântica.

## 1. Latência (loop Python, n=4000; RSD usa C core AVX2 via ctypes + fragmentação em Python; hashes via hashlib/OpenSSL)

| Primitiva | µs/chamada |
|---|---|
| RSD-S v5.1 (8R + SHA-256) | 31.26 |
| RSD-S v5.1 core cru (8R, sem SHA) | 30.58 |
| CONTROLE RSD-S 1R cru | 17.48 |
| CONTROLE RSD-S 2R cru | 19.07 |
| HMAC-SHA256 | 2.06 |
| HMAC-SHA3-256 | 3.35 |
| BLAKE2b (keyed) | 1.05 |
| SHAKE256(k||m) | 1.15 |
| SHA3-256(k||m) | 1.11 |
| CONTROLE linear GF(2) | 3.33 |

## 2. Avalanche (flip de 1 bit de entrada, fração de bits de saída alterados; ideal 0.5)

| Primitiva | média | σ |
|---|---|---|
| RSD-S v5.1 core cru (8R, sem SHA) | 0.49947 | 0.02246 |
| CONTROLE RSD-S 1R cru | 0.49932 | 0.02488 |
| CONTROLE RSD-S 2R cru | 0.49783 | 0.02238 |
| HMAC-SHA256 | 0.49932 | 0.031 |

## 3. Uniformidade do 1º byte (χ², 255 g.l., 2^16 amostras)

| Primitiva | χ² | p |
|---|---|---|
| RSD-S v5.1 core cru (8R, sem SHA) | 221.45 | 0.9366 |
| RSD-S v5.1 (8R + SHA-256) | 262.91 | 0.3533 |
| CONTROLE RSD-S 1R cru | 0.0 | 1.0 |
| HMAC-SHA256 | 239.94 | 0.7424 |
| CONTROLE linear GF(2) | 0.0 | 1.0 |

## 4. Tabelas H_k de n bits vs ensemble de Oráculo Aleatório (z-scores; |z|>4 = distinguível)

### n=10
RO: collisions_N_minus_image=375.025, preimage_multiplicity=2.125, simon_max_xor_period_matches=7.850

| Primitiva | collisions_N_minus_image | preimage_multiplicity | simon_max_xor_period_matches | flags |
|---|---|---|---|---|
| RSD-S v5.1 (8R + SHA-256) | 0.35 | -1.56 | 1.08 | — |
| RSD-S v5.1 core cru (8R, sem SHA) | 0.46 | -0.93 | -0.27 | — |
| CONTROLE RSD-S 1R cru | 0.96 | 0.31 | 1.75 | — |
| CONTROLE RSD-S 2R cru | 0.71 | -0.93 | -0.27 | — |
| HMAC-SHA256 | -0.22 | 0.0 | 2.42 | — |
| HMAC-SHA3-256 | 1.03 | -1.56 | 1.08 | — |
| BLAKE2b (keyed) | 1.47 | -1.24 | -0.27 | — |
| SHAKE256(k||m) | 1.36 | -0.31 | 1.75 | — |
| SHA3-256(k||m) | -0.22 | 0.0 | 0.4 | — |
| CONTROLE linear GF(2) | 2.58 | -0.93 | 2045.21 | simon_max_xor_period_matches |

### n=12
RO: collisions_N_minus_image=1501.500, preimage_multiplicity=2.150, simon_max_xor_period_matches=9.400

| Primitiva | collisions_N_minus_image | preimage_multiplicity | simon_max_xor_period_matches | flags |
|---|---|---|---|---|
| RSD-S v5.1 (8R + SHA-256) | 2.13 | -0.06 | -0.33 | — |
| RSD-S v5.1 core cru (8R, sem SHA) | 1.32 | -0.37 | 0.22 | — |
| CONTROLE RSD-S 1R cru | -6.4 | -1.61 | -0.87 | collisions_N_minus_image |
| CONTROLE RSD-S 2R cru | 1.03 | -0.37 | 0.22 | — |
| HMAC-SHA256 | 0.18 | -0.68 | -1.42 | — |
| HMAC-SHA3-256 | 2.83 | -0.06 | -0.33 | — |
| BLAKE2b (keyed) | -0.64 | -1.61 | 0.22 | — |
| SHAKE256(k||m) | 1.84 | -0.06 | 0.22 | — |
| SHA3-256(k||m) | -1.23 | -0.99 | 0.76 | — |
| CONTROLE linear GF(2) | 42.71 | 0.25 | 6679.06 | collisions_N_minus_image, simon_max_xor_period_matches |

### n=14
RO: collisions_N_minus_image=6040.600, preimage_multiplicity=2.375

| Primitiva | collisions_N_minus_image | preimage_multiplicity | flags |
|---|---|---|---|
| RSD-S v5.1 (8R + SHA-256) | -1.33 | -0.81 | — |
| RSD-S v5.1 core cru (8R, sem SHA) | -0.2 | -1.08 | — |
| CONTROLE RSD-S 1R cru | -58.91 | -0.81 | collisions_N_minus_image |
| CONTROLE RSD-S 2R cru | -0.58 | -1.08 | — |
| HMAC-SHA256 | -2.36 | -0.54 | — |
| HMAC-SHA3-256 | -1.26 | -1.88 | — |
| BLAKE2b (keyed) | -0.17 | 0.0 | — |
| SHAKE256(k||m) | -1.59 | -0.81 | — |
| SHA3-256(k||m) | 0.41 | -2.15 | — |
| CONTROLE linear GF(2) | -63.41 | -1.61 | collisions_N_minus_image |

## 5. Grover exato (statevector, n=12) sobre a tabela da primitiva

Nota: Grover simulado reproduz sin²((2k+1)θ) por construção; o que distingue primitivas é a multiplicidade M das pré-imagens (seção 4).

| Primitiva | M médio | k_opt médio | p_max médio | desvio máx vs teoria |
|---|---|---|---|---|
| RSD-S v5.1 (8R + SHA-256) | 1.67 | 40.0 | 1.0000 | 9.0e-15 |
| RSD-S v5.1 core cru (8R, sem SHA) | 2.00 | 38.0 | 0.9998 | 9.0e-15 |
| CONTROLE RSD-S 1R cru | 1.33 | 45.0 | 1.0000 | 9.0e-15 |
| CONTROLE RSD-S 2R cru | 1.67 | 43.0 | 0.9997 | 9.0e-15 |
| HMAC-SHA256 | 2.33 | 36.0 | 0.9995 | 9.0e-15 |
| HMAC-SHA3-256 | 1.67 | 40.0 | 1.0000 | 8.9e-15 |
| BLAKE2b (keyed) | 1.33 | 45.0 | 1.0000 | 9.0e-15 |
| SHAKE256(k||m) | 2.33 | 40.7 | 1.0000 | 8.9e-15 |
| SHA3-256(k||m) | 2.33 | 36.7 | 0.9998 | 9.0e-15 |
| CONTROLE linear GF(2) | 3.33 | 28.3 | 0.9996 | 6.0e-15 |

## 6. Veredito

| Primitiva | Distinguível do RO? | Testes sinalizados |
|---|---|---|
| RSD-S v5.1 (8R + SHA-256) | não | — |
| RSD-S v5.1 core cru (8R, sem SHA) | não | — |
| CONTROLE RSD-S 1R cru | SIM | collisions_N_minus_image |
| CONTROLE RSD-S 2R cru | não | — |
| HMAC-SHA256 | não | — |
| HMAC-SHA3-256 | não | — |
| BLAKE2b (keyed) | não | — |
| SHAKE256(k||m) | não | — |
| SHA3-256(k||m) | não | — |
| CONTROLE linear GF(2) | SIM | collisions_N_minus_image, simon_max_xor_period_matches |

## 7. Custos quânticos de referência (algébricos, não medidos)

| Alvo | Algoritmo | Consultas |
|---|---|---|
| Pré-imagem, saída 256 b | Grover | ~2^128 (profundidade serial, ver NIST) |
| Pré-imagem, saída 512 b (XOF512) | Grover | ~2^256 |
| Colisão, 256 b | BHT/CNS | ~2^85 consultas (2^{n/3}); trade-off com memória |
| Colisão, 512 b | BHT/CNS | ~2^170 |
| Chave 256 b | Grover | ~2^128 |

## 8. Limites honestos

- Domínio toy (n≤14 bits) não prova nada sobre 256/512 bits; mostra apenas ausência de estrutura grosseira testada.
- A saída pública usa SHA-256/SHAKE256: a segurança de pré-imagem/colisão final é herdada de SHA, não do núcleo SPN.
- Prova formal em QROM (Zhandry/Unruh) e revisão externa continuam pendentes; nada aqui altera `RESTRICOES_DE_PROJETO.md`.
