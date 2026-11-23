# Medições da RSD-S v5.2

Este documento registra o que foi **medido na v5.2** (não herdado da v5.1), como foi medido, em que máquina, e o que cada número **não** mostra. Todo número do [`README`](../../README.md) sobre a v5.2 aponta para cá.

Os dados brutos estão em [`resultados/v5_2/`](../../resultados/v5_2/) e o roteiro para reproduzir está em [`ferramentas/medicao_v52/`](../../ferramentas/medicao_v52/).

## 1. O que foi medido

| Item | Valor |
|---|---|
| Código | `implementacao/c_core/rsd_s_v5_ct.c`, `rsd_s_v5_hardened.py`, `bandlimited_dual_key.py` (v5.2) |
| Identificação | SHA-256 de cada arquivo em [`medicoes_v52_20261123.json`](../../resultados/v5_2/medicoes_v52_20261123.json) |
| Núcleo C | Executa **os dois fluxos A e B em todas as rodadas** (Anti-DFA v5.2). O custo de ~2× já está incluído em todos os tempos abaixo |
| Vetores | `testes/vetores_v52.json` (6 vetores) |

Os comentários do cabeçalho do arquivo C foram corrigidos depois da medição (versão, número de multiplicações e descrição do Anti-DFA). O código de máquina gerado é **idêntico** nas três compilações medidas (`-O3 -mavx2`, `-O2 -mno-avx2`, `-O0`), conferido por comparação do desmontado.

## 2. Ambiente

| | |
|---|---|
| CPU | Intel Xeon @ 2,10 GHz, **máquina virtual (KVM)**, 4 vCPU; AVX2, AVX-512, SHA-NI |
| Compilador | gcc 13.3.0 |
| Software | Python 3.13.18, NumPy 2.5.3, Linux 6.18 |
| Controle | Processo fixado em um núcleo (`taskset`); aquecimento antes de cada medição |
| **Limite** | VM compartilhada, sem controle de frequência, de *turbo* nem de vizinhos. Os números são de **uma máquina** e servem como ordem de grandeza reprodutível, não como especificação |

Os números da v5.1 citados em relatórios antigos foram medidos em outra CPU (Xeon Platinum 8481C). **Não são comparáveis** com os desta página.

## 3. Resultados

### 3.1 Latência do núcleo C99 (uma chamada = 64 bytes de estado)

21 repetições por passada, 2 passadas independentes. Mediana por passada. As duas passadas diferem menos de 1,5 % nas compilações com otimização e até cerca de 4 % no `-O0`.

| Compilação | Rodadas | Latência (µs) | Vazão (MiB/s) | Ciclos por byte |
|---|---:|---:|---:|---:|
| `-O3 -mavx2` | **8** (oficial) | **29,6** | 2,06 | ≈ 970 |
| `-O3 -mavx2` | 4 | 14,7 | 4,15 | ≈ 480 |
| `-O2`, sem AVX2 (escalar) | 8 | 355 | 0,17 | ≈ 11 650 |
| `-O0` | 8 | ≈ 1 800 | 0,03 | ≈ 60 000 |

**Custo do Anti-DFA (ablação, não é produto).** Uma cópia do núcleo que executa só o fluxo A levou 15,2 µs em 8 rodadas, contra 29,6 µs com os dois fluxos: razão **1,95×**. A proteção custa quase o dobro.

**O que não mostra:** é a latência do **núcleo** (o SPN). Não inclui derivação das chaves de rodada (HMAC), a compressão final (SHA-256/SHAKE256) nem o módulo de dupla chave. Não é vazão de cifra: a RSD-S não é uma cifra. Em outra CPU o resultado muda.

### 3.2 Camadas Python (referência pedagógica)

| Operação (8 rodadas) | Tempo por chamada |
|---|---:|
| Estado pré-SHA | ≈ 77 a 83 ms |
| API oficial, saída de 32 B | ≈ 78 a 83 ms |
| API oficial, saída de 64 B | ≈ 76 a 78 ms |
| Módulo de dupla chave (`refactor_public_output`) | ≈ 78 a 80 ms |
| Derivação das chaves de rodada | ≈ 15 a 25 µs |

O Python é cerca de 2 600 vezes mais lento que o núcleo C. **Não use a referência em Python para nada além de verificar vetores e estudar.** O custo do módulo de dupla chave é dominado pelo SPN.

### 3.3 Correção: paridade e detecção de falhas

| Compilação | Paridade C99 × Python | Falha injetada detectada, saída zerada |
|---|---:|---:|
| `-O3 -mavx2` | 126 / 126 | 24 / 24 |
| `-O2`, sem AVX2 | 126 / 126 | 24 / 24 |
| `-O0` | 126 / 126 | 24 / 24 |

As 126 entradas são os 6 vetores congelados mais 120 entradas aleatórias, em 1, 2, 4 e 8 rodadas. As 24 falhas são injeções em cada uma das rodadas 1 a 8, em 3 posições de palavra. Isso confirma a mitigação RT-F2-01.

**O que não mostra:** que as duas implementações estão **corretas** em relação a uma especificação independente (elas concordam entre si e com os vetores). Falhas aplicadas **aos dois fluxos de forma idêntica** não são detectadas, por construção.

### 3.4 Tempo constante (TVLA, teste de Welch)

100 000 amostras por grupo, aquisição intercalada e aleatorizada, com aquecimento, 6 execuções independentes por teste, núcleo `-O3 -mavx2`, 8 rodadas. Limiar de reprovação: |t| > 4,5.

| Teste | |t| máximo (bruto) | |t| máximo (recorte de 1 % superior) |
|---|---:|---:|
| Estado fixo contra aleatório | 2,24 | 1,61 |
| Zeros contra uns | 1,07 | 1,92 |
| **Controle:** aleatório contra aleatório | 2,18 | 1,85 |
| *Réplica (outra execução da ferramenta entregue): fixo / zeros / controle* | *2,03 / 2,30 / 2,00* | n/a |

Nas 12 execuções (6 originais e 6 da réplica) o máximo de |t| foi **2,30**, sempre abaixo de 4,5. Os sinais de *t* alternam entre as execuções e as magnitudes ficam na mesma ordem do controle (até 2,18). **Nenhum vazamento detectável nesta máquina.**

**O que não mostra:** o controle atinge 2,18 por ruído, então esta VM tem sensibilidade limitada, e um efeito muito pequeno poderia passar despercebido. Vale para este compilador, esta CPU e esta versão; **não** garante ausência de vazamento em outra microarquitetura, nem de canais laterais de cache fora do modelo (não houve medição com cache preparado por um adversário). O módulo Python **não** é tempo constante e não é alvo desta medição.

### 3.5 Wide-trail

Executado por `implementacao/analise_wide_trail.py`:

| Rodadas | S-boxes ativas (mínimo) | Limite diferencial de característica única | Correlação linear |
|---:|---:|---:|---:|
| 4 | 66 | 2^-924 | 2^-462 |
| 6 | 99 | 2^-1386 | 2^-693 |
| 8 | 132 | 2^-1848 | 2^-924 |

**O que não mostra:** vale para **uma** característica. Não soma trilhas e não é prova de segurança.

### 3.6 Ataque Square/Integral em 3 rodadas (reproduzido na v5.2)

Modelo: chave desconhecida, textos claros escolhidos, saída **pré-SHA** (64 B) observável. Alvo: a subchave equivalente da 3ª rodada, `k*₃ = rc₃·1 ⊕ M⁻¹·rk₃` (512 bits).

| Item | Resultado |
|---|---|
| Textos claros escolhidos | 131 072 (2 Λ-conjuntos de 2^16) |
| Palavras recuperadas, conferidas contra a subchave verdadeira | **32 / 32** (512 bits) |
| Tempo total | ≈ 10 s (6,6 s de consultas ao núcleo + 2,9 s de análise) |

O relatório da v5.1 registrava 296 s: o novo roteiro usa a transformada de Walsh–Hadamard para calcular a correlação XOR em vez de força bruta. O ataque **não** se estende a 4 rodadas, onde a propriedade integral é destruída. Roteiro: [`ataque_square_3r.py`](../../ferramentas/medicao_v52/ataque_square_3r.py).

**O que não mostra:** a API pública (`diffuse_rsd_s_v5`) passa a saída por SHA-256 ou SHAKE256 e **não expõe** o estado pré-SHA; este ataque vale para quem o observa (por exemplo, um uso interno do SPN sem a compressão final). Não diz nada sobre 8 rodadas.

### 3.7 Comparativo com o AES (harness de ataques automatizados)

"Alcance" é a maior rodada em que o ataque detecta o objeto. Integral e diferencial usam os mesmos parâmetros nos dois lados (Λ-conjunto de 2^16; 4 096 pares). Os dados são da execução na v5.2 (`r5_m1_resultados_v52.json`, `r5_m2_resultados_v52.json`).

| Ataque | AES-128 (10R) | AES-256 (14R) | RSD-S v5.2 (8R) |
|---|---:|---:|---:|
| Integral / Square | 3R | 3R | **2R** |
| Diferencial e truncado | 2R | 2R | **1R** |
| Linear / Walsh, **máscaras genéricas** (N = 524 288, 64 máscaras) | 1R (z = 68) | 1R (z = 68) | **0R** (z = 2,8) |
| Linear / Walsh, máscaras **estruturais** da MDS | n/a | n/a | 1R (z = 6,1) |

A linha de máscaras genéricas foi refeita aqui com o **mesmo N** nos dois lados. O relatório antigo comparava a RSD-S com N = 524 288 contra o AES com N = 16 384, o que não é simétrico.

**O que não mostra:** o alcance mede o que **este harness de 5 ataques** detecta, não segurança. O AES tem mais de 25 anos de criptoanálise pública e ataques mais fortes que o harness. Menos rodadas detectáveis pode significar difusão mais rápida, não maior segurança.

### 3.8 NIST SP 800-22 sobre a serialização de 64 B (reexecutado na v5.2)

O teste `testes/test_r3_metric2_nist_folding.py` chama a função `_unpadded_z65537_to_bytes64` da v5.2 e foi reexecutado em 2026-11-23: **10 de 10** testes principais e **12 de 12** estendidos em 1 024 000 bits, proporção de bits 1 igual a 0,500006. O resultado está em [`r3_metric2_nist_folding_20261122.json`](../../resultados/v5_sandbox/r3_metric2_nist_folding_20261122.json) (os valores são idênticos aos da execução anterior, porque a semente é fixa).

**O que não mostra:** a entrada do teste são **vetores sintéticos uniformes em ℤ₆₅₅₃₇**, não saídas do motor completo `(x, y) → Y_pub`. Testa a etapa de *folding*, que é onde a v5.2 mudou, e não a distribuição de `Y_pub` de ponta a ponta. É teste de sanidade estatística, não de segurança.

### 3.9 Réplica independente

A ferramenta entregue (`executar_medicao.sh`) foi executada de novo, do zero, numa cópia limpa do repositório. Os resultados estão em [`replica_ferramenta_entregue/`](../../resultados/v5_2/replica_ferramenta_entregue/). Concordância com as medições originais: latências dentro de ±3 %, paridade 126/126 e falhas 24/24 nas três compilações, ataque de 3 rodadas com 32/32 palavras em 9,0 s, comparativo linear idêntico.

## 4. O que foi corrigido em relação ao que o README dizia

| Antes (herdado da v5.1) | Agora (v5.2) |
|---|---|
| Latência de 16,26 µs por chamada | **29,6 µs** (≈ 1,8× mais lento: o Anti-DFA agora cobre todas as rodadas, e a CPU é outra) |
| TVLA \|t\| = 0,32, medido na v5.1 | Máx. \|t\| = 2,30 em 12 execuções, medido na v5.2, com controle |
| Quebra de 3R em ≈ 5 min | ≈ 10 s, reproduzida na v5.2 |
| Linear 0R sem ressalva | 0R com máscaras genéricas; 1R com máscaras estruturais |
| NIST 10/10 sem dizer a versão | Reexecutado na v5.2, com a ressalva de que a entrada é sintética |

## 5. Reproduzir

```bash
ferramentas/medicao_v52/executar_medicao.sh 2 resultados/v5_2/minha_medicao
```

Exige `gcc`, `python3`, `numpy` e `scipy`, e leva cerca de 5 minutos. Fixe a CPU (o primeiro argumento) e feche outros programas. **Seus números vão diferir.** Compare a ordem de grandeza e as conclusões, não o último dígito.
