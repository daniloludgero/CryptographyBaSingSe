# Cobertura de criptoanálise

O que já foi tentado contra a RSD-S, com o resultado e a fonte. Todos os números são do projeto, na linha v5.1 salvo indicação, e **não substituem revisão externa**.

## Ataques tentados

| Família | Resultado | Fonte |
|---|---|---|
| **Diferencial e linear sobre a S-box** | Uniformidade diferencial 4 (p ≤ 2^-14); não linearidade 32512, \|W\| máx. 512; grau 15; 0 pontos fixos | `resultados/v5_sandbox/lote_b_cryptanalysis_report.md` |
| **Wide-trail** | Mínimo de 66, 99 e 132 S-boxes ativas em 4, 6 e 8 rodadas; limite de característica única 2^-1848 | `implementacao/analise_wide_trail.py` |
| **Algébrico (bilinear da v4)** | Quebrava a v4 em 25 ms; **bloqueado** pela camada afim da v5 | `lote_b_cryptanalysis_report.md` |
| **Algébrico e integral em rodadas reduzidas** | 1R quebrada em 0,244 s; **3R quebrada** por Square/Integral (131 072 entradas; ≈ 10 s, **reproduzido na v5.2**); 4R destrói a propriedade | `lote_b_cryptanalysis_report.md`, [`MEDICOES_V5_2.md`](MEDICOES_V5_2.md) |
| **Integral/Square (harness R5)** | Detectado até 2R; margem de 6R sobre 8R (reexecutado na v5.2) | `docs/evidencia/CONSOLIDADO_R5.md`, [`MEDICOES_V5_2.md`](MEDICOES_V5_2.md) |
| **Linear / Walsh** | Máscaras genéricas: 0R (z = 2,8), contra 1R no AES. Máscaras estruturais da MDS: 1R (z = 6,1) | [`MEDICOES_V5_2.md`](MEDICOES_V5_2.md) |
| **Boomerang** | Sonda alinhada: 500/500 em 1R, 0/500 em 2R a 4R | `resultados/v5_sandbox/r5_m4_red_team_offensive.md` |
| **Diferencial impossível e MitM** | Diferencial impossível de 2R (0/8192) violado em 3R; barreira de MitM com dependência total | `r5_m4_red_team_offensive.md` |
| **Slide e chave relacionada** | Distâncias de Hamming normalizadas em torno de 0,49 a 0,50 | `r5_m4_red_team_offensive.md` |
| **DFA (falha injetada)** | Recuperava a subchave final da v4 com 64 falhas; detectado na v5.1; contornado em `R-1` (RT-F2-01), corrigido na v5.2 | `RELATORIO_M4_ATAQUES_SOBRE_A_V4.md`, `r5_m4_red_team_offensive.md` |
| **Tempo e cache (TVLA)** | v4: \|t\| = 42 e 817 (vazava); núcleo C99 da **v5.2**: máx. \|t\| = 2,30 em 12 execuções de 100 000 amostras por grupo, contra 2,18 do controle | `r3_metric4_avx2_tvla_20261122.md` (v4/v5.1), [`MEDICOES_V5_2.md`](MEDICOES_V5_2.md) (v5.2) |
| **Reticulados (LLL, Kannan, CVP) no módulo de dupla chave** | Controle positivo recuperado; modo endurecido: 0 de 3 recuperações | `lote_a_lattice_report.md` |
| **Reuso de `n_sess` no módulo de dupla chave** | v5.0 vazava a diferença de estados privados; v5.1 com SIV: 0 de 1000 vazamentos | `lote_a_lattice_report.md`, `r3_metric1_siv_z65537_20261122.md` |
| **Aleatoriedade (NIST SP 800-22)** | 10/10 na saída pública de 64 B; a serialização antiga de 3 B/palavra falhava 9/10 | `lote_a_lattice_report.md`, `r3_metric2_nist_folding_20261122.md` |
| **Concorrência (ThreadSanitizer)** | Corrida em `init_cauchy_mds()` (RT-F2-02); corrigida na v5.2 | `r5_m4_red_team_offensive.md` |
| **Fuzzing de fronteira da API** | 41 de 41 casos tratados | `r5_m4_red_team_offensive.md` |
| **SAT/SMT** | Modelos de 1 rodada e de camadas da 2ª rodada; **não** cobrem 8 rodadas | `ferramentas/`, `implementacao/` |

## O que o projeto reconhece como não coberto

- **Revisão independente externa**: nenhuma.
- **Ataques de rodada completa**: nada foi provado nem refutado para 8 rodadas além dos limites de característica única.
- **Soma de trilhas e *clustering* diferencial/linear** em rodadas altas.
- **Ataques quânticos específicos** à estrutura (além dos limites genéricos) e à derivação de chaves.
- **Chave relacionada em modelo forte**, **multi-chave** e **multi-sessão em larga escala**.
- **Canais laterais em outras plataformas**, compiladores e microarquiteturas, e na v5.2 em particular.
- **Falhas coordenadas** nos dois fluxos do Anti-DFA.
- **Reprodutibilidade numérica** da matriz `B` em `float64` entre plataformas.

## Como acrescentar um resultado

Abra uma issue com o modelo "Cryptanalysis finding" ([`docs/DESAFIO.md`](../DESAFIO.md)). Resultados reproduzíveis entram nesta tabela com crédito a quem os produziu.
