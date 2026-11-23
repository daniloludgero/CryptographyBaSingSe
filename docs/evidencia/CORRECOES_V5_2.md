# Correções da v5.2: os achados de severidade Alta e Média

A revisão ofensiva interna da v5.1 encontrou 9 achados: 2 de severidade **Alta**, 3 **Médios** e 4 **Baixos**. A v5.2 corrige os **5 achados Altos e Médios**. Esta página mostra, para cada um, o ataque, a correção e a prova. A prova consiste em executar **o mesmo exploit** escrito contra a v5.1 sobre o código v5.1 e sobre o código v5.2.

Reproduza em menos de um minuto:

```bash
python3 ferramentas/verificacao_correcoes_v52/reproduzir.py
```

O código v5.1 vulnerável e o exploit original ficam em [`ferramentas/verificacao_correcoes_v52/historico_v5_1/`](../../ferramentas/verificacao_correcoes_v52/historico_v5_1/) só para essa reprodução. Resultado da última execução: [`correcoes_antes_depois.json`](../../resultados/v5_2/correcoes_antes_depois.json).

## Resumo

| Achado | Severidade | Ataque na v5.1 | Mesmo ataque na v5.2 |
|---|---|---|---|
| RT-F2-01 | **Alta** | Falha nas rodadas 1 a 7 passa sem detecção | **Detectada** nas 8 rodadas |
| RT-F2-02 | **Alta** | Corrida de dados (ThreadSanitizer) | **Nenhuma** corrida |
| RT-F1-01 | Média | Metade da subchave reconstruída sem a chave mestra | **Bloqueado** |
| RT-F2-03 | Média | API pública devolve o estado privado | **Bloqueado** |
| RT-F2-04 | Média | Vazamento de tempo, Welch t = 13,2 | **Sem vazamento**, t = 0,12 |

## Achados de severidade Alta

### RT-F2-01: a proteção contra falhas (Anti-DFA) cobria só a última rodada

- **Ataque na v5.1.** O núcleo seguia com **um** estado até a rodada 7 e só duplicava o estado na rodada final para comparar. Uma falha transitória (pulso de tensão, de *clock*, laser) nas rodadas 1 a 7 entrava igual nos dois fluxos e a saída corrompida saía **sem erro**. É a porta de entrada para a análise diferencial de falhas, que recuperava a subchave da v4 com 64 falhas.
- **Correção na v5.2.** Dois fluxos independentes, A e B, percorrem **todas** as rodadas `R1..R` e são comparados em tempo constante ao final. Na divergência, a saída é zerada e a chamada falha (`rc = -2` no C99, `FaultDetectedError` no Python). Arquivos: `implementacao/c_core/rsd_s_v5_ct.c` e `implementacao/rsd_s_v5_hardened.py`.
- **Prova.** Falha de 1 bit injetada **dentro** da execução, na entrada de cada rodada:

  | Rodada | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
  |---|---|---|---|---|---|---|---|---|
  | v5.1 | não | não | não | não | não | não | não | detectada |
  | **v5.2** (C99 e Python) | **detectada** | **detectada** | **detectada** | **detectada** | **detectada** | **detectada** | **detectada** | **detectada** |

  Nas três compilações do C99 (`-O3 -mavx2`, `-O2`, `-O0`), 24 de 24 falhas (8 rodadas × 3 posições) foram detectadas com a saída zerada ([`MEDICOES_V5_2.md`](MEDICOES_V5_2.md), §3.3).
- **Custo.** A proteção completa custa **1,95×** em latência (29,6 µs contra 15,2 µs com um fluxo só).
- **O que continua fora do modelo.** Falha que atinge os dois fluxos de forma idêntica (na entrada, nas chaves de rodada ou nas constantes, que são compartilhadas) e estado corrompido **fora** do núcleo, entre duas chamadas. Nesse caso a segunda chamada recebe uma entrada já corrompida, que nenhuma redundância interna distingue de uma entrada legítima. O teste `test_05` da suíte ofensiva cobre os dois lados: a falha dentro da execução (detectada) e a corrupção entre chamadas (limite declarado).

### RT-F2-02: corrida de dados na inicialização da tabela MDS

- **Ataque na v5.1.** A tabela `CAUCHY_BIT_BASIS` (32 KiB) era inicializada na primeira chamada com uma bandeira comum. Com 16 *threads* chamando o núcleo ao mesmo tempo, o ThreadSanitizer acusou corrida de dados (`exit = 66`). Uma *thread* podia usar a tabela pela metade e produzir saída errada.
- **Correção na v5.2.** Inicialização com sincronização atômica *acquire/release* (`__atomic_load_n` e `__atomic_compare_exchange_n`) e três estados: não inicializada, inicializando e pronta.
- **Prova.** O mesmo teste com 16 *threads* sob ThreadSanitizer: **nenhuma corrida** (`exit = 0`).

## Achados de severidade Média

### RT-F1-01: a subchave expunha a chave de rodada literalmente

- **Ataque na v5.1.** A expansão copiava `K_r` para as primeiras 16 palavras da subchave e derivava só o resto por HMAC. Quem obtivesse `rk[r][0..15]` reconstruía **100 %** de `rk[r][16..31]` sem conhecer a chave mestra.
- **Correção na v5.2.** Todos os blocos são derivados por `HMAC-SHA256(K_r, "EXP|" ‖ uint32_be(bloco))`, inclusive o bloco 0. A paridade C99 × Python continua exata.
- **Prova.** O exploit não reconstrói mais a segunda metade, porque as duas metades são independentes.
- **Consequência.** As saídas da v5 mudaram em relação à v0.5.1, por isso os vetores da v5.2 são novos (`testes/vetores_v52.json`). Os vetores da v4 não mudaram.

### RT-F2-03: a API pública devolvia o estado secreto

- **Ataque na v5.1.** `BandlimitedDualKeyEngine.refactor_public_output()` devolvia `s_priv_state`, o estado interno antes do hash, no próprio dicionário de saída.
- **Correção na v5.2.** O campo saiu do retorno padrão. Só aparece com o parâmetro explícito `include_private_debug=True`, para auditoria.
- **Prova.** O exploit não encontra mais `s_priv_state` no retorno público.

### RT-F2-04: vazamento de tempo no *folding* de ℤ₆₅₅₃₇

- **Ataque na v5.1.** Para a coordenada de valor 65536, a função calculava um SHA-256 extra num desvio condicional. O tempo revelava quantas coordenadas tinham esse valor: Welch **t = 13,2** no caso realista (0 contra 1 coordenada; p = 1,3 × 10⁻³⁸) e **t = 192,9** no pior caso.
- **Correção na v5.2.** Um único fluxo SHAKE-256 gera todas as palavras de *folding*, e a escolha é feita por máscara aritmética, sem desvio. Entradas fora de `0..65536` são rejeitadas com `ValueError`.
- **Prova.** O mesmo teste de Welch: **t = 0,12** no caso realista e **t = 0,21** no pior caso, abaixo do limiar de 4,5.

## Os 4 achados de severidade Baixa: não foram corrigidos

O repositório de origem **não traz correção** para os achados Baixos. Executei de novo, sobre a v5.2, os mesmos testes que os revelaram. Os resultados são iguais aos da v5.1:

| Achado | O que é | Situação na v5.2 |
|---|---|---|
| RT-F1-02 | O bit mais alto das palavras 15 e 31 do estado de entrada é sempre 0 (as entradas são menores que 2^255 − 19) | Igual. O viés some após a 1ª rodada (130 e 135 de 256, perto de 128) |
| RT-F1-03 | A constante de rodada é a mesma nas 32 palavras e as 32 linhas da MDS têm a mesma soma (`0x1731`) | Igual. Só a subchave quebra o subespaço simétrico |
| RT-F2-05 | A serialização isolada de 64 B não é injetiva: 65536 e outro valor colidem | Igual. No motor completo as entradas diferentes mudam o *folding*; a forma de 96 B distingue. Documentado na especificação, §3.2 |
| RT-F2-06 | A tabela de 32 KiB ocupa o cache L1D inteiro; o núcleo emite `vzeroupper`, mas não zera `xmm0..15` antes de retornar | **Aberto** |

O RT-F2-06 é o único que pode afetar uma implementação real: resíduos em registradores podem ser lidos por código que roda depois na mesma *thread*. Corrigi-lo exige zerar os registradores vetoriais na saída do núcleo e medir o custo.

## O que esta página não mostra

- Correção de um achado conhecido não significa ausência de outros. A revisão foi feita **pelo próprio projeto**, sem auditoria independente.
- Os testes de tempo e de concorrência valem para a máquina, o compilador e a versão usados ([`MEDICOES_V5_2.md`](MEDICOES_V5_2.md), §2).
