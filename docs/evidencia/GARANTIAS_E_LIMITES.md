# Garantias e limites

Esta página lista o que o projeto afirma, com que base, e o que isso **não** garante. Leia junto com o [objetivo e modelo de ameaça](OBJETIVO_E_MODELO_DE_AMEACA.md).

## Classes de evidência

| Marca | Significado |
|---|---|
| **Documentada** | Vem de especificação, padrão ou literatura citada |
| **Observada** | Medida ou executada pelo projeto, com comando reproduzível |
| **Inferida** | Conclusão do projeto a partir de outras evidências |
| **Desconhecida** | O projeto não sabe |

## Tabela

| Afirmação | Classe | O que **não** garante |
|---|---|---|
| As implementações Python e C99 produzem as mesmas saídas nos 6 vetores v5.2 | Observada | Que a construção é segura; apenas que as implementações concordam |
| A S-box tem uniformidade diferencial 4, nenhum ponto fixo e grau 15 | Observada | Segurança da primitiva completa |
| A matriz MDS tem *branch number* 33 | Observada | Segurança da primitiva completa |
| No mínimo 66 S-boxes ativas em 4 rodadas e 132 em 8; limite diferencial de característica única 2^-1848 | Documentada e conferida por programação dinâmica | Não soma trilhas. Não é prova de segurança |
| O núcleo C99 da v5.2 não mostra vazamento de tempo detectável (TVLA, máx. \|t\| = 2,30 em 12 execuções, contra 2,18 do controle; limiar 4,5) | Observada | Vale para um compilador e uma CPU (VM ruidosa, sensibilidade limitada). Não prova ausência de vazamento em outra microarquitetura nem de canais de cache |
| Desempenho do núcleo de 8 rodadas: 29,6 µs por chamada, com Anti-DFA de dois fluxos | Observada | Uma VM Xeon 2,10 GHz. Não inclui HMAC nem hash final |
| Saída pública do módulo de dupla chave passa na bateria NIST SP 800-22 | Observada | Teste de sanidade estatística; não indica segurança |
| Rodadas reduzidas (1 a 3) são quebradas por ataques estruturais; a subchave equivalente de 3 rodadas é recuperada em ≈ 10 s na v5.2 | Observada | Não diz nada sobre 8 rodadas, mas mostra onde a margem começa |
| A construção **não** se baseia em fatoração nem em logaritmo discreto | Documentada | Não implica segurança contra computadores quânticos |
| Rascunho de redução QROM (Teoremas 1 e 2) | Documentada, **condicional** | Escrito para a v5.1; depende de hipóteses não provadas (qPRP do SPN de 8 rodadas); sem revisão externa |
| Segurança contra todos os ataques de rodada completa | **Desconhecida** | — |

## O que o projeto **não** declara

- Que a RSD-S é segura, pós-quântica, certificada, auditada ou pronta para produção.
- Que o resultado de um teste estatístico, de avalanche ou de limite de característica única é prova de segurança.
- Que "512 bits de estado" equivale a "512 bits de segurança".
- Que um resultado da v5.1 vale para a v5.2 sem nova medição, exceto onde a correção da v5.2 é a causa da mudança.

## Achados do red-team interno

Revisão ofensiva interna da v5.1, com 9 achados. Estado atual:

| ID | Severidade | Descrição curta | Estado |
|---|---|---|---|
| RT-F2-01 | Alta | Anti-DFA contornado por falha na penúltima rodada | **Corrigido na v5.2** (dois fluxos por `R1..R`) |
| RT-F2-02 | Alta | Corrida de dados em `init_cauchy_mds()` | **Corrigido na v5.2** (sincronização atômica) |
| RT-F1-01 | Média | Subchave expunha `K_r` literalmente | **Corrigido na v5.2** (HMAC em todos os blocos) |
| RT-F2-03 | Média | API devolvia o estado privado | **Corrigido na v5.2** (opt-in explícito) |
| RT-F2-04 | Média | Vazamento de tempo no *folding* em Python | **Corrigido na v5.2** (seleção por máscara) |
| RT-F1-02 | Baixa | Dois bits mais significativos fixos na entrada | Dissipa-se após a 1ª rodada |
| RT-F1-03 | Baixa | Simetria de constante de rodada e soma de linha da MDS | Mitigada pela subchave |
| RT-F2-05 | Baixa | Colisão 2 para 1 na função isolada de *folding* | Validação de faixa entregue; a não injetividade está documentada na especificação (§3.2) |
| RT-F2-06 | Baixa | Pegada de cache L1D e registradores AVX2 não zerados | **Aberto** |

Esta revisão foi feita **pelo próprio projeto**. Não substitui auditoria independente.
