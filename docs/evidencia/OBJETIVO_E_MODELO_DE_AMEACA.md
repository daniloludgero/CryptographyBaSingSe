# Objetivo e modelo de ameaça

Este documento diz **o que a RSD-S pretende ser**, contra quem e sob quais condições. Sem isso, nenhum número de teste tem significado.

## O que a RSD-S pretende ser

Uma **função pseudoaleatória chaveada** (PRF) e, a partir dela, uma ferramenta de **derivação de chaves** (KDF) e um **compromisso simétrico verificável**:

- `F_s(x, y, n_sess)`: com chave secreta `s` (32 B), entradas `x, y` em `F_p` (`p = 2^255 - 19`) e contador de sessão `n_sess`, produz 32 ou 64 bytes que, sem `s`, devem ser indistinguíveis de aleatórios.
- **Módulo de dupla chave (SIV)**: produz uma saída pública `Y_pub` de que quem tem `(s, n_sess)` consegue verificar a origem, e que não revela o estado privado.

## O que a RSD-S **não** é

- **Não é cifra, nem AEAD.** Não há operação de decifração, nem autenticação de mensagem definida.
- **Não é KEM nem PKE.** O módulo de dupla chave não suporta encapsulamento: o relatório do Lote A tentou e refutou isso (decapsulação no nível do acaso).
- **Não é função de hash pública sem chave** para uso geral, nem assinatura.
- **Não é um padrão** e não substitui AES, ChaCha20 ou SHA-2/SHA-3.

## Ativos protegidos

| Ativo | Proteção pretendida |
|---|---|
| Chave `s` | Não deve ser recuperável a partir de saídas |
| Estado privado pós-SPN (`S_priv`) | Não deve ser inferido de `Y_pub` |
| Saída de `F_s` | Indistinguível de aleatória sem `s` |

## Modelos de adversário

| Modelo | O que o adversário faz |
|---|---|
| **Clássico** | Escolhe entradas, vê saídas, tem tempo e memória limitados |
| **Quântico offline (Q1)** | Computa quanticamente, mas consulta o oráculo **classicamente** |
| **Quântico com sessão clássica (Q2)** | Pode consultar o oráculo em **superposição** sobre parte da entrada |
| **Canal lateral** | Mede tempo, cache ou falhas na implementação |

As definições formais estão no [rascunho QROM](../../especificacao/REDUCAO_QROM_RASCUNHO_V5_1.md), que é condicional e pendente de atualização.

## Suposições de uso

1. A chave `s` é secreta e uniformemente aleatória.
2. Para o módulo de dupla chave, `n_sess` **não deveria** se repetir com a mesma chave. A construção SIV (v5.1) existe para **limitar o dano** do reuso: na v5.0 o reuso permitia recuperar a diferença entre dois estados privados, e a correção foi verificada empiricamente, sem prova formal.
3. A implementação roda em ambiente sem acesso físico do adversário.

## Fora de escopo

- Ataques com acesso físico, injeção de falha coordenada nos dois fluxos do Anti-DFA, e execução de código do adversário na mesma máquina.
- Uso em protocolos reais: nenhum protocolo foi projetado ou analisado.
- Segurança pós-quântica: o projeto afirma apenas que **não se baseia nos problemas atacados por Shor**.

## Alvo numérico de segurança

**Não declarado nesta versão.** Declarar um número (por exemplo, "128 bits") sem revisão externa e sem prova seria uma alegação que o projeto não consegue sustentar. Os limites genéricos (Grover, BHT) estão na [especificação](../../especificacao/ESPECIFICACAO_V5_2.md), seção 4, e não são garantia da construção.
