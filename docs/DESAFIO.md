# Desafio público: ataque a RSD-S

> **A muralha se prova, quando exposta ao fogo.** A RSD-S só ganha credibilidade se for atacada. Este documento diz como atacar e como relatar.

Não há prêmio em dinheiro. O que o projeto oferece é **crédito público e permanente** a quem produzir um resultado reproduzível.

## Alvos

Use a referência em Python como oráculo, com chave e sessão escolhidas por você:

```python
import sys; sys.path.insert(0, "implementacao")
from rsd_s_v5_hardened import diffuse_rsd_s_v5_pre_sha
estado = diffuse_rsd_s_v5_pre_sha(x, y, chave_32_bytes, n_sess, rounds=4)
```

| Nível | Alvo | Situação |
|---|---|---|
| **A** | Distinguidor ou recuperação de subchave em **até 3 rodadas** | Já feito pelo projeto (Lote B). Reproduzir e **reduzir o custo** conta |
| **B** | Recuperação de subchave ou distinguidor em **4 rodadas** | Aberto |
| **C** | Distinguidor em **5 a 7 rodadas** | Aberto |
| **D** | Qualquer ataque de **custo menor que a busca exaustiva** em **8 rodadas** | Aberto. Seria um achado de severidade Crítica |
| **E** | Falha de implementação: C99, Python, módulo de dupla chave | Siga o [`SECURITY.md`](../SECURITY.md) |

## O que é um resultado válido

1. **Reproduzível**: um script que roda a partir da raiz do repositório e imprime o resultado.
2. **Com custo declarado**: número de consultas, tempo, memória, ambiente.
3. **Com modelo explícito**: chaves conhecidas ou desconhecidas, entradas escolhidas ou conhecidas, uma ou várias chaves.
4. **Honesto sobre a incerteza**: *timeouts* de solver são **inconclusivos**. Um bom resultado negativo também vale.

## Como relatar

- Ataque à construção: issue pública com o modelo **Cryptanalysis finding**.
- Falha de implementação: relato privado, conforme o [`SECURITY.md`](../SECURITY.md).

## Crédito

Resultados confirmados são acrescentados a [`docs/evidencia/COBERTURA_DE_CRIPTOANALISE.md`](evidencia/COBERTURA_DE_CRIPTOANALISE.md) e às notas de versão, com o nome de quem os produziu (ou "anônimo", se preferir).

## Regras do jogo

- Teste apenas **as suas próprias instâncias** e este repositório.
- Não tente o repositório, a conta do autor ou a infraestrutura do GitHub.
- Ao reportar, seguimos o princípio de boa-fé do [`SECURITY.md`](../SECURITY.md).
