# Código histórico da v5.1 (vulnerável)

**Não use este código.** Ele contém os 5 achados de severidade Alta e Média corrigidos na v5.2 e existe só para que qualquer pessoa reproduza a correção com [`../reproduzir.py`](../reproduzir.py).

| Arquivo | Origem |
|---|---|
| `rsd_s_v5_ct.c` | Núcleo C99 da v5.1 |
| `rsd_s_v5_hardened.py` | Referência em Python da v5.1 |
| `bandlimited_dual_key.py` | Módulo de dupla chave da v5.1 |
| `exploits_v5_1.py` | Suíte ofensiva escrita contra a v5.1 (cada teste **passa** quando o ataque funciona) |

Só dois comentários de cabeçalho foram editados em relação ao original. O código de máquina do C99 é idêntico (conferido em `-O3 -mavx2` e `-O0`) e a árvore sintática do Python é idêntica fora das *docstrings*.
