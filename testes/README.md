# Testes do RSD-S

Os testes automatizados usam apenas `unittest` da biblioteca padrão, além do
NumPy já exigido pela implementação.

## Suíte rápida e determinística

Execute a partir da raiz do pacote:

```bash
python3 -m unittest discover -s testes -p "test_*.py" -v
```

Essa suíte verifica contrato de entrada, vetores de resposta conhecida,
determinismo, fragmentação, separação entre chave/sessão e avalanche com
chave fixa.

## Suíte estatística original

```bash
python3 testes/suite_testes_completa.py
```

## Análises adicionais

```bash
python3 testes/teste_branch_number.py
python3 testes/teste_diferencial.py
python3 testes/teste_linear.py
python3 testes/teste_trilha_diferencial_completa.py
python3 implementacao/analise_wide_trail.py
python3 testes/analise_rodadas.py --trials 18 --rounds 4 6 8 10
python3 ferramentas/prova_ddt_smt.py
python3 implementacao/analise_trilhas_concretas.py
python3 implementacao/mds_bitmatrix.py
python3 implementacao/mds_xor_synthesis.py
python3 implementacao/gf16_inverse_cnf.py
python3 implementacao/rsd_round_cnf.py
python3 implementacao/rsd_differential_cnf.py
python3 implementacao/analise_duas_rodadas.py
python3 implementacao/busca_branch_bound.py
python3 implementacao/busca_diversificada.py
```

Os testes diferencial e linear da S-box são amostrais quanto às diferenças
ou máscaras escolhidas, embora cada escolha percorra exaustivamente as 65.536
entradas. A busca de trilhas também é empírica e não substitui uma busca
formal por MILP, SAT ou SMT. A configuração completa da busca de trilhas é
intencionalmente demorada na implementação Python.

`analise_wide_trail.py` produz um limite conservador para características
individuais a partir do branch number e das cotas da S-box. A fórmula é
conferida por programação dinâmica no modelo relaxado de pesos de palavra.
Ela não soma trilhas nem substitui um modelo de valores diferenciais.

A rede sintetizada da MDS está em `ferramentas/mds_512.cnf`. Ela contém apenas
o componente linear; ainda não é um modelo CNF completo das rodadas.

A primeira rodada funcional completa está em
`ferramentas/rsd_round1_fixed.cnf`; os arquivos `*_kat_sat.cnf` e
`*_kat_unsat.cnf` verificam um vetor conhecido correto e um incorreto.

As consultas diferenciais compactas estão em
`ferramentas/rsd_diff_round1_compact_*.cnf`; a correta é SAT e o controle com
um bit de diferença alterado é UNSAT.

A análise concreta das quatro testemunhas máximas por quatro rodadas está em
`implementacao/analise_duas_rodadas.py`.

A busca ampliada e reproduzível está em
`implementacao/busca_branch_bound.py`; ela é amostral e não prova ótimo global.

A busca diversificada em `implementacao/busca_diversificada.py` acrescenta
quatro fundos determinísticos e testemunhas DDT de contagem 2. Sua execução
completa também é amostral e mantém a mesma ressalva de não provar ótimo.

O Z3 está instalado de forma isolada em `ferramentas/_vendor`. Após a
otimização booleana, o modelo global experimental retorna `sat` para uma
rodada; duas rodadas ainda podem retornar `unknown` por timeout.

## Contrato da API v4

- `x` e `y`: inteiros em `0 <= valor < 2^255 - 19`;
- `s`: objeto `bytes` com exatamente 32 bytes;
- `n_sess`: inteiro em `0 <= valor < 2^64`;
- saída pública: 32 bytes.

Entradas fora desse contrato geram `TypeError` ou `ValueError`; não são
reduzidas nem truncadas silenciosamente.

## Campanhas R3 a R5 (mais lentas)

Os módulos `test_r3_*`, `test_r4_*` e `test_r5_*` reproduzem as campanhas de criptoanálise e levam vários minutos (a R5 leva cerca de 8). Eles exigem `scipy` (`pip install scipy`) e `gcc`, e gravam relatórios em `resultados/`. Rode-os com `python3 -m pytest testes/test_r5_m1_hardened_margin.py` (e semelhantes).

## Medições da v5.2

A latência, o TVLA, a paridade C99 × Python, o ataque Square de 3 rodadas e o comparativo linear com o AES têm roteiro próprio, que reproduz todas as medições da v5.2 em cerca de 5 minutos:

```bash
ferramentas/medicao_v52/executar_medicao.sh 2 resultados/v5_2/minha_medicao
```

Método, ambiente e limites: [`docs/evidencia/MEDICOES_V5_2.md`](../docs/evidencia/MEDICOES_V5_2.md).

## Prova das correções da v5.2

O mesmo exploit escrito contra a v5.1 roda contra o código v5.1 e contra o v5.2, em menos de um minuto. Exige `gcc` com ThreadSanitizer, `scipy` e `pytest`:

```bash
python3 ferramentas/verificacao_correcoes_v52/reproduzir.py
```

Explicação de cada achado: [`docs/evidencia/CORRECOES_V5_2.md`](../docs/evidencia/CORRECOES_V5_2.md).

## Fórmulas CNF grandes

Os arquivos `*.cnf` com mais de 1 MB não ficam na árvore do repositório. Eles são publicados como *asset* de cada release, com soma SHA-256 (veja `ferramentas/LEIAME_CNF.md`). Os geradores em `implementacao/` os recriam: `rsd_round_cnf.py`, `rsd_differential_cnf.py`, `analise_duas_rodadas.py` e `mds_xor_synthesis.py`.

## Vetores da v5.2

```bash
python3 ferramentas/rsd_cli.py kat52
python3 -m unittest testes/test_vetores_v52.py -v
```

O teste exige `gcc` para conferir a paridade Python ↔ C99; a CLI `kat52` confere só o Python.
