# Política de segurança

A RSD-S é um **protótipo de pesquisa, sem auditoria independente**. Não a use para proteger dados reais. Esta política diz como relatar falhas e o que consideramos vulnerabilidade.

## Como relatar

**Vulnerabilidades de implementação ou de cadeia de suprimentos** (corrupção de memória, vazamento de segredo, canal lateral, bypass de verificação, dependência comprometida, fluxo de CI inseguro): use o relato privado do GitHub:

**<https://github.com/daniloludgero/CryptographyBaSingSe/security/advisories/new>**

Preencha o formulário [`SECURITY-REPORT-TEMPLATE.md`](SECURITY-REPORT-TEMPLATE.md). Sem formulário, não conseguimos classificar o relato de modo formal. **Não abra issue pública** para esse tipo de falha antes do prazo de divulgação.

**Achados contra a própria construção criptográfica** (um ataque a rodadas reduzidas, um distinguidor, um invariante estrutural): são **bem-vindos como issue pública**, com o modelo "Cryptanalysis finding". A RSD-S é um objeto de pesquisa e o projeto se beneficia de ataque aberto. Veja [`docs/DESAFIO.md`](docs/DESAFIO.md).

## Severidade

| Nível | Critério | Exemplo |
|---|---|---|
| **Crítica** | Recupera chave, ou quebra a saída de 8 rodadas, em custo menor que a busca exaustiva, com a implementação de referência | Recuperação de `s` a partir de saídas públicas |
| **Alta** | Contorna uma proteção declarada (Anti-DFA, tempo constante) ou permite corrupção de memória | Falha injetada passa sem detecção |
| **Média** | Expõe estado interno ou reduz uma margem declarada sem quebrar a primitiva | API devolve estado secreto |
| **Baixa** | Defeito de higiene, documentação enganosa sobre segurança, pegada de implementação | Registradores não zerados |

## O que **não** consideramos vulnerabilidade

Estes pontos são **limites já declarados**, não falhas:

- ataques a **rodadas reduzidas** (1 a 3 rodadas), já documentados em [`docs/evidencia/COBERTURA_DE_CRIPTOANALISE.md`](docs/evidencia/COBERTURA_DE_CRIPTOANALISE.md);
- o fato de a primitiva **não ter auditoria, prova ou validação FIPS** ([`GARANTIAS_E_LIMITES.md`](docs/evidencia/GARANTIAS_E_LIMITES.md));
- limite de característica única, resultado de avalanche ou de teste estatístico "não provar" segurança;
- o risco de reprodutibilidade numérica do `float64` na construção da matriz `B`, já documentado na especificação;
- reuso de `n_sess` com a mesma chave em modos que o contrato proíbe;
- ataques que exigem acesso físico, depuração ou execução de código na mesma máquina e já descritos como fora de escopo no [modelo de ameaça](docs/evidencia/OBJETIVO_E_MODELO_DE_AMEACA.md).

## Prazos

**Não prometemos prazo de resposta, de correção nem de divulgação.** O projeto é novo, mantido por uma pessoa e é um protótipo de pesquisa; não há compromisso de atendimento, e nada aqui constitui acordo de nível de serviço.

- Lemos todo relato e respondemos quando for possível.
- A divulgação é combinada caso a caso com quem relatou. Pedimos que não divulgue publicamente uma falha de implementação sem antes combinar conosco um prazo razoável.
- Achados confirmados são publicados com severidade, status e data, **com crédito a quem relatou**, se a pessoa quiser.

## Proteção a quem relata de boa-fé

Se você agir de boa-fé, testar apenas o seu próprio ambiente e este repositório, não acessar dados de terceiros e nos der tempo razoável para corrigir antes de divulgar, a nossa intenção é **não tomar medidas legais** contra você por causa da pesquisa. Isto é uma declaração de intenção, não uma garantia nem uma autorização para testar sistemas de terceiros.

## Versões com suporte

| Versão | Situação |
|---|---|
| 0.6.x (RSD-S v5.2) | Recebe correções |
| 0.5.x e anteriores | Sem suporte. Publicadas antes desta política |
