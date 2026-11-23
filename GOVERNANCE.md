# Governança

## Modelo

O BaSingSe é mantido por uma pessoa: o autor e titular, **Danilo Ludgero**. As decisões finais de especificação, licenciamento, versões e marca são dele. Este documento diz como as decisões são tomadas e o que você pode esperar.

Não prometemos comitê, votação nem número mínimo de mantenedores. Se o projeto crescer, esta página será atualizada **antes** de qualquer mudança de poder.

## Decisões do dia a dia

Correções, ferramentas de análise, testes e documentação são decididos pelo autor em revisão de PR. Pedimos 72 horas de espera, quando possível, para que haja tempo de objeção técnica fundamentada.

## Mudanças no contrato criptográfico

Qualquer mudança que altere o formato do estado, a S-box, a matriz MDS, as chaves de rodada, o número de rodadas ou os vetores congelados segue este rito:

1. **Proposta** em issue, com a motivação matemática, o impacto nos limites de wide-trail e nos testes SAT/SMT, e os novos vetores.
2. **Período público de ataque** de pelo menos 14 dias.
3. **Decisão** do autor, registrada na issue com a justificativa. Objeção técnica reproduzível (contraexemplo, regressão ou alternativa concreta) obriga resposta pública.
4. **Nova versão** da primitiva, com vetores novos. Os vetores antigos permanecem.

## Licenciamento

Somente o autor concede licenças comerciais. Contribuições seguem o [`CLA.md`](CLA.md).

## Segurança operacional

- Quem tiver permissão de escrita ou de release deve usar autenticação em dois fatores.
- Tags de versão são criadas e verificadas pela CI, que roda os vetores antes de publicar.
- Ações de CI são fixadas por SHA de commit, e o Dependabot propõe atualizações.

## Sucessão

Nenhum direito de licenciamento ou de marca é transferido sem ato escrito do autor. Se o autor ficar inativo por mais de 6 meses, o repositório permanece como está e as versões publicadas continuam sob a licença com que foram lançadas.
