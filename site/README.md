# Site e laboratório (GitHub Pages)

Site estático com a página inicial e o **laboratório** da RSD-S v5.2, em português e inglês. O laboratório executa o motor no navegador do visitante: tudo o que aparece é calculado, e cada valor é conferido bit a bit contra o Python e o núcleo C do repositório.

**Endereço (depois de ativar o Pages):** <https://daniloludgero.github.io/CryptographyBaSingSe/>

## Ativar a publicação (uma vez, pelo dono)

*Settings → Pages → Build and deployment → Source: **GitHub Actions***. Depois, rode o workflow **Pages** (aba *Actions*, *Run workflow*) ou faça um commit em `main`. O workflow roda os testes do motor e só publica se a paridade com o Python passar.

## Estrutura

| Pasta | Conteúdo |
|---|---|
| `src/paginas/` | Modelos HTML (`index.html`, `lab.html`) com marcadores `{{t:chave}}` e `{{@fragmento}}` |
| `src/i18n/` | Textos em português e inglês (um dicionário por idioma; o teste exige as mesmas chaves) |
| `src/dados/` | Achados do red-team (`cercos.json`) e quadro de alcance (`alcance.json`) |
| `src/js/engine/` | Motor: SHA-256, HMAC, SHAKE256 e a RSD-S v5.2 em JavaScript puro |
| `src/js/` | `runes.js` (glifos), `lab.js` (interface), `ui.js`, `sessao.js`, `worker.js` (missão do feixe) |
| `src/css/site.css` | Tokens de design (claro e escuro) e componentes |
| `src/assets/` | Arte aprovada (cenas, logotipo, favicon) |
| `dados/` | `vetores_v52.json` (cópia dos vetores congelados) e `paridade.json` (verdade do Python e do núcleo C) |
| `ferramentas/build.mjs` | Gera `dist/`: as páginas, e as tabelas e grades estáticas calculadas pelo próprio motor |
| `ferramentas/gerar_dados.py` | Regenera `dados/paridade.json` (leva ~2 min; precisa de `gcc`) |
| `testes/` | Paridade, glifos, feixe e E2E |

## Comandos

```bash
node site/ferramentas/build.mjs              # gera site/dist
cd site && node --test "testes/*.test.js"    # motor e paridade (cerca de 15 s)
cd site && npm ci && node --test "testes/*.e2e.mjs"   # navegador (Chromium); cerca de 1 min
python3 site/ferramentas/gerar_dados.py --conferir    # os dados ainda batem com o Python e o C?
```

O E2E usa Playwright e axe-core, que são **dependências só de desenvolvimento**: nada disso vai para o site.

## O que os testes garantem

- **Paridade** (`paridade.test.js`): SHA-256, HMAC e SHAKE256 contra `hashlib`; S-box e MDS inteiras; os 6 vetores congelados da v5.2 (pré-hash, 32 B e 64 B); 300 casos aleatórios com 1 a 8 rodadas; rastro estado a estado; injeção de falha; contrato de entradas com as mesmas mensagens do Python; integral recalculado.
- **Glifos** (`runas.test.js`): as 65.536 palavras reconstroem o próprio valor lendo o pixel central de cada quadrante. O E2E repete isso nos pixels reais da tela, em claro e escuro.
- **E2E** (`site.e2e.mjs`): nenhuma requisição a terceiros; CSP sem estilo nem script inline; Explorar e Verificar com os mesmos números; as missões; os 6 vetores e a adulteração; teclado; versão sem JavaScript; movimento reduzido; 320, 360 e 1280 px; alvos de toque de 44 px; vocabulário proibido; orçamentos de peso; acessibilidade automática (axe) em 4 páginas, 2 temas e 2 modos.

## Decisões que se afastam do plano, e por quê

1. **Motor só em JavaScript.** O plano recomendava o núcleo C compilado para WebAssembly como motor de referência. Esta versão usa JavaScript com tabelas, que é necessário de qualquer forma para a missão do feixe (segundo a medição feita no planejamento, o C escalar em WebAssembly leva cerca de 7 s por conjunto de 65.536 entradas, contra cerca de 0,5 s neste motor). A confiança vem da paridade bit a bit com o Python e o C, não de ser o mesmo código. **Consequência:** o motor do navegador não é tempo constante e não substitui o núcleo C.
2. **Fontes do sistema.** Sem fontes pixel de terceiros: nenhuma requisição externa e nenhuma licença de fonte a arquivar. Os títulos usam a pilha de sistema; o logotipo é imagem desenhada.
3. **Glifos da arte aprovada.** Um bloco é uma palavra de 16 bits em 4 glifos de 4 quadrantes (dígito hexadecimal mais significativo primeiro, em ordem de leitura). O valor em texto aparece sempre **abaixo** do glifo, nunca por cima, e o sinal Δ também. Um teste de pixels pegou um selo que cobria um bit e ele foi movido.

## Missões e conteúdo que **não** estão nesta versão

Módulo de dupla chave, diferencial impossível ("Portas que nunca se abrem"), boomerang, AES no navegador e o desafio linear. O laboratório diz isso na seção "O que este site não mostra".

## Limites verificados e não verificados

- **Verificado:** Chromium (versão do Playwright 1.63), em Linux, sem rede externa. Acessibilidade automática (axe) sem violações; contraste verificado em centenas de nós por tema.
- **Não verificado:** Firefox e Safari/WebKit; celulares reais; leitores de tela (NVDA, VoiceOver, TalkBack); auditoria manual de acessibilidade; desempenho do feixe em celular. O axe automático não substitui nada disso.
- **Peso:** JS e HTML+CSS dentro dos orçamentos do plano, conferidos por teste.
- **Cultura e arte:** a revisão humana por pessoa de cada tradição continua pendente (decisão do dono).
