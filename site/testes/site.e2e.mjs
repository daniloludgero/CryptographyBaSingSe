// E2E do site e do laboratório (Chromium). Roda o build, serve dist localmente e exercita a interface.
// Requisitos: playwright e axe-core (devDependencies de site/package.json) e um Chromium instalado.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';
import { subirSite, carregarPlaywright, axeFonte, lerBlocoPorPixels, DIST, SITE } from './_apoio.mjs';
import * as E from '../src/js/engine/rsd.js';
import { fromHex } from '../src/js/engine/hash.js';

const { chromium } = await carregarPlaywright();
const srv = await subirSite();
const browser = await chromium.launch();
test.after(async () => { await browser.close(); await srv.fechar(); });

const PAGINAS = [['pt', ''], ['pt', 'lab/'], ['en', 'en/'], ['en', 'en/lab/']];
const novaPagina = async (opts = {}) => {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, ...opts });
  const page = await ctx.newPage();
  const problemas = [];
  page.on('pageerror', (e) => problemas.push('erro de página: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') problemas.push('console: ' + m.text()); });
  page.on('requestfailed', (r) => problemas.push('requisição falhou: ' + r.url()));
  return { ctx, page, problemas };
};
const abrirLab = async (page, caminho = 'lab/') => {
  await page.goto(srv.url + caminho, { waitUntil: 'networkidle' });
  await page.waitForSelector('html[data-lab-pronto]', { timeout: 15000 });
};

// ---------------------------------------------------------------------------------------------
test('rede: nenhuma requisição sai do próprio servidor, em nenhuma das 4 páginas', async () => {
  for (const [, caminho] of PAGINAS) {
    const { ctx, page, problemas } = await novaPagina();
    const externos = [];
    page.on('request', (r) => { if (!r.url().startsWith(srv.url) && !r.url().startsWith('data:') && !r.url().startsWith('blob:')) externos.push(r.url()); });
    await page.goto(srv.url + caminho, { waitUntil: 'networkidle' });
    assert.deepEqual(externos, [], `${caminho}: requisições externas`);
    assert.deepEqual(problemas, [], `${caminho}: erros`);
    await ctx.close();
  }
});

test('estático: nenhum recurso externo declarado nos HTML (src, srcset, href de folha de estilo ou script)', () => {
  for (const [, caminho] of PAGINAS) {
    const html = readFileSync(join(DIST, caminho, 'index.html'), 'utf8');
    const recursos = [...html.matchAll(/<(?:script|img|source|link)\b[^>]*?(?:src|srcset|href)="(https?:)?\/\/[^"]*"/g)]
      .filter((m) => !/rel="(canonical|alternate)"/.test(m[0]));
    assert.deepEqual(recursos.map((m) => m[0]), [], caminho);
    assert.ok(!/style="/.test(html), `${caminho}: atributo style inline violaria a CSP`);
    assert.ok(!/<script(?![^>]*\bsrc=)(?![^>]*type="application\/json")[^>]*>/.test(html), `${caminho}: script inline`);
    assert.match(html, /Content-Security-Policy/);
  }
});

test('idioma: cada página declara o lang certo e aponta para a alternativa', () => {
  const esperado = { '': 'pt-BR', 'lab/': 'pt-BR', 'en/': 'en', 'en/lab/': 'en' };
  for (const [caminho, lang] of Object.entries(esperado)) {
    const html = readFileSync(join(DIST, caminho, 'index.html'), 'utf8');
    assert.match(html, new RegExp(`<html lang="${lang}"`));
    assert.match(html, /hreflang="pt-BR"/); assert.match(html, /hreflang="en"/);
  }
});

test('i18n: dicionários com as mesmas chaves e nenhuma chave usada no código ficou sem tradução', () => {
  const pt = { ...JSON.parse(readFileSync(join(SITE, 'src/i18n/pt.json'), 'utf8')), ...JSON.parse(readFileSync(join(SITE, 'src/i18n/pt-lab.json'), 'utf8')) };
  const en = { ...JSON.parse(readFileSync(join(SITE, 'src/i18n/en.json'), 'utf8')), ...JSON.parse(readFileSync(join(SITE, 'src/i18n/en-lab.json'), 'utf8')) };
  assert.deepEqual(Object.keys(pt).sort(), Object.keys(en).sort());
  const usadas = new Set();
  for (const f of ['lab.js', 'ui.js']) {
    const s = readFileSync(join(SITE, 'src/js', f), 'utf8');
    for (const m of s.matchAll(/\bt\(\s*'([a-z0-9_]+)'/g)) usadas.add(m[1]);
    for (const m of s.matchAll(/\?\s*'([a-z0-9_]+)'\s*:\s*'([a-z0-9_]+)'/g)) { usadas.add(m[1]); usadas.add(m[2]); }
    for (const m of s.matchAll(/t\(\{([^}]*)\}/g)) for (const k of m[1].matchAll(/'([a-z0-9_]+)'/g)) usadas.add(k[1]);
  }
  const tpl = readFileSync(join(SITE, 'src/paginas/lab.html'), 'utf8') + readFileSync(join(SITE, 'src/paginas/index.html'), 'utf8');
  for (const m of tpl.matchAll(/\{\{t:(\w+)\}\}/g)) usadas.add(m[1]);
  const candidatas = [...usadas].filter((k) => /_/.test(k) && !/^(sev|estado)_/.test(k) && !['data_i'].includes(k));
  const faltam = candidatas.filter((k) => !(k in pt)).filter((k) => /^(lab|modo|sessao|erro|rod|rot|bloco|byte|painel|conf|palpite|exp|chaves|rc|feixe|poco|sent|kat|cerco|cercos|origem|rotulacao|resumo|nojs|alc|atq|gar|corr|oq|heroi|rodape|nav|aviso|tema|lic)_/.test(k));
  assert.deepEqual(faltam, []);
});

test('vocabulário: nenhuma afirmação proibida pelo plano (segurança absoluta, militar, pós-quântico, etc.)', () => {
  const proibidos = [/inquebr/i, /unbreak/i, /\bmilitar/i, /military/i, /à prova de/i, /bulletproof/i, /100 ?% (seguro|secure)/i,
    /pronto para produção/i, /production[- ]ready/i, /invenc[ií]vel/i, /invincible/i, /\bvencemos\b/i, /\bwe won\b/i];
  const arquivos = [...PAGINAS.map(([, c]) => join(DIST, c, 'index.html')), ...['pt', 'en', 'pt-lab', 'en-lab'].map((n) => join(SITE, `src/i18n/${n}.json`))];
  for (const f of arquivos) {
    const txt = readFileSync(f, 'utf8');
    for (const re of proibidos) assert.ok(!re.test(txt), `${f}: ${re}`);
    // "open source" e "pós-quântico" só podem aparecer negados
    for (const m of txt.matchAll(/.{0,60}(open[- ]source|p[óo]s-qu[âa]ntic\w*|post-quantum).{0,40}/gi)) {
      assert.match(m[0], /(n[ãa]o|not|does not|nunca|never)/i, `${f}: uso sem negação -> ${m[0]}`);
    }
  }
});

// ---------------------------------------------------------------------------------------------
test('lab: Explorar e Verificar mostram os mesmos números, iguais aos do motor (caso do projeto)', async () => {
  const { ctx, page, problemas } = await novaPagina();
  await abrirLab(page);
  const sch = E.schedule(Uint8Array.from({ length: 32 }, (_, i) => i), 1n, 8);
  const A = E.core(E.fragment(1n, 2n), sch), B = E.core(E.fragment(0n, 2n), sch);
  const st = E.diffStats(A.trace[1], B.trace[1]);
  const ler = async () => ({ pal: await page.textContent('#m-pal'), bits: await page.textContent('#m-bits') });
  await page.click('#modo-explorar');
  const ex = await ler();
  await page.click('#modo-verificar');
  const ve = await ler();
  assert.deepEqual(ex, ve);
  assert.equal(ve.pal.trim(), `${st.words} / 32`);
  assert.equal(ve.bits.trim(), `${st.bits} / 512`);
  assert.equal(st.bits, 264);
  await page.click('#grade-a button[data-i="0"]');
  assert.match(await page.textContent('#painel-palavra'), /0xd626/);
  assert.deepEqual(problemas, []);
  await ctx.close();
});

test('lab: os pixels desenhados reconstroem o valor exato de cada palavra (claro e escuro, 32 blocos)', async () => {
  const sch = E.schedule(Uint8Array.from({ length: 32 }, (_, i) => i), 1n, 8);
  const A = E.core(E.fragment(1n, 2n), sch);
  for (const esquema of ['light', 'dark']) {
    const { ctx, page } = await novaPagina({ colorScheme: esquema, deviceScaleFactor: 2 });
    await abrirLab(page);
    for (let i = 0; i < 32; i++) {
      const lido = await lerBlocoPorPixels(page, `#grade-a button[data-i="${i}"] svg`);
      assert.equal(lido, A.trace[1][i], `${esquema}: bloco ${i} -> 0x${lido.toString(16)}`);
    }
    await ctx.close();
  }
});

test('lab: missão do Feixe: 1R e 2R distinguem (32 poços parados), 3R não (0 parados)', async () => {
  const { ctx, page, problemas } = await novaPagina();
  await abrirLab(page);
  const parados = async (r) => {
    await page.click(`#feixe-rodadas button[data-r="${r}"]`);
    await page.click('#feixe-disparar');
    await page.waitForFunction(() => document.querySelectorAll('#pocos .poco').length === 32, null, { timeout: 60000 });
    return page.locator('#pocos .parado').count();
  };
  assert.equal(await parados(2), 32);
  assert.match(await page.textContent('#feixe-veredito'), /distingue/);
  assert.equal(await parados(3), 0);
  assert.match(await page.textContent('#feixe-veredito'), /n[ãa]o distingue/);
  assert.equal(await page.locator('#pocos .ondulado').count(), 32);
  assert.deepEqual(problemas, []);
  await ctx.close();
});

test('lab: o feixe pode ser cancelado e a página não trava', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  await page.click('#feixe-rodadas button[data-r="8"]');
  await page.click('#feixe-disparar');
  await page.click('#feixe-cancelar');
  assert.equal(await page.isEnabled('#feixe-disparar'), true);
  assert.match(await page.textContent('#feixe-resultado'), /cancelado/i);
  await ctx.close();
});

test('lab: sentinelas detectam falha só em A em todas as rodadas, e mostram os limites', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  for (let r = 1; r <= 8; r++) {
    await page.selectOption('#sent-modo', 'A');
    await page.selectOption('#sent-rodada', String(r));
    await page.click('#sent-executar');
    assert.match(await page.textContent('#sent-resultado'), /ALARME/, `rodada ${r}`);
  }
  for (const modo of ['ambos', 'antes']) {
    await page.selectOption('#sent-modo', modo);
    await page.click('#sent-executar');
    const txt = await page.textContent('#sent-resultado');
    assert.match(txt, /Sem alarme/); assert.match(txt, /difere da correta/);
  }
  await ctx.close();
});

test('lab: pergaminhos: os 6 vetores conferem; adulterar 1 caractere faz o selo falhar', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  const nomes = await page.locator('#kat-lista button').count();
  assert.equal(nomes, 6);
  for (let i = 0; i < nomes; i++) {
    await page.locator('#kat-lista button').nth(i).click();
    assert.equal(await page.locator('#kat-quadro .tag.ok').count(), 3, `vetor ${i}`);
    await page.click('#kat-adulterar');
    assert.equal(await page.locator('#kat-quadro .tag.alta').count(), 3, `vetor ${i} adulterado`);
    await page.click('#kat-restaurar');
  }
  await ctx.close();
});

test('lab: entrada inválida mostra o erro do contrato e não quebra a página', async () => {
  const { ctx, page, problemas } = await novaPagina();
  await abrirLab(page);
  await page.click('#modo-verificar');
  await page.fill('#campo-x', '57896044618658097711785492504343953926634992332820282019728792003956564819949'); // = p
  await page.click('#form-sessao button[type="submit"]');
  assert.match(await page.textContent('#erros-sessao'), /2\^255/);
  await page.fill('#campo-x', '7');
  await page.fill('#campo-chave', '00ff');
  await page.click('#form-sessao button[type="submit"]');
  assert.match(await page.textContent('#erros-sessao'), /64 d[ií]gitos/);
  await page.fill('#campo-chave', '00'.repeat(32));
  await page.fill('#campo-rodadas', '3');
  await page.click('#form-sessao button[type="submit"]');
  assert.equal((await page.textContent('#erros-sessao')).trim(), '');
  assert.equal(await page.locator('#momento').getAttribute('max'), '3');
  assert.deepEqual(problemas, []);
  await ctx.close();
});

test('lab: livro de cercos recalcula ao vivo os achados que podem ser refeitos', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  const clicar = async (id) => { await page.locator(`#cerco-${id} button`).click(); return (await page.textContent(`#cerco-${id} .resultado-cerco`)).trim(); };
  assert.match(await clicar('rt-f1-01'), /Em 9 de 9 chaves/);
  assert.match(await clicar('rt-f1-03'), /0x1731/);
  assert.match(await clicar('rt-f1-02'), /acendeu em 0\./);
  assert.match(await clicar('rt-f2-01'), /sentinelas/i);
  assert.equal(await page.locator('#cercos-lista article').count(), 9);
  assert.equal(await page.locator('#cercos-lista article:not(:has(button))').count(), 5); // os que não são recalculados dizem isso
  await ctx.close();
});

test('lab: teclado: setas movem o foco entre blocos e Enter abre o painel', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  await page.focus('#grade-a button[data-i="0"]');
  await page.keyboard.press('ArrowRight');
  assert.equal(await page.evaluate(() => document.activeElement.dataset.i), '1');
  await page.keyboard.press('ArrowDown');
  assert.equal(await page.evaluate(() => document.activeElement.dataset.i), '9');
  await page.keyboard.press('End');
  assert.equal(await page.evaluate(() => document.activeElement.dataset.i), '31');
  await page.keyboard.press('Enter');
  assert.match(await page.textContent('#painel-palavra'), /Palavra 31/);
  await ctx.close();
});

test('lab: o link compartilhado não carrega a chave por padrão e restaura a entrada', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  const frag = await page.evaluate(() => location.hash);
  assert.ok(!/[?&#]k=/.test(frag), frag);
  await page.goto(srv.url + 'lab/#x=5&y=6&n=9&r=4&bit=300&o=64', { waitUntil: 'networkidle' });
  await page.waitForSelector('html[data-lab-pronto]');
  assert.match(await page.textContent('#resumo-sessao'), /x = 5 · y = 6 · sessão = 9 · 4 rodadas · bit invertido #300 \(y\[45\]\)/);
  await ctx.close();
});

// ---------------------------------------------------------------------------------------------
test('sem JavaScript: a página inicial e o laboratório mostram os resultados calculados no build', async () => {
  const ctx = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(srv.url, { waitUntil: 'load' });
  assert.equal(await page.locator('.painel-duplo .bloco').count(), 64);
  assert.match(await page.textContent('main'), /264/);
  await page.goto(srv.url + 'lab/', { waitUntil: 'load' });
  assert.ok(await page.locator('.sem-js-aviso').isVisible());
  assert.ok(await page.locator('#cercos table').isVisible());
  assert.ok(await page.locator('#feixe table').isVisible());
  assert.ok(await page.locator('#alcance table').isVisible());
  assert.equal(await page.locator('#cercos-lista').isVisible(), false);
  await ctx.close();
});

test('movimento reduzido: sem animações, e o laboratório funciona', async () => {
  const { ctx, page, problemas } = await novaPagina({ reducedMotion: 'reduce' });
  await abrirLab(page);
  const anim = await page.evaluate(() => [...document.querySelectorAll('*')].filter((e) => { const s = getComputedStyle(e); return (s.animationName !== 'none' && s.animationDuration !== '0s') || (s.transitionDuration !== '0s' && s.transitionProperty !== 'none'); }).length);
  assert.equal(anim, 0);
  await page.click('#feixe-rodadas button[data-r="1"]');
  await page.click('#feixe-disparar');
  await page.waitForFunction(() => document.querySelectorAll('#pocos .parado').length === 32, null, { timeout: 60000 });
  assert.deepEqual(problemas, []);
  await ctx.close();
});

test('responsivo: sem rolagem horizontal da página em 320, 360 e 1280 px (claro e escuro)', async () => {
  for (const largura of [320, 360, 1280]) for (const esquema of ['light', 'dark']) for (const [, caminho] of PAGINAS) {
    const { ctx, page } = await novaPagina({ viewport: { width: largura, height: 800 }, colorScheme: esquema });
    await page.goto(srv.url + caminho, { waitUntil: 'networkidle' });
    const [sw, iw] = await page.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth]);
    assert.ok(sw <= iw, `${caminho} em ${largura}px (${esquema}): scrollWidth ${sw} > ${iw}`);
    await ctx.close();
  }
});

test('alvos de toque: botões e campos interativos têm pelo menos 44 px de altura (exceto blocos da grade)', async () => {
  const { ctx, page } = await novaPagina({ viewport: { width: 360, height: 800 } });
  await abrirLab(page);
  await page.click('#modo-verificar');
  const pequenos = await page.evaluate(() => [...document.querySelectorAll('button:not(.bloco), input:not([type=checkbox]):not([type=range]), select, summary')]
    .filter((e) => e.offsetParent !== null && e.getBoundingClientRect().height < 43.5).map((e) => (e.id || e.textContent.trim().slice(0, 20)) + ':' + Math.round(e.getBoundingClientRect().height)));
  assert.deepEqual(pequenos, []);
  await ctx.close();
});

// ---------------------------------------------------------------------------------------------
async function rodarAxe(page) {
  await page.evaluate(axeFonte());
  return page.evaluate(async () => {
    const r = await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] } });
    return r.violations.map((v) => ({ id: v.id, impacto: v.impact, n: v.nodes.length, ajuda: v.help, alvos: v.nodes.slice(0, 3).map((n) => n.target.join(' ') + ' :: ' + (n.failureSummary || '').split('\n').slice(1, 3).join(' | ')) }));
  });
}
test('acessibilidade (axe): sem violações em nenhuma página, nos dois temas e nos dois modos', async () => {
  const falhas = [];
  for (const esquema of ['light', 'dark']) for (const [, caminho] of PAGINAS) for (const modo of caminho.includes('lab') ? ['explorar', 'verificar'] : ['-']) {
    const { ctx, page } = await novaPagina({ colorScheme: esquema });
    await page.goto(srv.url + caminho, { waitUntil: 'networkidle' });
    if (caminho.includes('lab')) {
      await page.waitForSelector('html[data-lab-pronto]');
      await page.click(modo === 'verificar' ? '#modo-verificar' : '#modo-explorar');
      await page.click('#grade-a button[data-i="3"]');
      await page.fill('#esperado', 'abcd');
      await page.click('#feixe-disparar');
      await page.waitForFunction(() => document.querySelectorAll('#pocos .poco').length === 32, null, { timeout: 60000 });
      await page.click('#sent-executar');
      await page.locator('#cercos-lista article button').first().click();
    }
    for (const v of await rodarAxe(page)) falhas.push(`${esquema} ${caminho} ${modo}: [${v.impacto}] ${v.id} (${v.n}) ${v.ajuda} -> ${v.alvos.join(' // ')}`);
    await ctx.close();
  }
  assert.deepEqual(falhas, []);
});

// ---------------------------------------------------------------------------------------------
const gz = (f) => gzipSync(readFileSync(f)).length;
function arquivos(dir) {
  return readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? arquivos(p) : [p]; });
}
test('orçamentos: JS, HTML+CSS e arte dentro dos limites do plano', () => {
  const js = arquivos(join(DIST, 'js')).reduce((a, f) => a + gz(f), 0);
  assert.ok(js <= 120 * 1024, `JS gzip ${js} B > 120 KiB`);
  const css = gz(join(DIST, 'css/site.css'));
  for (const [, c] of PAGINAS) {
    const html = gz(join(DIST, c, 'index.html'));
    assert.ok(html + css <= 60 * 1024, `${c}: HTML+CSS gzip ${html + css} B > 60 KiB`);
  }
  const arte = arquivos(join(DIST, 'assets')).filter((f) => /cena-.*semtexto|lockup-V1-horizontal-.*4x|favicon-32/.test(f)).reduce((a, f) => a + statSync(f).size, 0);
  assert.ok(arte <= 400 * 1024, `arte de primeira carga ${arte} B > 400 KiB`);
  const todos = arquivos(DIST).reduce((a, f) => a + statSync(f).size, 0);
  assert.ok(todos <= 1.5 * 1024 * 1024, `site inteiro ${todos} B`);
});

// ---------------------------------------------------------------------------------------------
test('inglês: nenhuma chave de tradução crua em nenhum modo, depois de exercitar todas as seções', async () => {
  const { ctx, page, problemas } = await novaPagina();
  await abrirLab(page, 'en/lab/');
  for (const modo of ['#modo-explorar', '#modo-verificar']) {
    await page.click(modo);
    await page.click('#grade-a button[data-i="2"]');
    await page.fill('#esperado', 'zz');
    await page.fill('#esperado', '13bd');
    await page.fill('#palpite', '250').catch(() => {});
    await page.click('#revelar-palpite').catch(() => {});
    await page.click('#feixe-disparar');
    await page.waitForFunction(() => document.querySelectorAll('#pocos .poco').length === 32, null, { timeout: 60000 });
    await page.selectOption('#sent-modo', 'antes');
    await page.click('#sent-executar');
    await page.click('#kat-adulterar');
    for (const b of await page.locator('#cercos-lista article button').all()) await b.click();
    const cru = await page.evaluate(() => (document.body.innerText.match(/⟦[^⟧]*⟧/g) || []));
    assert.deepEqual(cru, [], modo);
  }
  assert.deepEqual(problemas, []);
  await ctx.close();
});

test('feixe: o mosaico mostra dados reais (não é uma cor uniforme) e a explicação dos distintos bate com o cálculo', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  await page.click('#feixe-rodadas button[data-r="2"]');
  await page.click('#feixe-disparar');
  await page.waitForFunction(() => document.querySelectorAll('#pocos .poco').length === 32, null, { timeout: 60000 });
  const cores = await page.evaluate(() => {
    const d = document.getElementById('mosaico').getContext('2d').getImageData(0, 0, 256, 256).data;
    const s = new Set(); for (let i = 0; i < d.length; i += 4) s.add((d[i] << 16) | (d[i + 1] << 8) | d[i + 2]);
    return s.size;
  });
  assert.equal(cores, 4); // as 4 tonalidades da paleta, uma por valor de 2 bits da saída
  assert.match(await page.textContent('#feixe-resultado'), /0 das 32 palavras de sa[ií]da s[ãa]o permuta/);
  await page.click('#feixe-rodadas button[data-r="1"]');
  await page.click('#feixe-disparar');
  await page.waitForFunction(() => /32 das 32/.test(document.getElementById('feixe-resultado').textContent), null, { timeout: 60000 });
  await ctx.close();
});

test('feixe: os poços "parados" (a defesa cedeu) não usam verde, e o veredito usa texto e ícone', async () => {
  const { ctx, page } = await novaPagina();
  await abrirLab(page);
  await page.click('#feixe-rodadas button[data-r="1"]');
  await page.click('#feixe-disparar');
  await page.waitForFunction(() => document.querySelectorAll('#pocos .poco').length === 32, null, { timeout: 60000 });
  const cor = await page.evaluate(() => getComputedStyle(document.querySelector('#pocos .parado')).borderTopColor);
  const [r, g, b] = cor.match(/\d+/g).map(Number);
  assert.ok(!(g > r && g > b), `borda verde: ${cor}`);
  assert.match(await page.textContent('#feixe-veredito'), /▲/);
  await ctx.close();
});
