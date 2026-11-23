#!/usr/bin/env node
// Gera site/dist a partir de site/src. Os números e as grades estáticas saem do MESMO motor que roda no
// laboratório, então a versão sem JavaScript nunca diverge do cálculo.
// Uso (da raiz do repositório): node site/ferramentas/build.mjs
import { readFileSync, writeFileSync, mkdirSync, rmSync, cpSync, existsSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as E from '../src/js/engine/rsd.js';
import { hex, fromHex } from '../src/js/engine/hash.js';
import { folhaDeGlifos, blocoSvg, byteSvg, hex4, hex2 } from '../src/js/runes.js';

const AQUI = dirname(fileURLToPath(import.meta.url));
const SITE = join(AQUI, '..');
const RAIZ = join(SITE, '..');
const SRC = join(SITE, 'src');
const DIST = join(SITE, 'dist');
const URL_SITE = 'https://daniloludgero.github.io/CryptographyBaSingSe/';
const URL_REPO = 'https://github.com/daniloludgero/CryptographyBaSingSe';
const ler = (p) => readFileSync(p, 'utf8');
const sha = (buf) => createHash('sha256').update(buf).digest('hex');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// ---------- dados e versões ----------
const dict = { pt: JSON.parse(ler(join(SRC, 'i18n/pt.json'))), en: JSON.parse(ler(join(SRC, 'i18n/en.json'))) };
for (const l of ['pt', 'en']) {
  const extra = join(SRC, `i18n/${l}-lab.json`);
  if (existsSync(extra)) Object.assign(dict[l], JSON.parse(ler(extra)));
}
const cercos = JSON.parse(ler(join(SRC, 'dados/cercos.json')));
const alcance = JSON.parse(ler(join(SRC, 'dados/alcance.json')));
const paridade = JSON.parse(ler(join(SITE, 'dados/paridade.json')));
const kats = JSON.parse(ler(join(SITE, 'dados/vetores_v52.json')));

function hashDir(dir) {
  const h = createHash('sha256');
  for (const f of readdirSync(dir).sort()) h.update(f).update(readFileSync(join(dir, f)));
  return h.digest('hex');
}
function commitCurto() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA.slice(0, 7);
  try { return execSync('git rev-parse --short HEAD', { cwd: RAIZ, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { return 'local'; }
}
const pyproject = ler(join(RAIZ, 'pyproject.toml'));
const VERSOES = {
  site: (pyproject.match(/^version\s*=\s*"([^"]+)"/m) || [])[1] || '0',
  motor: sha(Buffer.from(hashDir(join(SRC, 'js/engine')) + sha(readFileSync(join(SRC, 'js/runes.js'))))).slice(0, 16),
  spec: sha(readFileSync(join(RAIZ, 'especificacao/ESPECIFICACAO_V5_2.md'))).slice(0, 16),
  kat: sha(readFileSync(join(SITE, 'dados/vetores_v52.json'))).slice(0, 16),
  commit: commitCurto(),
};

// ---------- internacionalização ----------
const fmt = (s, v = {}) => s.replace(/\{(\w+)\}/g, (_, k) => (k in v ? v[k] : `{${k}}`));
const tFn = (lang) => (k, v) => {
  if (!(k in dict[lang])) throw new Error(`chave de tradução ausente (${lang}): ${k}`);
  return fmt(dict[lang][k], v);
};

// ---------- fragmentos calculados ----------
const CHAVE_DEMO = Uint8Array.from({ length: 32 }, (_, i) => i);
function casoDoDono() {
  const sch = E.schedule(CHAVE_DEMO, 1n, 8);
  const a = E.core(E.fragment(1n, 2n), sch), b = E.core(E.fragment(0n, 2n), sch);
  return { a: a.trace[1], b: b.trace[1], stats: E.diffStats(a.trace[1], b.trace[1]) };
}
function blocoEstatico(w, i, dif, lang) {
  const rotulo = lang === 'pt'
    ? `Palavra ${i}, valor 0x${hex4(w)}${dif ? ', difere da outra execução' : ''}`
    : `Word ${i}, value 0x${hex4(w)}${dif ? ', differs from the other execution' : ''}`;
  return `<li><div class="bloco${dif ? ' dif' : ''}" role="img" aria-label="${esc(rotulo)}">${blocoSvg(w)}<span class="hex" aria-hidden="true">${hex4(w)}</span></div></li>`;
}
function gradeEstatica(est, ref, lang) {
  return `<ul class="grade mostrar-hex-sempre">${Array.from(est, (w, i) => blocoEstatico(w, i, w !== ref[i], lang)).join('')}</ul>`;
}
function fragCasoDono(ctx) {
  const c = casoDoDono();
  const t = ctx.t;
  return `<div class="painel-duplo">
<div class="painel mostrar-hex"><h3>${t('rodada_a')}</h3>${gradeEstatica(c.a, c.b, ctx.lang)}</div>
<div class="painel mostrar-hex"><h3>${t('rodada_b')}</h3>${gradeEstatica(c.b, c.a, ctx.lang)}</div>
</div>
<p class="metrica-linha"><strong>${t('rodada_momento')}.</strong> ${t('rodada_resultado', { palavras: `<strong class="num">${c.stats.words}</strong>`, bits: `<strong class="num">${c.stats.bits}</strong>` })}</p>`;
}
function fragIntegral(ctx) {
  const t = ctx.t;
  const lin = paridade.integral[0];
  const linhas = [1, 2, 3, 4, 5, 6, 7, 8].map((r) => {
    const n = lin.soma_nao_nula[String(r)];
    const dist = n === 0;
    return `<tr><td class="num">${r}</td><td class="num">${n}</td><td>${dist ? `<span class="tag alta" ><span aria-hidden="true">◆</span> ${t('atq_distingue')}</span>` : `<span class="tag baixa"><span aria-hidden="true">◇</span> ${t('atq_nao_distingue')}</span>`}</td></tr>`;
  }).join('');
  return `<div class="tabela-rolavel"><table><thead><tr><th class="num">${t('atq_col_r')}</th><th class="num">${t('atq_col_p')}</th><th>${t('atq_col_v')}</th></tr></thead><tbody>${linhas}</tbody></table></div>`;
}
function faixa(n, total, ctx) {
  const rotulo = n === null ? ctx.t('alc_nd') : ctx.t('alc_det', { n, t: total });
  if (n === null) return `<span class="suave">${ctx.t('alc_nd')}</span>`;
  const cel = Array.from({ length: total }, (_, i) => `<span class="${i < n ? 'cheia' : 'vazia'}"></span>`).join('');
  return `<span class="faixa" role="img" aria-label="${esc(rotulo)}">${cel}</span> <span class="num">${n} / ${total}</span>`;
}
function fragAlcance(ctx) {
  const t = ctx.t, tot = alcance.total;
  const linhas = alcance.linhas.map((l) => `<tr><th scope="row">${esc(l[ctx.lang])}</th><td>${faixa(l.aes128, tot.aes128, ctx)}</td><td>${faixa(l.aes256, tot.aes256, ctx)}</td><td>${faixa(l.rsd, tot.rsd, ctx)}</td></tr>`).join('');
  return `<div class="tabela-rolavel"><table class="alcance"><thead><tr><th>${t('alc_col_ataque')}</th><th>${t('alc_aes128')}</th><th>${t('alc_aes256')}</th><th>${t('alc_rsd')}</th></tr></thead><tbody>${linhas}</tbody></table></div>`;
}
function fragCercos(ctx, resumo = false) {
  const t = ctx.t;
  const lista = resumo ? cercos.filter((c) => c.sev !== 'baixa') : cercos;
  const linhas = lista.map((c) => {
    const d = c[ctx.lang];
    const est = { corrigido: 'ok', nao_corrigido: 'aberto', aberto: 'aberto' }[c.estado];
    const icone = c.estado === 'corrigido' ? '✓' : c.estado === 'aberto' ? '!' : '–';
    return `<tr id="${c.id.toLowerCase()}"><th scope="row"><span class="mono">${c.id}</span><br>${esc(d.titulo)}</th><td><span class="tag ${c.sev}">${t('sev_' + c.sev)}</span></td><td>${esc(d.v51)}</td><td>${esc(d.v52)}<br><span class="tag ${est}"><span aria-hidden="true">${icone}</span> ${t('estado_' + c.estado)}</span></td></tr>`;
  }).join('');
  return `<div class="tabela-rolavel"><table><thead><tr><th>${t('corr_col_id')}</th><th>${t('corr_col_sev')}</th><th>${t('corr_col_v51')}</th><th>${t('corr_col_v52')}</th></tr></thead><tbody>${linhas}</tbody></table></div>`;
}
function fragGarantias(ctx) {
  const t = ctx.t;
  const linhas = [1, 2, 3, 4, 5].map((i) => `<tr><th scope="row">${t('gar_l' + i)}</th><td>${t('gar_e' + i)}</td></tr>`).join('');
  return `<div class="tabela-rolavel"><table><thead><tr><th>${t('gar_col_gar')}</th><th>${t('gar_col_est')}</th></tr></thead><tbody>${linhas}</tbody></table></div>`;
}

// ---------- cabeçalho, aviso, rodapé ----------
function paginaHref(ctx, destino) { // links relativos entre as 4 páginas
  const mapa = { pt: { inicio: '', lab: 'lab/' }, en: { inicio: 'en/', lab: 'en/lab/' } };
  return ctx.base + mapa[ctx.lang][destino];
}
function fragCabecalho(ctx) {
  const t = ctx.t;
  const outro = ctx.lang === 'pt' ? { rot: dict.pt.outro_idioma_rotulo, href: ctx.base + (ctx.pagina === 'lab' ? 'en/lab/' : 'en/') }
    : { rot: dict.en.outro_idioma_rotulo, href: ctx.base + (ctx.pagina === 'lab' ? 'lab/' : '') };
  const home = paginaHref(ctx, 'inicio');
  const ancora = (a) => (ctx.pagina === 'inicio' ? '' : home) + a;
  return `<header class="cabecalho"><div class="conteudo">
<a class="marca" href="${home}" aria-label="${t('nome')}"><img class="logo-dia" src="${ctx.base}assets/logos/lockup-V1-horizontal-dia-4x.png" alt="${t('nome')}" width="236" height="34"><img class="logo-noite" src="${ctx.base}assets/logos/lockup-V1-horizontal-noite-4x.png" alt="" width="236" height="34"></a>
<nav aria-label="${t('nav_principal')}"><ul class="menu">
<li><a href="${paginaHref(ctx, 'lab')}"${ctx.pagina === 'lab' ? ' aria-current="page"' : ''}>${t('nav_lab')}</a></li>
<li><a href="${ancora('#garantias')}">${t('nav_garantias')}</a></li>
<li><a href="${ancora('#correcoes')}">${t('nav_correcoes')}</a></li>
<li><a href="${ancora('#ataques')}">${t('nav_ataques')}</a></li>
<li><a href="${ancora('#licenca')}">${t('nav_licenca')}</a></li>
<li><a href="${URL_REPO}">${t('nav_repo')}</a></li>
</ul></nav>
<div class="ferramentas">
<a class="btn sec pequeno" href="${outro.href}" hreflang="${dict[ctx.lang].outro_idioma_lang}" lang="${dict[ctx.lang].outro_idioma_lang}">${outro.rot}</a>
<button type="button" class="btn contorno pequeno so-js" id="alternar-tema" aria-pressed="false">${t('tema_rotulo')}: <span id="tema-nome">…</span></button>
</div></div></header>`;
}
const fragAviso = (ctx) => `<div class="aviso" role="region" aria-label="${ctx.t('aviso_rotulo')}"><div class="conteudo"><strong>${ctx.t('aviso_curto').split('. ')[0]}.</strong> <span>${ctx.t('aviso_curto').split('. ').slice(1).join('. ')}</span> <a href="#limites">${ctx.t('aviso_link')}</a></div></div>`;
function fragRodape(ctx) {
  const t = ctx.t;
  return `<footer class="rodape"><div class="conteudo">
<div><h2>${t('nome')}</h2><p>${t('rodape_aviso')}</p><p>${t('rodape_autor')}</p><p>${t('rodape_sem_rastreio')}</p></div>
<div><h2>${t('rodape_versoes')}</h2><dl>
<dt>${t('rodape_site')}</dt><dd>${VERSOES.site}</dd>
<dt>${t('rodape_motor')}</dt><dd class="mono">${VERSOES.motor}</dd>
<dt>${t('rodape_spec')}</dt><dd class="mono">${VERSOES.spec}</dd>
<dt>${t('rodape_kat')}</dt><dd class="mono">${VERSOES.kat}</dd>
<dt>${t('rodape_commit')}</dt><dd class="mono">${VERSOES.commit}</dd></dl></div>
<div><h2>${t('rodape_links')}</h2><ul>
<li><a href="${URL_REPO}">${t('nav_repo')}</a></li>
<li><a href="${URL_REPO}/blob/main/LICENSE">PolyForm Noncommercial 1.0.0</a></li>
<li><a href="${URL_REPO}/blob/main/COMMERCIAL.md">${t('lic_link')}</a></li>
<li><a href="${URL_REPO}/blob/main/SECURITY.md">SECURITY.md</a></li>
<li><a href="#topo">${t('voltar_topo')}</a></li></ul></div>
</div></footer>`;
}
function fragHead(ctx, titulo, descricao) {
  const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'";
  const alt = ctx.lang === 'pt' ? ctx.base + (ctx.pagina === 'lab' ? 'en/lab/' : 'en/') : ctx.base + (ctx.pagina === 'lab' ? 'lab/' : '');
  const caminho = (l, p) => URL_SITE + (l === 'pt' ? (p === 'lab' ? 'lab/' : '') : (p === 'lab' ? 'en/lab/' : 'en/'));
  return `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>${esc(titulo)}</title>
<meta name="description" content="${esc(descricao)}">
<link rel="canonical" href="${caminho(ctx.lang, ctx.pagina)}">
<link rel="alternate" hreflang="pt-BR" href="${caminho('pt', ctx.pagina)}">
<link rel="alternate" hreflang="en" href="${caminho('en', ctx.pagina)}">
<meta property="og:type" content="website"><meta property="og:title" content="${esc(titulo)}"><meta property="og:description" content="${esc(descricao)}">
<meta property="og:image" content="${URL_SITE}assets/imagem-social-1280x640.png"><meta name="twitter:card" content="summary_large_image">
<link rel="icon" type="image/svg+xml" href="${ctx.base}assets/favicon/favicon.svg"><link rel="icon" type="image/png" sizes="32x32" href="${ctx.base}assets/favicon/favicon-32.png"><link rel="apple-touch-icon" href="${ctx.base}assets/favicon/apple-touch-icon-180.png">
<link rel="stylesheet" href="${ctx.base}css/site.css">
<script src="${ctx.base}js/tema.js"></script>`;
}

// ---------- montagem ----------
const PAGINAS = [
  { tpl: 'index', pagina: 'inicio', saida: { pt: 'index.html', en: 'en/index.html' } },
  { tpl: 'lab', pagina: 'lab', saida: { pt: 'lab/index.html', en: 'en/lab/index.html' } },
];

function render(tpl, ctx) {
  const frag = {
    head: () => fragHead(ctx, ctx.t(`titulo_${ctx.pagina}`), ctx.t(`descricao_${ctx.pagina}`)),
    aviso: () => fragAviso(ctx), cabecalho: () => fragCabecalho(ctx), rodape: () => fragRodape(ctx),
    glifos: () => folhaDeGlifos(),
    'caso-dono': () => fragCasoDono(ctx), integral: () => fragIntegral(ctx), alcance: () => fragAlcance(ctx),
    cercos: () => fragCercos(ctx), 'cercos-resumo': () => fragCercos(ctx, true), garantias: () => fragGarantias(ctx),
    'i18n-json': () => `<script type="application/json" id="i18n">${JSON.stringify(dict[ctx.lang]).replace(/</g, '\\u003c')}</script>`,
    'cercos-json': () => `<script type="application/json" id="dados-cercos">${JSON.stringify(cercos).replace(/</g, '\\u003c')}</script>`,
    'kats-json': () => `<script type="application/json" id="dados-kats">${JSON.stringify(kats.vectors).replace(/</g, '\\u003c')}</script>`,
  };
  return tpl
    .replace(/\{\{@([\w-]+)\}\}/g, (_, n) => { if (!frag[n]) throw new Error('fragmento desconhecido: ' + n); return frag[n](); })
    .replace(/\{\{t:(\w+)\}\}/g, (_, k) => ctx.t(k))
    .replace(/\{\{(\w+)\}\}/g, (_, k) => { if (!(k in ctx.vars)) throw new Error('variável desconhecida: ' + k); return ctx.vars[k]; });
}

rmSync(DIST, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });
for (const d of ['assets', 'css']) cpSync(join(SRC, d), join(DIST, d), { recursive: true });
cpSync(join(SRC, 'js'), join(DIST, 'js'), { recursive: true });
mkdirSync(join(DIST, 'dados'), { recursive: true });
writeFileSync(join(DIST, '.nojekyll'), '');
writeFileSync(join(DIST, 'robots.txt'), `User-agent: *\nAllow: /\n`);

let escritas = 0;
for (const p of PAGINAS) {
  const tplPath = join(SRC, 'paginas', `${p.tpl}.html`);
  if (!existsSync(tplPath)) continue;
  const tpl = ler(tplPath);
  for (const lang of ['pt', 'en']) {
    const rel = p.saida[lang];
    const base = '../'.repeat(rel.split('/').length - 1);
    const ctx = { lang, pagina: p.pagina, base, t: tFn(lang), vars: { base, lang: dict[lang].idioma, versao: VERSOES.site, repo: URL_REPO, lab: paginaHref({ lang, base }, 'lab'), inicio: paginaHref({ lang, base }, 'inicio') } };
    const out = join(DIST, rel);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, render(tpl, ctx));
    escritas++;
  }
}
console.log(`site/dist: ${escritas} páginas | site ${VERSOES.site} | motor ${VERSOES.motor} | kat ${VERSOES.kat} | commit ${VERSOES.commit}`);
export { casoDoDono };
