// Componentes de interface compartilhados: grades de blocos, painel de palavra, conferência manual.
import { blocoSvg, byteSvg, hex4, hex2 } from './runes.js';
import { t } from './i18n.js';
import { popcount16 } from './engine/rsd.js';

export const $ = (sel, raiz = document) => raiz.querySelector(sel);
export const $$ = (sel, raiz = document) => Array.from(raiz.querySelectorAll(sel));
export function el(tag, attrs = {}, html = '') {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? '' : v);
  }
  if (html) e.innerHTML = html;
  return e;
}
export const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Nome acessível de um bloco: posição na grade 4x8, valor e diferença. */
export function nomeDoBloco(i, w, ref) {
  const lin = (i >> 3) + 1;
  const col = (i & 7) + 1;
  const base = t('bloco_nome', { i, lin, col, hex: hex4(w) });
  if (ref === undefined || ref === w) return base;
  return `${base}, ${t('bloco_difere', { n: popcount16(w ^ ref) })}`;
}

/**
 * Desenha uma grade 4x8 de blocos (32 palavras) dentro de `ul`. Cada bloco é um botão.
 * opcoes: ref (palavras da outra execução, para marcar diferenças), selecionado (índice),
 * aoEscolher(i), inexistentes (índices cujo bit mais alto nunca acende na entrada).
 * Setas navegam entre os blocos (tabindex móvel); Enter e Espaço escolhem.
 */
export function desenharGrade(ul, palavras, { ref, selecionado = -1, aoEscolher, inexistentes = [] } = {}) {
  ul.innerHTML = '';
  ul.classList.add('grade');
  palavras.forEach((w, i) => {
    const dif = ref !== undefined && ref[i] !== w;
    const li = el('li');
    const b = el('button', {
      type: 'button',
      class: `bloco${dif ? ' dif' : ''}${inexistentes.includes(i) ? ' inexistente' : ''}`,
      'aria-label': nomeDoBloco(i, w, ref ? ref[i] : undefined),
      'aria-pressed': i === selecionado ? 'true' : 'false',
      tabindex: i === (selecionado >= 0 ? selecionado : 0) ? '0' : '-1',
      'data-i': i,
    }, `${blocoSvg(w)}<span class="hex" aria-hidden="true">${hex4(w)}</span>`);
    b.addEventListener('click', () => { if (aoEscolher) aoEscolher(i); });
    li.appendChild(b);
    ul.appendChild(li);
  });
  ul.onkeydown = (ev) => {
    const alvo = ev.target.closest && ev.target.closest('button.bloco');
    if (!alvo) return;
    const cols = getComputedStyle(ul).gridTemplateColumns.split(' ').length || 8;
    const i = Number(alvo.dataset.i);
    const passos = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: cols, ArrowUp: -cols, Home: -i, End: 31 - i };
    const passo = passos[ev.key];
    if (passo === undefined) return;
    ev.preventDefault();
    const j = Math.min(31, Math.max(0, i + passo));
    const botoes = $$('button.bloco', ul);
    botoes.forEach((x) => x.setAttribute('tabindex', '-1'));
    botoes[j].setAttribute('tabindex', '0');
    botoes[j].focus();
  };
}

/** Grade somente leitura de blocos (selo de chave): cada item é uma imagem com descrição. */
export function desenharSelo(ul, palavras, prefixo) {
  ul.innerHTML = '';
  ul.classList.add('grade');
  palavras.forEach((w, i) => {
    const li = el('li');
    li.innerHTML = `<div class="bloco" role="img" aria-label="${esc(prefixo)} ${i}: 0x${hex4(w)}">${blocoSvg(w)}<span class="hex" aria-hidden="true">${hex4(w)}</span></div>`;
    ul.appendChild(li);
  });
}

export function desenharChaveiro(ul, bytes) {
  ul.innerHTML = '';
  ul.classList.add('grade', 'chaveiro');
  bytes.forEach((b, k) => {
    const li = el('li');
    li.innerHTML = `<div class="byte" role="img" aria-label="${esc(t('byte_nome', { k, hex: hex2(b) }))}">${byteSvg(b)}<span class="hex" aria-hidden="true">${hex2(b)}</span></div>`;
    ul.appendChild(li);
  });
}

const bin16 = (w) => w.toString(2).padStart(16, '0').replace(/(.{4})/g, '$1 ').trim();

/** Painel com todos os detalhes de uma palavra e a conferência manual contra um valor digitado. */
export function painelPalavra(host, { i, w, ref, origem }) {
  const dif = ref === undefined ? '' : `<p>${t('painel_xor', { xor: hex4(w ^ ref), n: popcount16(w ^ ref) })}</p>`;
  host.innerHTML = `
<h3>${t('painel_titulo', { i })}</h3>
<dl class="dl-tec">
<dt>${t('painel_origem')}</dt><dd>${esc(origem)}</dd>
<dt>${t('painel_hex')}</dt><dd class="mono">0x${hex4(w)}</dd>
<dt>${t('painel_bin')}</dt><dd class="mono">${bin16(w)}</dd>
<dt>${t('painel_dec')}</dt><dd class="mono">${w}</dd>
<dt>${t('painel_pos')}</dt><dd>${t('painel_pos_txt', { lin: (i >> 3) + 1, col: (i & 7) + 1 })}</dd>
</dl>
${dif}
<div class="campo"><label for="esperado">${t('conf_rotulo')}</label>
<input id="esperado" class="mono" type="text" inputmode="text" maxlength="6" autocomplete="off" spellcheck="false" placeholder="3a91" aria-describedby="conf-ajuda">
<p class="ajuda" id="conf-ajuda">${t('conf_ajuda')}</p></div>
<div id="conf-saida" aria-live="polite"></div>`;
  const inp = $('#esperado', host);
  const saida = $('#conf-saida', host);
  inp.addEventListener('input', () => {
    const v = inp.value.trim().replace(/^0x/i, '');
    if (!v) { saida.innerHTML = ''; return; }
    if (!/^[0-9a-f]{1,4}$/i.test(v)) { saida.innerHTML = `<p class="erro">${t('conf_invalido')}</p>`; return; }
    const esp = parseInt(v, 16);
    const d = esp ^ w;
    if (d === 0) {
      saida.innerHTML = `<p class="veredito sem"><span class="ico" aria-hidden="true">=</span>${t('conf_igual')}</p>`
        + `<div class="duplo-bloco"><div class="bloco" role="img" aria-label="${esc(t('conf_calculado'))}">${blocoSvg(w)}</div></div>`;
      return;
    }
    const bits = [];
    for (let b = 15; b >= 0; b--) if ((d >> b) & 1) bits.push(b);
    saida.innerHTML = `<p class="veredito cede"><span class="ico" aria-hidden="true">≠</span>${t('conf_difere', { n: bits.length, bits: bits.join(', ') })}</p>`
      + `<div class="duplo-bloco"><figure><div class="bloco" role="img" aria-label="${esc(t('conf_esperado'))}">${blocoSvg(esp)}</div><figcaption>${t('conf_esperado')}</figcaption></figure>`
      + `<figure><div class="bloco" role="img" aria-label="${esc(t('conf_calculado'))}">${blocoSvg(w)}</div><figcaption>${t('conf_calculado')}</figcaption></figure></div>`;
  });
}

export function anunciar(msg) {
  const r = document.getElementById('anuncio');
  if (r) r.textContent = msg;
}
