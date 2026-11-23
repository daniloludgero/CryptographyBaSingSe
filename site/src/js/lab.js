// Laboratório da RSD-S v5.2. Tudo o que aparece é calculado pelo motor (engine/rsd.js), conferido bit a bit
// contra o Python nos testes do repositório. Os dois modos (Explorar e Verificar) leem o MESMO traço.
import * as E from './engine/rsd.js';
import { sha256, hex, fromHex } from './engine/hash.js';
import { hex4, blocoSvg } from './runes.js';
import { iniciarI18n, t, fmtNum } from './i18n.js';
import { PRESET_DONO, sortear, lerInteiro, lerChave, aplicarBit, paraFragmento, deFragmento, CHAVE_DEMO_HEX } from './sessao.js';
import { $, $$, el, esc, desenharGrade, desenharSelo, desenharChaveiro, painelPalavra, anunciar } from './ui.js';

iniciarI18n();
const raiz = document.documentElement;
const reduzMovimento = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// ---------- armazenamento opcional (pode falhar; a página funciona sem ele) ----------
const guardar = (k, v) => { try { localStorage.setItem(k, v); } catch { /* sem armazenamento */ } };
const lerGuardado = (k) => { try { return localStorage.getItem(k); } catch { return null; } };

// ---------- estado ----------
let S = PRESET_DONO();
let C = null; // resultado do cálculo
let modo = 'explorar';
let momento = 1;
let palavraSel = -1;

function calcular(sessao) {
  const b = aplicarBit(sessao);
  if (b.erro) return { erro: b.erro };
  const sch = E.schedule(sessao.chave, sessao.nSess, sessao.rounds);
  const A = E.core(E.fragment(sessao.x, sessao.y), sch);
  const B = E.core(E.fragment(b.x, b.y), sch);
  const s1 = E.schedule(sessao.chave, sessao.nSess, 1);
  const A1 = E.core(E.fragment(sessao.x, sessao.y), s1);
  const B1 = E.core(E.fragment(b.x, b.y), s1);
  const dA = E.digest(sessao.x, sessao.y, sessao.chave, sessao.nSess, sessao.rounds, sessao.saida);
  const dB = E.digest(b.x, b.y, sessao.chave, sessao.nSess, sessao.rounds, sessao.saida);
  return { sch, A, B, Bin: b, A1, B1, dA, dB, porRodada: A.trace.map((st, r) => E.diffStats(st, B.trace[r])) };
}

// ---------- formulário ----------
function preencherFormulario() {
  $('#campo-x').value = S.x.toString();
  $('#campo-y').value = S.y.toString();
  $('#campo-n').value = S.nSess.toString();
  $('#campo-rodadas').value = String(S.rounds);
  $('#campo-bit').value = String(S.bit);
  $('#campo-saida').value = String(S.saida);
  $('#campo-chave').value = hex(S.chave);
}
function lerFormulario() {
  const erros = [];
  const x = lerInteiro($('#campo-x').value), y = lerInteiro($('#campo-y').value), n = lerInteiro($('#campo-n').value);
  const chave = lerChave($('#campo-chave').value);
  const rounds = Number($('#campo-rodadas').value), bit = Number($('#campo-bit').value);
  if (x === null || x < 0n || x >= E.P) erros.push(t('erro_x'));
  if (y === null || y < 0n || y >= E.P) erros.push(t('erro_y'));
  if (n === null || n < 0n || n >= (1n << 64n)) erros.push(t('erro_n'));
  if (!chave) erros.push(t('erro_chave'));
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > 255) erros.push(t('erro_rodadas'));
  if (!Number.isInteger(bit) || bit < 0 || bit > 509) erros.push(t('erro_bit'));
  if (erros.length) return { erros };
  return { S: { x, y, nSess: n, chave, rounds, bit, saida: Number($('#campo-saida').value) === 64 ? 64 : 32 } };
}
function aplicarSessao(nova) {
  const teste = calcular(nova);
  if (teste.erro) { $('#erros-sessao').textContent = t('erro_bit_fora'); return false; }
  $('#erros-sessao').textContent = '';
  S = nova; C = teste;
  momento = Math.min(Math.max(momento, 0), S.rounds);
  palavraSel = -1;
  preencherFormulario();
  desenharTudo();
  try { history.replaceState(null, '', '#' + paraFragmento(S, false)); } catch { /* ignora */ }
  return true;
}

// ---------- modo ----------
function definirModo(m) {
  modo = m;
  raiz.setAttribute('data-modo', m);
  guardar('basingse-modo', m);
  $('#modo-explorar').setAttribute('aria-pressed', String(m === 'explorar'));
  $('#modo-verificar').setAttribute('aria-pressed', String(m === 'verificar'));
  $('#modo-desc').textContent = t(m === 'explorar' ? 'modo_desc_explorar' : 'modo_desc_verificar');
  $('#det-entrada').open = m === 'verificar';
  $('#det-tabela').open = m === 'verificar';
  $('#ver-hex').checked = m === 'verificar';
  alternarHex();
  anunciar(t('modo_anuncio', { modo: t(m === 'explorar' ? 'modo_explorar' : 'modo_verificar') }));
}
function alternarHex() {
  for (const p of ['#painel-a', '#painel-b']) $(p).classList.toggle('mostrar-hex', $('#ver-hex').checked);
}

// ---------- seção 1: uma rodada ----------
const origemEstado = (m) => t(m === 0 ? 'origem_m0' : 'origem_m', { r: m, total: S.rounds });
function desenharRodada() {
  const rng = $('#momento');
  rng.max = String(S.rounds);
  rng.value = String(momento);
  $('#momento-txt').textContent = momento === 0 ? t('rod_m0') : t('rod_mr', { r: momento, total: S.rounds });
  $('#rotulacao').textContent = momento === 0 ? t('rotulacao_m0') : t('rotulacao_mr', { r: momento, total: S.rounds });
  const a = C.A.trace[momento], b = C.B.trace[momento];
  const aoEscolher = (i) => { palavraSel = i; desenharRodada(); const bt = $(`#grade-a button[data-i="${i}"]`); if (bt) bt.focus(); };
  desenharGrade($('#grade-a'), a, { ref: b, selecionado: palavraSel, aoEscolher });
  desenharGrade($('#grade-b'), b, { ref: a, selecionado: palavraSel, aoEscolher });
  const st = C.porRodada[momento];
  $('#m-pal').textContent = `${st.words} / 32`;
  $('#m-bits').textContent = `${st.bits} / 512`;
  let bitsSaida = 0;
  for (let i = 0; i < C.dA.length; i++) { let d = C.dA[i] ^ C.dB[i]; while (d) { bitsSaida += d & 1; d >>>= 1; } }
  $('#m-saida').textContent = `${bitsSaida} / ${C.dA.length * 8}`;
  if (palavraSel >= 0) painelPalavra($('#painel-palavra'), { i: palavraSel, w: a[palavraSel], ref: b[palavraSel], origem: origemEstado(momento) });
  else $('#painel-palavra').innerHTML = `<p class="suave">${t('painel_vazio')}</p>`;
  $('#tabela-rodadas').innerHTML = C.porRodada.map((s, r) => `<tr${r === momento ? ' aria-current="true"' : ''}><td class="num">${r === 0 ? '0 (rk[0])' : r}</td><td class="num">${s.words}</td><td class="num">${s.bits}</td></tr>`).join('');
  const s1 = E.diffStats(C.A1.state, C.B1.state);
  const s8 = C.porRodada[Math.min(1, S.rounds)];
  $('#nota-rotulacao').innerHTML = `<strong>${t('rot_nota_t')}</strong>${t('rot_nota', { w8: s8.words, b8: s8.bits, w1: s1.words, b1: s1.bits, total: S.rounds })}`;
}

// ---------- palpite (Pedra no poço) ----------
function jogarPalpite() {
  const v = Number($('#palpite').value);
  if (!Number.isInteger(v) || v < 0 || v > 512) { $('#palpite-saida').innerHTML = `<p class="erro">${t('palpite_invalido')}</p>`; return; }
  const real = C.porRodada[Math.min(1, S.rounds)].bits;
  let hist = [];
  try { hist = JSON.parse(lerGuardado('basingse-palpites') || '[]'); } catch { hist = []; }
  hist.push({ palpite: v, real });
  hist = hist.slice(-20);
  guardar('basingse-palpites', JSON.stringify(hist));
  const erro = hist.reduce((a, h) => a + Math.abs(h.palpite - h.real), 0) / hist.length;
  $('#palpite-saida').innerHTML = `<p class="veredito sem">${t('palpite_resultado', { real, dif: Math.abs(v - real), meta: 256 })}</p><p class="suave">${t('palpite_hist', { n: hist.length, erro: erro.toFixed(1) })}</p><p>${t('palpite_lembrete')}</p>`;
}

// ---------- seção 2: chaves ----------
function desenharChaves() {
  desenharChaveiro($('#chaveiro'), S.chave);
  const r = Math.min(Number($('#sel-chave').value), S.rounds);
  $('#sel-chave').max = String(S.rounds);
  $('#sel-chave').value = String(r);
  $('#sel-chave-txt').textContent = `r = ${r}`;
  $('#selo-r').textContent = `rk[${r}]`;
  desenharSelo($('#selo'), C.sch.rk.subarray(r * 32, r * 32 + 32), `rk[${r}]`);
  const rcBox = $('#bloco-rc');
  if (r === 0) { rcBox.innerHTML = ''; rcBox.setAttribute('aria-label', t('rc_nenhum')); $('#rc-texto').textContent = t('rc_nenhum'); }
  else {
    const rc = C.sch.rc[r - 1];
    rcBox.innerHTML = blocoSvg(rc);
    rcBox.setAttribute('aria-label', `rc[${r}] = 0x${hex4(rc)}`);
    $('#rc-texto').textContent = t('rc_texto', { r, hex: hex4(rc) });
  }
  $('#tabela-chaves').innerHTML = C.sch.keys.map((k, i) => `<tr><td class="num">${i}</td><td class="mono">${hex(k)}</td><td class="num mono">${i === 0 ? '–' : '0x' + hex4(C.sch.rc[i - 1])}</td></tr>`).join('');
}

// ---------- missão A: feixe de espelhos ----------
let feixeRodadas = 2;
let worker = null;
function preparaFeixe() {
  const sel = $('#feixe-palavra');
  sel.innerHTML = Array.from({ length: 32 }, (_, i) => `<option value="${i}">${i}${i < 16 ? ' (x)' : ' (y)'}</option>`).join('');
  const g = $('#feixe-rodadas');
  g.innerHTML = '';
  for (let r = 1; r <= 8; r++) {
    const b = el('button', { type: 'button', class: 'btn contorno pequeno', 'aria-pressed': String(r === feixeRodadas), 'data-r': r }, String(r));
    b.setAttribute('aria-label', t('feixe_r_rotulo', { r }));
    b.addEventListener('click', () => { feixeRodadas = r; $$('button', g).forEach((x) => x.setAttribute('aria-pressed', String(Number(x.dataset.r) === r))); });
    g.appendChild(b);
  }
}
function cancelarFeixe() {
  if (worker) { worker.terminate(); worker = null; }
  $('#feixe-disparar').disabled = false;
  $('#feixe-cancelar').disabled = true;
  $('#feixe-disparar').removeAttribute('aria-busy');
}
function dispararFeixe() {
  cancelarFeixe();
  const ativa = Number($('#feixe-palavra').value);
  const r = feixeRodadas;
  const camaraSelada = modo === 'explorar';
  const chave = camaraSelada ? crypto.getRandomValues(new Uint8Array(32)) : S.chave;
  const base = Array.from(E.fragment(S.x, S.y));
  const cv = $('#mosaico'), cx = cv.getContext('2d');
  cx.fillStyle = '#1c1510'; cx.fillRect(0, 0, 256, 256);
  $('#feixe-veredito').innerHTML = '';
  $('#pocos').innerHTML = '';
  $('#feixe-resultado').innerHTML = `<p>${t('feixe_rodando', { r, w: ativa })}</p>`;
  $('#feixe-disparar').disabled = true;
  $('#feixe-disparar').setAttribute('aria-busy', 'true');
  $('#feixe-cancelar').disabled = false;
  $('#feixe-prog').value = 0;
  const TONS = [[0x3b, 0x2a, 0x1c], [0x7a, 0x5a, 0x38], [0xc9, 0x8a, 0x22], [0xfe, 0xf8, 0xb6]];
  const img = cx.createImageData(256, 256);
  const tonsTodos = new Uint8Array(65536);
  const pintar = (ate) => {
    for (let v = 0; v < ate; v++) { const c = TONS[tonsTodos[v]]; img.data[4 * v] = c[0]; img.data[4 * v + 1] = c[1]; img.data[4 * v + 2] = c[2]; img.data[4 * v + 3] = 255; }
    cx.putImageData(img, 0, 0);
  };
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  worker.onmessage = (ev) => {
    const m = ev.data;
    if (m.tipo === 'prog') {
      tonsTodos.set(m.tons, m.feito - m.tons.length);
      $('#feixe-prog').value = m.feito;
      $('#feixe-prog-txt').textContent = `${fmtNum(m.feito)} / 65.536`;
      if (!reduzMovimento) pintar(m.feito);
    } else if (m.tipo === 'fim') {
      pintar(65536);
      $('#feixe-prog').value = 65536;
      $('#feixe-prog-txt').textContent = `65.536 / 65.536 (${m.ms} ms)`;
      mostrarFeixe(m.soma, r, ativa, chave, camaraSelada, m.ms, m.distintos);
      cancelarFeixe();
    }
  };
  worker.onerror = (e) => { $('#feixe-resultado').innerHTML = `<p class="erro">${esc(e.message || t('feixe_erro'))}</p>`; cancelarFeixe(); };
  worker.postMessage({ chave: hex(chave), n: S.nSess.toString(), rounds: r, ativa, base });
}
function pocoSvg(parado) {
  const d = parado ? 'M0 10 H60' : 'M0 10 L8 3 L16 17 L24 3 L32 17 L40 3 L48 17 L56 10 L60 10';
  return `<svg viewBox="0 0 60 20" aria-hidden="true" focusable="false"><path d="${d}" fill="none" stroke="currentColor" stroke-width="2" shape-rendering="crispEdges"/></svg>`;
}
function mostrarFeixe(soma, r, ativa, chave, selada, ms, distintos) {
  const parados = soma.filter((v) => v === 0).length;
  $('#pocos').innerHTML = soma.map((v, i) => `<li class="poco ${v === 0 ? 'parado' : 'ondulado'}"><span class="n">${i}</span>${pocoSvg(v === 0)}<span>${v === 0 ? t('poco_parado') : t('poco_ondulado')}</span><br><span>soma = 0x${hex4(v)}</span></li>`).join('');
  $('#feixe-resultado').innerHTML = `<p class="metrica-linha">${t('feixe_resumo', { r, w: ativa, parados, ond: 32 - parados })}</p>`
    + `<p>${t('feixe_distintos', { min: fmtNum(Math.min(...distintos)), perm: distintos.filter((d) => d === 65536).length })}</p>`
    + `<p class="suave pequeno">${t('feixe_distintos_nota')}</p>`
    + `<p class="suave pequeno">${t('feixe_tempo', { ms })}</p>`
    + (selada ? `<p><button type="button" class="btn contorno pequeno" id="feixe-revelar">${t('feixe_revelar')}</button> <code id="feixe-chave" class="mono" hidden>${hex(chave)}</code></p>` : `<p class="suave pequeno">${t('feixe_chave_usada')}</p>`);
  const rev = $('#feixe-revelar');
  if (rev) rev.addEventListener('click', () => { $('#feixe-chave').hidden = false; rev.hidden = true; });
  let v;
  if (parados === 32) v = `<div class="veredito cede" role="status"><span class="ico" aria-hidden="true">▲</span><strong>${t('feixe_distingue', { r })}</strong> ${t('feixe_distingue_det', { r })}</div>`;
  else if (parados === 0) v = `<div class="veredito sem" role="status"><span class="ico" aria-hidden="true">○</span><strong>${t('feixe_nao_distingue', { r })}</strong> ${t('feixe_nao_distingue_det')}</div>`;
  else v = `<div class="veredito" role="status"><span class="ico" aria-hidden="true">?</span><strong>${t('feixe_inesperado')}</strong> ${t('feixe_inesperado_det', { parados })}</div>`;
  $('#feixe-veredito').innerHTML = v;
  anunciar(t('feixe_anuncio', { parados }));
}

// ---------- missão C: duas sentinelas ----------
function preparaSentinelas() {
  $('#sent-rodada').innerHTML = Array.from({ length: S.rounds }, (_, i) => `<option value="${i + 1}"${i + 1 === Math.min(7, S.rounds) ? ' selected' : ''}>${i + 1}</option>`).join('');
  $('#sent-palavra').innerHTML = Array.from({ length: 32 }, (_, i) => `<option value="${i}">${i}</option>`).join('');
  $('#sent-bit').innerHTML = Array.from({ length: 16 }, (_, i) => `<option value="${i}">${i} (0x${hex4(1 << i)})</option>`).join('');
  atualizarDescSentinelas();
}
function atualizarDescSentinelas() {
  const m = $('#sent-modo').value;
  $('#sent-desc').textContent = t({ A: 'sent_d_a', ambos: 'sent_d_ambos', antes: 'sent_d_antes' }[m]);
  $('#sent-rodada').disabled = m === 'antes';
}
function executarSentinelas() {
  const m = $('#sent-modo').value;
  const f = { round: Number($('#sent-rodada').value), word: Number($('#sent-palavra').value), mask: 1 << Number($('#sent-bit').value), modo: m };
  const ent = E.fragment(S.x, S.y);
  const limpo = E.core(ent, C.sch);
  const res = E.core(ent, C.sch, f);
  const dif = E.diffStats(res.finalA, res.finalB);
  const saidaDifere = res.status === 0 && E.diffStats(res.state, limpo.state).bits > 0;
  let html;
  if (res.status === -2) html = `<div class="veredito cede" role="status"><span class="ico" aria-hidden="true">▲</span><strong>${t('sent_alarme')}</strong> ${t('sent_alarme_det', { palavras: dif.words, bits: dif.bits })}</div>`;
  else html = `<div class="veredito ${saidaDifere ? 'cede' : 'sem'}" role="status"><span class="ico" aria-hidden="true">${saidaDifere ? '!' : '○'}</span><strong>${t('sent_sem_alarme')}</strong> ${saidaDifere ? t('sent_saida_errada', { bits: E.diffStats(res.state, limpo.state).bits }) : t('sent_saida_igual')}</div>`;
  $('#sent-resultado').innerHTML = html;
  $('#sent-grades').hidden = false;
  desenharGrade($('#sent-a'), res.finalA, { ref: res.finalB });
  desenharGrade($('#sent-b'), res.finalB, { ref: res.finalA });
  anunciar(res.status === -2 ? t('sent_alarme') : t('sent_sem_alarme'));
}

// ---------- pergaminhos de referência (KAT) ----------
let katIdx = 0, katAdulterado = false;
const KATS = JSON.parse($('#dados-kats').textContent);
function calcularKat(v) {
  const x = BigInt(v.x), y = BigInt(v.y), s = fromHex(v.s_hex), n = BigInt(v.n_sess), r = v.rounds;
  const res = E.core(E.fragment(x, y), E.schedule(s, n, r));
  return { pre: hex(E.serialize(res.state)), d32: hex(E.digest(x, y, s, n, r, 32)), d64: hex(E.digest(x, y, s, n, r, 64)) };
}
function desenharKat() {
  const lista = $('#kat-lista');
  if (!lista.children.length) {
    KATS.forEach((v, i) => {
      const b = el('button', { type: 'button', class: 'btn contorno pequeno', 'aria-pressed': String(i === katIdx), 'data-i': i }, esc(v.name));
      b.addEventListener('click', () => { katIdx = i; katAdulterado = false; desenharKat(); });
      lista.appendChild(b);
    });
  }
  $$('button', lista).forEach((b) => b.setAttribute('aria-pressed', String(Number(b.dataset.i) === katIdx)));
  const v = KATS[katIdx];
  const c = calcularKat(v);
  const campos = [['pre_sha', v.pre_sha_hex, c.pre], ['output_256', v.output_256_hex, c.d32], ['output_512', v.output_512_hex, c.d64]];
  let linhas = '';
  for (const [nome, esperado, calc] of campos) {
    let esp = esperado;
    if (katAdulterado) esp = esperado.slice(0, 5) + (esperado[5] === 'a' ? 'b' : 'a') + esperado.slice(6);
    const ok = esp === calc;
    const marcado = [...esp].map((ch, i) => (ch === calc[i] ? ch : `<mark>${ch}</mark>`)).join('');
    linhas += `<tr><th scope="row" class="mono">${nome}</th><td class="mono quebra">${marcado}</td><td class="mono quebra">${calc}</td><td><span class="tag ${ok ? 'ok' : 'alta'}"><span aria-hidden="true">${ok ? '✓' : '✗'}</span> ${ok ? t('kat_igual') : t('kat_diferente')}</span></td></tr>`;
  }
  $('#kat-quadro').innerHTML = `<p class="mono">${t('kat_param', { x: esc(v.x), y: esc(v.y), n: esc(v.n_sess), r: v.rounds })}</p><div class="tabela-rolavel"><table><thead><tr><th>${t('kat_campo')}</th><th>${t('kat_esperado')}</th><th>${t('kat_calculado')}</th><th>${t('kat_selo')}</th></tr></thead><tbody>${linhas}</tbody></table></div>`;
  $('#kat-restaurar').hidden = !katAdulterado;
  $('#kat-adulterar').hidden = katAdulterado;
}

// ---------- Livro de cercos ----------
const CERCOS = JSON.parse($('#dados-cercos').textContent);
function aleatorioMenorQueP() {
  const b = crypto.getRandomValues(new Uint8Array(40));
  return b.reduce((a, v) => (a << 8n) | BigInt(v), 0n) % E.P;
}
const verificacoes = {
  sentinelas() {
    $('#sent-modo').value = 'A';
    $('#sent-rodada').value = String(Math.min(7, S.rounds));
    $('#sent-palavra').value = '0'; $('#sent-bit').value = '0';
    atualizarDescSentinelas();
    executarSentinelas();
    $('#sentinelas').scrollIntoView({ behavior: reduzMovimento ? 'auto' : 'smooth' });
    return t('cerco_ir_sent', { r: Math.min(7, S.rounds) });
  },
  subchave() {
    let difs = 0;
    const total = C.sch.keys.length;
    for (let r = 0; r < total; r++) {
      let iguais = 0;
      for (let k = 0; k < 16; k++) if (((C.sch.keys[r][2 * k] << 8) | C.sch.keys[r][2 * k + 1]) === C.sch.rk[r * 32 + k]) iguais++;
      if (iguais <= 1) difs++;
    }
    return t('cerco_subchave', { difs, total });
  },
  msb() {
    const N = 300;
    let naEntrada = 0, aposR1 = 0;
    const s = E.schedule(S.chave, S.nSess, 8);
    for (let i = 0; i < N; i++) {
      const f = E.fragment(aleatorioMenorQueP(), aleatorioMenorQueP());
      if ((f[15] >> 15) || (f[31] >> 15)) naEntrada++;
      const st = E.core(f, s).trace[1];
      if (st[15] >> 15) aposR1++;
    }
    return t('cerco_msb', { n: N, a: naEntrada, b: aposR1 });
  },
  somas() {
    const somas = new Set();
    for (let i = 0; i < 32; i++) { let q = 0; for (let j = 0; j < 32; j++) q ^= E.MDS[i * 32 + j]; somas.add(q); }
    const rcs = new Set(Array.from(C.sch.rc));
    return t('cerco_somas', { distintas: somas.size, valor: '0x' + hex4([...somas][0]), constantes: rcs.size, rounds: C.sch.rc.length });
  },
};
function desenharCercos() {
  const host = $('#cercos-lista');
  host.innerHTML = '';
  const idioma = document.documentElement.getAttribute('lang').slice(0, 2) === 'en' ? 'en' : 'pt';
  for (const c of CERCOS) {
    const d = c[idioma];
    const est = { corrigido: 'ok', nao_corrigido: 'aberto', aberto: 'aberto' }[c.estado];
    const art = el('article', { class: 'cartao cerco', id: `cerco-${c.id.toLowerCase()}` });
    art.innerHTML = `<h3><span class="mono">${c.id}</span> <span class="tag ${c.sev}">${t('sev_' + c.sev)}</span> <span class="tag ${est}">${t('estado_' + c.estado)}</span></h3>
<p><strong>${esc(d.titulo)}</strong></p>
<dl class="dl-tec"><dt>${t('corr_col_v51')}</dt><dd>${esc(d.v51)}</dd><dt>${t('corr_col_v52')}</dt><dd>${esc(d.v52)}</dd></dl>
<p class="suave pequeno">${t('cerco_nao_mostra')}: ${esc(d.limite)}</p>`;
    if (c.refazer) {
      const b = el('button', { type: 'button', class: 'btn sec pequeno' }, t('cerco_refazer'));
      const out = el('p', { class: 'resultado-cerco', 'aria-live': 'polite' });
      b.addEventListener('click', () => { out.textContent = verificacoes[c.refazer](); });
      art.append(b, out);
    } else {
      art.appendChild(el('p', { class: 'suave pequeno' }, esc(t('cerco_nao_recalculado'))));
    }
    host.appendChild(art);
  }
}

// ---------- exportação ----------
function exportar() {
  const incluir = $('#exp-chave').checked;
  const obj = {
    laboratorio: 'BaSingSe', primitiva: 'RSD-S v5.2', aviso: t('aviso_curto'),
    entrada: { x: S.x.toString(), y: S.y.toString(), n_sess: S.nSess.toString(), rounds: S.rounds, bit_invertido: S.bit, saida_bytes: S.saida },
    chave: incluir ? hex(S.chave) : null,
    chaves_K: C.sch.keys.map(hex),
    rk: Array.from({ length: S.rounds + 1 }, (_, r) => Array.from(C.sch.rk.subarray(r * 32, r * 32 + 32), hex4)),
    rc: Array.from(C.sch.rc, hex4),
    traco_A: C.A.trace.map((s) => Array.from(s, hex4)),
    traco_B: C.B.trace.map((s) => Array.from(s, hex4)),
    saida_A: hex(C.dA), saida_B: hex(C.dB),
    diferencas_por_rodada: C.porRodada,
  };
  const txt = JSON.stringify(obj, null, 1);
  return { txt, h: hex(sha256(new TextEncoder().encode(txt))) };
}
function atualizarComandoReproduzir() {
  $('#exp-cmd').textContent = `python3 ferramentas/rsd_cli.py hash --x ${S.x} --y ${S.y} --key-hex ${$('#exp-chave').checked ? hex(S.chave) : '<chave-de-demonstracao-em-hex>'} --session ${S.nSess} --rounds ${S.rounds}`;
}

// ---------- montagem ----------
function desenharTudo() {
  $('#resumo-sessao').textContent = t('resumo_sessao', { x: S.x.toString().length > 20 ? S.x.toString().slice(0, 18) + '…' : S.x, y: S.y.toString().length > 20 ? S.y.toString().slice(0, 18) + '…' : S.y, n: S.nSess.toString().slice(0, 20), r: S.rounds, bit: S.bit, onde: S.bit < 255 ? `x[${S.bit}]` : `y[${S.bit - 255}]` });
  desenharRodada();
  desenharChaves();
  preparaSentinelas();
  atualizarComandoReproduzir();
}

function ligar() {
  $('#modo-explorar').addEventListener('click', () => definirModo('explorar'));
  $('#modo-verificar').addEventListener('click', () => definirModo('verificar'));
  $('#preset-dono').addEventListener('click', () => aplicarSessao(PRESET_DONO()));
  $('#sortear').addEventListener('click', () => aplicarSessao(sortear()));
  $('#form-sessao').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const r = lerFormulario();
    if (r.erros) { $('#erros-sessao').innerHTML = r.erros.map((e) => `<p>${esc(e)}</p>`).join(''); return; }
    aplicarSessao(r.S);
  });
  $('#momento').addEventListener('input', (e) => { momento = Number(e.target.value); desenharRodada(); });
  $('#mom-ant').addEventListener('click', () => { momento = Math.max(0, momento - 1); desenharRodada(); });
  $('#mom-prox').addEventListener('click', () => { momento = Math.min(S.rounds, momento + 1); desenharRodada(); });
  $('#ver-hex').addEventListener('change', alternarHex);
  $('#revelar-palpite').addEventListener('click', jogarPalpite);
  $('#sel-chave').addEventListener('input', desenharChaves);
  $('#feixe-disparar').addEventListener('click', dispararFeixe);
  $('#feixe-cancelar').addEventListener('click', () => { cancelarFeixe(); $('#feixe-resultado').innerHTML = `<p class="suave">${t('feixe_cancelado')}</p>`; });
  $('#sent-modo').addEventListener('change', atualizarDescSentinelas);
  $('#sent-executar').addEventListener('click', executarSentinelas);
  $('#kat-adulterar').addEventListener('click', () => { katAdulterado = true; desenharKat(); });
  $('#kat-restaurar').addEventListener('click', () => { katAdulterado = false; desenharKat(); });
  $('#exp-chave').addEventListener('change', atualizarComandoReproduzir);
  $('#exp-baixar').addEventListener('click', () => {
    const { txt, h } = exportar();
    const url = URL.createObjectURL(new Blob([txt], { type: 'application/json' }));
    const a = el('a', { href: url, download: 'basingse-rsd-s-v52-traco.json' });
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    $('#exp-hash').textContent = `SHA-256: ${h}`;
  });
  $('#exp-link').addEventListener('click', async () => {
    const link = location.href.split('#')[0] + '#' + paraFragmento(S, $('#exp-chave').checked);
    try { await navigator.clipboard.writeText(link); $('#exp-hash').textContent = t('exp_copiado'); } catch { $('#exp-hash').textContent = link; }
  });
}

function aoMudarFragmento() {
  const nova = location.hash.length > 1 ? deFragmento(location.hash) : null;
  if (nova) aplicarSessao(nova);
}

function iniciar() {
  const doLink = location.hash.length > 1 ? deFragmento(location.hash) : null;
  if (doLink) S = doLink;
  C = calcular(S);
  if (C.erro) { S = PRESET_DONO(); C = calcular(S); }
  preencherFormulario();
  preparaFeixe();
  ligar();
  desenharKat();
  desenharCercos();
  const m = lerGuardado('basingse-modo');
  definirModo(m === 'verificar' ? 'verificar' : 'explorar');
  desenharTudo();
  window.addEventListener('hashchange', aoMudarFragmento);
  document.documentElement.setAttribute('data-lab-pronto', '1');
}
iniciar();
