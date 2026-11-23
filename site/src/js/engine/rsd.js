// Motor de referência da RSD-S v5.2 para o navegador (JavaScript puro).
// Porte fiel de implementacao/rsd_s_v5_hardened.py. A paridade bit a bit com o Python é
// conferida em site/testes/paridade.test.js (vetores congelados + casos aleatórios + rastros).
//
// ATENÇÃO: isto é uma DEMONSTRAÇÃO. Usa tabelas indexadas por valores secretos, portanto NÃO é
// tempo constante, e o navegador não controla memória nem canais laterais.
import { sha256, hmacSha256, shake256 } from './hash.js';

export const W = 32;
export const R_V5 = 8;
export const P = (1n << 255n) - 19n;
export const GF16_POLY = 0x1100b;
export const AFFINE_CONST = 0x63a9;
const AFFINE_ROTATIONS = [0, 1, 2, 3, 4, 5, 7, 11, 13];
const enc = new TextEncoder();

// ---------- GF(2^16) por tabelas log/antilog ----------
const EXP = new Uint16Array(131070); // duplicada para evitar módulo na soma de logs
const LOG = new Int32Array(65536).fill(-1);
(function buildTables() {
  let x = 1;
  for (let i = 0; i < 65535; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x10000) x ^= GF16_POLY;
  }
  if (x !== 1) throw new Error('2 não gera o grupo multiplicativo de GF(2^16)');
  for (let i = 65535; i < 131070; i++) EXP[i] = EXP[i - 65535];
})();

export function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}
export function gfInv(a) {
  return a === 0 ? 0 : EXP[65535 - LOG[a]];
}
const rotl16 = (v, k) => ((v << k) | (v >>> (16 - k))) & 0xffff;
export function affine16(v) {
  let acc = 0;
  for (const k of AFFINE_ROTATIONS) acc ^= rotl16(v, k);
  return acc & 0xffff;
}

/** S-box v5: S(u) = A16(u^-1) xor 0x63A9. */
export const SBOX = new Uint16Array(65536);
for (let u = 0; u < 65536; u++) SBOX[u] = affine16(gfInv(u)) ^ AFFINE_CONST;

// ---------- MDS 32x32: M[i][j] = (i xor (32 + p(j)))^-1, p(j) = (5j+1) mod 32 ----------
export const MDS_COL_PERM = Array.from({ length: W }, (_, j) => (5 * j + 1) % W);
export const MDS = new Uint16Array(W * W);
const LOGM = new Int32Array(W * W);
for (let i = 0; i < W; i++) {
  for (let j = 0; j < W; j++) {
    const v = gfInv(i ^ (32 + MDS_COL_PERM[j]));
    MDS[i * W + j] = v;
    LOGM[i * W + j] = LOG[v];
  }
}

// ---------- validação (mensagens iguais às do Python) ----------
function bigintOf(v, nome) {
  if (typeof v === 'bigint') return v;
  throw new TypeError(`${nome} deve ser um inteiro`);
}
export function validateField(v, nome) {
  v = bigintOf(v, nome);
  if (v < 0n || v >= P) throw new RangeError(`${nome} deve satisfazer 0 <= ${nome} < 2^255 - 19`);
}
export function validateKey(s) {
  if (!(s instanceof Uint8Array)) throw new TypeError('s deve ser bytes');
  if (s.length !== 32) throw new RangeError('s deve ter exatamente 32 bytes');
}
export function validateSession(n) {
  n = bigintOf(n, 'n_sess');
  if (n < 0n || n > (1n << 64n) - 1n) throw new RangeError('n_sess deve satisfazer 0 <= n_sess < 2^64');
}
export function validateRounds(r) {
  if (!Number.isInteger(r)) throw new TypeError('rounds deve ser um inteiro');
  if (r < 1 || r > 255) throw new RangeError('rounds deve satisfazer 1 <= rounds <= 255');
}

// ---------- fragmentação, chaves, constantes ----------
export function fragment(x, y) {
  validateField(x, 'x');
  validateField(y, 'y');
  const out = new Uint16Array(W);
  for (let j = 0; j < 16; j++) {
    out[j] = Number((x >> BigInt(16 * j)) & 0xffffn);
    out[16 + j] = Number((y >> BigInt(16 * j)) & 0xffffn);
  }
  return out;
}

export function domainTag(nSess, rounds) {
  const prefix = enc.encode('RSD-S-V5.1|CORE|');
  const out = new Uint8Array(prefix.length + 1 + 8);
  out.set(prefix);
  out[prefix.length] = rounds;
  let n = nSess;
  for (let i = 7; i >= 0; i--) {
    out[prefix.length + 1 + i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export function deriveKeys(s, nSess, rounds) {
  validateKey(s); validateSession(nSess); validateRounds(rounds);
  const dom = domainTag(nSess, rounds);
  const keys = [hmacSha256(s, cat(dom, Uint8Array.of(0)))];
  for (let r = 1; r <= rounds; r++) keys.push(hmacSha256(s, cat(keys[r - 1], dom, Uint8Array.of(r))));
  return keys;
}

export function roundConstant(s, nSess, r, rounds) {
  const dom = domainTag(nSess, rounds);
  const h = hmacSha256(s, cat(dom, enc.encode('RC'), Uint8Array.of(r)));
  return (h[0] << 8) | h[1];
}

/** Expansão da chave de rodada em 32 palavras big-endian (HMAC em todos os blocos, RT-F1-01). */
export function expandWords(keyBytes) {
  const material = new Uint8Array(64);
  for (let blk = 0; blk < 2; blk++) {
    const idx = Uint8Array.of(0, 0, 0, blk);
    material.set(hmacSha256(keyBytes, cat(enc.encode('EXP|'), idx)), 32 * blk);
  }
  const out = new Uint16Array(W);
  for (let i = 0; i < W; i++) out[i] = (material[2 * i] << 8) | material[2 * i + 1];
  return out;
}

/** Agenda completa: rk[(rounds+1)*32], rc[rounds] e as chaves K_r. */
export function schedule(s, nSess, rounds) {
  const keys = deriveKeys(s, nSess, rounds);
  const rk = new Uint16Array((rounds + 1) * W);
  for (let r = 0; r <= rounds; r++) rk.set(expandWords(keys[r]), r * W);
  const rc = new Uint16Array(rounds);
  for (let r = 1; r <= rounds; r++) rc[r - 1] = roundConstant(s, nSess, r, rounds);
  return { keys, rk, rc, rounds };
}

// ---------- rodada ----------
const acc = new Uint16Array(W);
/** Uma rodada: S-box por palavra xor rc, MDS 32x32, xor da chave. Escreve em `out`. */
export function singleRound(state, rc, rk, rkOff, out) {
  acc.fill(0);
  for (let j = 0; j < W; j++) {
    const u = SBOX[state[j]] ^ rc;
    if (u === 0) continue;
    const lu = LOG[u];
    for (let i = 0; i < W; i++) acc[i] ^= EXP[lu + LOGM[i * W + j]];
  }
  for (let i = 0; i < W; i++) out[i] = acc[i] ^ rk[rkOff + i];
}

/** Caminho rápido (um fluxo) usado nas missões em massa. Devolve o estado pré-SHA. */
export function rawRounds(inState, sched, rounds = sched.rounds, out = new Uint16Array(W)) {
  const a = new Uint16Array(W), b = new Uint16Array(W);
  for (let i = 0; i < W; i++) a[i] = inState[i] ^ sched.rk[i];
  let cur = a, nxt = b;
  for (let r = 1; r <= rounds; r++) {
    singleRound(cur, sched.rc[r - 1], sched.rk, r * W, nxt);
    const t = cur; cur = nxt; nxt = t;
  }
  out.set(cur);
  return out;
}

/**
 * Núcleo com proteção Anti-DFA (v5.2): fluxos A e B percorrem R1..R e são comparados ao final.
 * fault = { round, word, mask, modo } injeta uma falha. Modos:
 *   'A'      (padrão) só no fluxo A, na entrada da rodada `round`: é o que a v5.2 detecta.
 *   'ambos'  a mesma falha nos dois fluxos: LIMITE da redundância (não é detectada).
 *   'antes'  no estado inicial, antes de copiar para A e B (ignora `round`): LIMITE (não é detectada).
 * Os modos 'ambos' e 'antes' são cenários didáticos construídos aqui; o núcleo C só injeta em A.
 * Devolve { status: 0 | -2, state, trace, finalA, finalB }. trace = estado do fluxo B após cada
 * rodada (índice 0 = depois da soma de rk[0]). Em caso de divergência `state` é zerado (status -2),
 * mas finalA e finalB preservam o que cada fluxo calculou, para mostrar a divergência.
 */
export function core(inState, sched, fault = null) {
  const rounds = sched.rounds;
  const modo = (fault && fault.modo) || 'A';
  const sa = new Uint16Array(W), sb = new Uint16Array(W);
  for (let i = 0; i < W; i++) sa[i] = sb[i] = inState[i] ^ sched.rk[i];
  if (fault && modo === 'antes' && fault.word >= 0 && fault.word < W) {
    sa[fault.word] ^= fault.mask & 0xffff; sb[fault.word] ^= fault.mask & 0xffff;
  }
  const trace = [Uint16Array.from(sb)];
  const na = new Uint16Array(W), nb = new Uint16Array(W);
  for (let r = 1; r <= rounds; r++) {
    if (fault && fault.round === r && fault.word >= 0 && fault.word < W && modo !== 'antes') {
      sa[fault.word] ^= fault.mask & 0xffff;
      if (modo === 'ambos') sb[fault.word] ^= fault.mask & 0xffff;
    }
    singleRound(sa, sched.rc[r - 1], sched.rk, r * W, na);
    singleRound(sb, sched.rc[r - 1], sched.rk, r * W, nb);
    sa.set(na); sb.set(nb);
    trace.push(Uint16Array.from(sb));
  }
  let diff = 0;
  for (let i = 0; i < W; i++) diff |= sa[i] ^ sb[i];
  const finalA = Uint16Array.from(sa), finalB = Uint16Array.from(sb);
  if (diff !== 0) return { status: -2, state: new Uint16Array(W), trace, finalA, finalB };
  return { status: 0, state: Uint16Array.from(sa), trace, finalA, finalB };
}

export function serialize(state) {
  const out = new Uint8Array(64);
  for (let i = 0; i < W; i++) { out[2 * i] = state[i] >>> 8; out[2 * i + 1] = state[i] & 255; }
  return out;
}

/** API oficial: SHA-256 (32 B) ou SHAKE256 (64 B) sobre dom || estado. Equivale a diffuse_rsd_s_v5. */
export function digest(x, y, s, nSess, rounds = R_V5, outputBytes = 32) {
  if (outputBytes !== 32 && outputBytes !== 64) throw new RangeError('output_bytes deve ser 32 (256 bits) ou 64 (512 bits)');
  validateField(x, 'x'); validateField(y, 'y'); validateKey(s); validateSession(nSess); validateRounds(rounds);
  const sched = schedule(s, nSess, rounds);
  const res = core(fragment(x, y), sched);
  if (res.status !== 0) throw new Error('Anti-DFA: divergência detectada entre execuções redundantes (R1..R); saída abortada.');
  const raw = serialize(res.state);
  const dom = domainTag(nSess, rounds);
  return outputBytes === 32 ? sha256(cat(dom, raw)) : shake256(cat(dom, enc.encode('|XOF512|'), raw), 64);
}

// utilitários de diferença
export function popcount16(v) { v = v - ((v >>> 1) & 0x5555); v = (v & 0x3333) + ((v >>> 2) & 0x3333); v = (v + (v >>> 4)) & 0x0f0f; return (v + (v >>> 8)) & 0x1f; }
export function diffStats(a, b) {
  let words = 0, bits = 0;
  for (let i = 0; i < W; i++) { const d = a[i] ^ b[i]; if (d) { words++; bits += popcount16(d); } }
  return { words, bits };
}
