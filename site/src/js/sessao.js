// Sessão do laboratório: entrada (x, y, chave, sessão, rodadas), bit invertido e conversões.
// Um único objeto de sessão alimenta os dois modos (Explorar e Verificar): os números nunca divergem.
import { P } from './engine/rsd.js';
import { hex, fromHex } from './engine/hash.js';

export const CHAVE_DEMO_HEX = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join('');

export const PRESET_DONO = () => ({
  x: 1n, y: 2n, chave: fromHex(CHAVE_DEMO_HEX), nSess: 1n, rounds: 8, saida: 32, bit: 0,
});

export function sortear() {
  const buf = new Uint8Array(32 + 64 + 8);
  crypto.getRandomValues(buf);
  const big = (a) => a.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
  return {
    x: big(buf.subarray(32, 64)) % P, y: big(buf.subarray(64, 96)) % P, // 32 bytes cada
    chave: buf.slice(0, 32), nSess: big(buf.subarray(96, 104)), rounds: 8, saida: 32, bit: Math.floor(Math.random() * 510),
  };
}
// (buf tem 104 bytes: [0,32) chave, [32,64) x, [64,96) y, [96,104) sessão)

/** Interpreta decimal ou hexadecimal (0x...). Devolve BigInt ou null. */
export function lerInteiro(txt) {
  const s = String(txt).trim().replace(/[_\s]/g, '');
  if (/^0x[0-9a-f]+$/i.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}
export function lerChave(txt) {
  const s = String(txt).trim().replace(/^0x/i, '').replace(/\s+/g, '');
  if (!/^[0-9a-f]*$/i.test(s) || s.length !== 64) return null;
  return fromHex(s.toLowerCase());
}

/** Aplica o bit invertido: 0..254 em x, 255..509 em y. Devolve {x, y} da execução B ou {erro}. */
export function aplicarBit(S) {
  let { x, y } = S;
  if (S.bit < 255) x ^= 1n << BigInt(S.bit); else y ^= 1n << BigInt(S.bit - 255);
  if (x >= P || y >= P) return { erro: 'bit_fora' };
  return { x, y };
}

export function paraFragmento(S, incluirChave = false) {
  const p = new URLSearchParams({ x: S.x.toString(), y: S.y.toString(), n: S.nSess.toString(), r: String(S.rounds), bit: String(S.bit), o: String(S.saida) });
  if (incluirChave) p.set('k', hex(S.chave));
  return p.toString();
}
export function deFragmento(frag) {
  const p = new URLSearchParams(frag.replace(/^#/, ''));
  if (!p.has('x') || !p.has('y')) return null;
  try {
    const S = PRESET_DONO();
    S.x = BigInt(p.get('x')); S.y = BigInt(p.get('y')); S.nSess = BigInt(p.get('n') || '1');
    S.rounds = Math.min(255, Math.max(1, parseInt(p.get('r') || '8', 10) || 8));
    S.bit = Math.min(509, Math.max(0, parseInt(p.get('bit') || '0', 10) || 0));
    S.saida = p.get('o') === '64' ? 64 : 32;
    if (p.has('k')) { const k = lerChave(p.get('k')); if (k) S.chave = k; }
    if (S.x < 0n || S.x >= P || S.y < 0n || S.y >= P || S.nSess < 0n || S.nSess >= (1n << 64n)) return null;
    return S;
  } catch { return null; }
}
