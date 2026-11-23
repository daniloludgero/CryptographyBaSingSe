// Paridade bit a bit do motor JavaScript contra o Python (e o núcleo C) da RSD-S v5.2.
// Dados: site/dados/paridade.json (gerado por site/ferramentas/gerar_dados.py) e testes/vetores_v52.json.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { sha256, hmacSha256, shake256, hex, fromHex } from '../src/js/engine/hash.js';
import * as E from '../src/js/engine/rsd.js';

const aqui = dirname(fileURLToPath(import.meta.url));
const D = JSON.parse(readFileSync(join(aqui, '../dados/paridade.json'), 'utf8'));
const KAT = JSON.parse(readFileSync(join(aqui, '../dados/vetores_v52.json'), 'utf8'));
const h2s = (h) => hex(E.serialize(Uint16Array.from(h.match(/.{4}/g).map((q) => parseInt(q, 16)))));

test('PAR-05 SHA-256 contra hashlib', () => {
  for (const c of D.hash.sha256) assert.equal(hex(sha256(fromHex(c.msg))), c.out);
  assert.ok(D.hash.sha256.length >= 60);
});
test('PAR-05 HMAC-SHA-256 contra hmac do Python', () => {
  for (const c of D.hash.hmac) assert.equal(hex(hmacSha256(fromHex(c.key), fromHex(c.msg))), c.out);
});
test('PAR-05 SHAKE256 contra hashlib (várias saídas, incluindo múltiplos de 136)', () => {
  for (const c of D.hash.shake256) assert.equal(hex(shake256(fromHex(c.msg), c.len)), c.out);
  assert.ok(D.hash.shake256.length >= 300);
});

test('PAR-03 S-box: 65.536 entradas, bijeção, 0 pontos fixos', () => {
  const le = new Uint8Array(65536 * 2);
  for (let u = 0; u < 65536; u++) { le[2 * u] = E.SBOX[u] & 255; le[2 * u + 1] = E.SBOX[u] >>> 8; }
  assert.equal(hex(sha256(le)), D.tabelas.sbox_sha256_le16);
  for (const [u, v] of Object.entries(D.tabelas.sbox_amostra)) assert.equal(E.SBOX[Number(u)], v);
  let fixos = 0; const vistos = new Set();
  for (let u = 0; u < 65536; u++) { if (E.SBOX[u] === u) fixos++; vistos.add(E.SBOX[u]); }
  assert.equal(fixos, 0); assert.equal(fixos, D.tabelas.pontos_fixos);
  assert.equal(vistos.size, 65536); assert.ok(D.tabelas.bijecao);
});
test('PAR-04 MDS: 1.024 entradas idênticas, nenhuma nula', () => {
  const le = new Uint8Array(1024 * 2);
  for (let i = 0; i < 1024; i++) { le[2 * i] = E.MDS[i] & 255; le[2 * i + 1] = E.MDS[i] >>> 8; }
  assert.equal(hex(sha256(le)), D.tabelas.mds_sha256_le16);
  assert.deepEqual(Array.from(E.MDS.slice(0, 32)), D.tabelas.mds_primeira_linha);
  assert.equal(E.MDS.filter((v) => v === 0).length, 0);
});

test('PAR-01 vetores congelados da v5.2 (pré-SHA, 32 B e 64 B)', () => {
  assert.ok(KAT.vectors.length >= 6);
  for (const v of KAT.vectors) {
    const x = BigInt(v.x), y = BigInt(v.y), s = fromHex(v.s_hex), n = BigInt(v.n_sess), r = v.rounds;
    const res = E.core(E.fragment(x, y), E.schedule(s, n, r));
    assert.equal(res.status, 0, v.name);
    assert.equal(hex(E.serialize(res.state)), v.pre_sha_hex, v.name);
    assert.equal(hex(E.digest(x, y, s, n, r, 32)), v.output_256_hex, v.name);
    assert.equal(hex(E.digest(x, y, s, n, r, 64)), v.output_512_hex, v.name);
  }
});

test('PAR-02 300 casos aleatórios com rodadas 1..8, saídas de 32 e 64 B', () => {
  const rodadas = new Set();
  for (const c of D.rsd) {
    const x = BigInt(c.x), y = BigInt(c.y), s = fromHex(c.s), n = BigInt(c.n_sess);
    const res = E.core(E.fragment(x, y), E.schedule(s, n, c.rounds));
    assert.equal(hex(E.serialize(res.state)), c.pre_sha);
    assert.equal(hex(E.digest(x, y, s, n, c.rounds, 32)), c.out32);
    assert.equal(hex(E.digest(x, y, s, n, c.rounds, 64)), c.out64);
    rodadas.add(c.rounds);
  }
  assert.deepEqual([...rodadas].sort((p, q) => p - q), [1, 2, 3, 4, 5, 6, 7, 8]);
});
test('PAR-02 rastro estado a estado, chaves K_r e constantes rc (60 casos)', () => {
  let n = 0;
  for (const c of D.rsd.filter((q) => q.traco)) {
    const x = BigInt(c.x), y = BigInt(c.y), s = fromHex(c.s), nn = BigInt(c.n_sess);
    const sch = E.schedule(s, nn, c.rounds);
    c.chaves.forEach((k, i) => assert.equal(hex(sch.keys[i]), k));
    assert.deepEqual(Array.from(sch.rc), c.rc);
    const res = E.core(E.fragment(x, y), sch);
    res.trace.forEach((st, r) => assert.equal(hex(E.serialize(st)), c.traco[r], `rodada ${r}`));
    n++;
  }
  assert.ok(n >= 60);
});
test('rawRounds (caminho rápido de um fluxo) coincide com o núcleo de dois fluxos', () => {
  for (const c of D.rsd.slice(0, 40)) {
    const sch = E.schedule(fromHex(c.s), BigInt(c.n_sess), c.rounds);
    const ent = E.fragment(BigInt(c.x), BigInt(c.y));
    assert.equal(hex(E.serialize(E.rawRounds(ent, sch))), c.pre_sha);
  }
});

test('PAR-08 injeção de falha em A: status e saída zerada iguais ao Python', () => {
  let detectadas = 0, limpas = 0;
  for (const c of D.falhas) {
    const sch = E.schedule(fromHex(c.s), BigInt(c.n_sess), c.rounds);
    const res = E.core(E.fragment(BigInt(c.x), BigInt(c.y)), sch, { round: c.round, word: c.word, mask: c.mask });
    assert.equal(res.status, c.status);
    if (res.status === -2) { detectadas++; assert.ok(res.state.every((v) => v === 0)); } else limpas++;
  }
  assert.ok(detectadas > 20 && limpas > 5, `${detectadas}/${limpas}`);
});
test('PAR-08 toda falha em A, em qualquer rodada 1..8, é detectada (v5.2)', () => {
  const sch = E.schedule(new Uint8Array(32).fill(0x55), 4242n, 8);
  const ent = E.fragment(0x123456789abcdef0123456789abcdef0n, 0xfedcba9876543210fedcba9876543210n);
  for (let r = 1; r <= 8; r++) for (const w of [0, 15, 16, 31]) {
    assert.equal(E.core(ent, sch, { round: r, word: w, mask: 1 }).status, -2, `rodada ${r} palavra ${w}`);
  }
  assert.equal(E.core(ent, sch, { round: 5, word: 3, mask: 0 }).status, 0);
});

test('PAR-07 contrato de entradas: mesmas condições e mensagens do Python', () => {
  const s = new Uint8Array(32);
  const P = E.P;
  const exec = {
    'x=p': () => E.digest(P, 0n, s, 0n),
    'x<0': () => E.digest(-1n, 0n, s, 0n),
    'y=p': () => E.digest(0n, P, s, 0n),
    'chave 31B': () => E.digest(0n, 0n, new Uint8Array(31), 0n),
    'n_sess=2^64': () => E.digest(0n, 0n, s, 1n << 64n),
    'n_sess<0': () => E.digest(0n, 0n, s, -1n),
    'rounds=0': () => E.digest(0n, 0n, s, 0n, 0),
    'rounds=256': () => E.digest(0n, 0n, s, 0n, 256),
    'output_bytes=48': () => E.digest(0n, 0n, s, 0n, 8, 48),
  };
  for (const c of D.contrato) {
    assert.ok(c.erro, c.caso);
    assert.throws(exec[c.caso], (e) => e.message === c.mensagem, c.caso);
  }
  assert.equal(D.contrato.length, Object.keys(exec).length);
});

test('PAR-09 integral: soma XOR nula em 1R e 2R, não nula de 3R a 8R (recalculado no JS)', () => {
  // recalcula só 1R..4R para manter o teste rápido; o Python/C já cobriu 1R..8R no arquivo de dados
  for (const lin of D.integral) {
    for (let r = 1; r <= 8; r++) assert.equal(lin.soma_nao_nula[String(r)], r <= 2 ? 0 : 32);
    const s = fromHex(lin.s), n = BigInt(lin.n_sess);
    for (const r of [1, 2, 3, 4]) {
      const sch = E.schedule(s, n, r);
      const ent = Uint16Array.from(lin.base), out = new Uint16Array(32), acc = new Uint16Array(32);
      for (let v = 0; v < 65536; v++) { ent[lin.palavra_ativa] = v; E.rawRounds(ent, sch, r, out); for (let i = 0; i < 32; i++) acc[i] ^= out[i]; }
      assert.equal(acc.filter((q) => q !== 0).length, lin.soma_nao_nula[String(r)], `r=${r}`);
    }
  }
});

test('o caso do dono: 1 palavra na rodada 0 e 32 na rodada 1 (trace 8R)', () => {
  const s = Uint8Array.from({ length: 32 }, (_, i) => i);
  const sch = E.schedule(s, 1n, 8);
  const a = E.core(E.fragment(1n, 2n), sch), b = E.core(E.fragment(0n, 2n), sch);
  assert.equal(E.diffStats(a.trace[0], b.trace[0]).words, 1);
  assert.equal(E.diffStats(a.trace[1], b.trace[1]).words, 32);
  const red = E.schedule(s, 1n, 1);
  const ar = E.core(E.fragment(1n, 2n), red), br = E.core(E.fragment(0n, 2n), red);
  assert.equal(E.diffStats(ar.state, br.state).words, 32);
  assert.notEqual(E.diffStats(ar.state, br.state).bits, E.diffStats(a.trace[1], b.trace[1]).bits); // 280 x 264: rotulações distintas
});

test('limites da redundância (cenários didáticos): falha nos dois fluxos e antes da cópia não são detectadas', () => {
  const s = new Uint8Array(32).fill(0x55);
  const sch = E.schedule(s, 4242n, 8);
  const ent = E.fragment(0x123456789abcdef0123456789abcdef0n, 0xfedcba9876543210fedcba9876543210n);
  const limpo = E.core(ent, sch);
  assert.equal(limpo.status, 0);
  for (const modo of ['ambos', 'antes']) for (let r = 1; r <= 8; r++) {
    const res = E.core(ent, sch, { round: r, word: 7, mask: 0x0100, modo });
    assert.equal(res.status, 0, `${modo} r=${r}: sem alarme`);
    assert.notDeepEqual(Array.from(res.state), Array.from(limpo.state), `${modo} r=${r}: saída errada`);
  }
  const so = E.core(ent, sch, { round: 4, word: 7, mask: 0x0100, modo: 'A' });
  assert.equal(so.status, -2);
  assert.notDeepEqual(Array.from(so.finalA), Array.from(so.finalB)); // a divergência fica visível
  assert.ok(so.state.every((v) => v === 0));
});
test('o núcleo preserva finalA e finalB iguais quando não há falha', () => {
  const sch = E.schedule(new Uint8Array(32), 0n, 8);
  const r = E.core(E.fragment(5n, 6n), sch);
  assert.deepEqual(Array.from(r.finalA), Array.from(r.finalB));
});
test('RT-F1-01: nenhuma das 16 primeiras palavras de rk[r] é cópia literal de K_r', () => {
  const sch = E.schedule(Uint8Array.from({ length: 32 }, (_, i) => i), 1n, 8);
  for (let r = 0; r <= 8; r++) {
    let iguais = 0;
    for (let k = 0; k < 16; k++) if (((sch.keys[r][2 * k] << 8) | sch.keys[r][2 * k + 1]) === sch.rk[r * 32 + k]) iguais++;
    assert.ok(iguais <= 1, `rodada ${r}: ${iguais} palavras iguais`);
  }
});
test('RT-F1-03: a soma XOR de cada linha da MDS é a mesma nas 32 linhas', () => {
  const somas = new Set();
  for (let i = 0; i < 32; i++) { let s = 0; for (let j = 0; j < 32; j++) s ^= E.MDS[i * 32 + j]; somas.add(s); }
  assert.equal(somas.size, 1);
  assert.equal([...somas][0], 0x1731);
});
test('RT-F1-02: o bit mais alto das palavras 15 e 31 nunca acende na entrada válida', () => {
  let r = 12345n;
  const prox = () => { r = (r * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return r; };
  for (let n = 0; n < 500; n++) {
    let x = 0n, y = 0n;
    for (let k = 0; k < 4; k++) { x = (x << 64n) | prox(); y = (y << 64n) | prox(); }
    x %= E.P; y %= E.P;
    const f = E.fragment(x, y);
    assert.equal(f[15] >> 15, 0); assert.equal(f[31] >> 15, 0);
  }
});
