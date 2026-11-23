// A explicação da missão do Feixe tem de bater com o cálculo: valores distintos por palavra de saída e soma XOR.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as E from '../src/js/engine/rsd.js';

function feixe(r, ativa = 0) {
  const sch = E.schedule(Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 255), 5n, r);
  const ent = E.fragment(123456789n, 987654321n), out = new Uint16Array(32), acc = new Uint16Array(32);
  const vistos = Array.from({ length: 32 }, () => new Uint8Array(65536));
  for (let v = 0; v < 65536; v++) { ent[ativa] = v; E.rawRounds(ent, sch, r, out); for (let i = 0; i < 32; i++) { acc[i] ^= out[i]; vistos[i][out[i]] = 1; } }
  const dist = vistos.map((a) => a.reduce((s, x) => s + x, 0));
  return { soma0: acc.filter((v) => v === 0).length, permutacoes: dist.filter((d) => d === 65536).length, minDistintos: Math.min(...dist) };
}

test('1 rodada: as 32 palavras de saída são permutações do feixe e a soma zera nas 32', () => {
  const f = feixe(1);
  assert.equal(f.permutacoes, 32); assert.equal(f.soma0, 32);
});
test('2 rodadas: a soma zera nas 32, mas a saída NÃO é permutação (a explicação é a linearidade)', () => {
  const f = feixe(2);
  assert.equal(f.soma0, 32); assert.equal(f.permutacoes, 0); assert.ok(f.minDistintos < 65536 && f.minDistintos > 30000);
});
test('3 rodadas: a soma não zera em nenhuma palavra', () => {
  assert.equal(feixe(3).soma0, 0);
});
