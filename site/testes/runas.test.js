// Glifos-chave: o desenho nunca altera o valor (Plano de Marca 8.3 e Plano do Laboratório 4.5).
import test from 'node:test';
import assert from 'node:assert/strict';
import { corDoPixel, pixelsAcesos, centroDoBit, COR, blocoSvg, byteSvg, folhaDeGlifos } from '../src/js/runes.js';

// posição do dígito dentro do bloco: d3 d2 / d1 d0
const POS = [[0, 0], [12, 0], [0, 12], [12, 12]];

function lerBloco(w) {
  // reconstrói a palavra lendo apenas a cor do pixel central de cada quadrante, como um teste de pixels faria
  let v = 0;
  const dig = [(w >> 12) & 15, (w >> 8) & 15, (w >> 4) & 15, w & 15];
  for (let bit = 0; bit < 16; bit++) {
    const [cx, cy] = centroDoBit(bit);
    const i = POS.findIndex(([px, py]) => cx >= px && cx < px + 12 && cy >= py && cy < py + 12);
    const lx = Math.floor(cx - POS[i][0]), ly = Math.floor(cy - POS[i][1]);
    const cor = corDoPixel(dig[i], lx, ly);
    if (cor !== COR.apagado && cor !== COR.moldura) v |= 1 << bit;
  }
  return v;
}

test('ida e volta: as 65.536 palavras reconstroem o próprio valor', () => {
  for (let w = 0; w < 65536; w++) assert.equal(lerBloco(w), w);
});
test('os 16 glifos são distintos e distam pelo menos 25 pixels (um quadrante) entre si', () => {
  const g = Array.from({ length: 16 }, (_, d) => {
    const lit = pixelsAcesos(d); const m = [];
    for (let y = 0; y < 12; y++) for (let x = 0; x < 12; x++) m.push(corDoPixel(d, x, y, lit));
    return m;
  });
  let min = 999;
  for (let a = 0; a < 16; a++) for (let b = a + 1; b < 16; b++) {
    let d = 0; for (let i = 0; i < 144; i++) if (g[a][i] !== g[b][i]) d++;
    min = Math.min(min, d);
  }
  assert.ok(min >= 25, `distância mínima ${min}`);
});
test('o glifo F é o único com os 4 quadrantes e 0 não tem pixel aceso', () => {
  assert.equal(pixelsAcesos(0).size, 0);
  assert.equal(pixelsAcesos(15).size, 100);
  assert.equal(pixelsAcesos(1).size, 25);
});
test('SVG gerado: bloco com 4 glifos, byte com 2, folha com 16 símbolos', () => {
  assert.equal((blocoSvg(0xd626).match(/<use /g) || []).length, 4);
  assert.match(blocoSvg(0xd626), /#gd".*#g6".*#g2".*#g6"/s); // d, 6, 2, 6 em ordem de leitura
  assert.equal((byteSvg(0x1f).match(/<use /g) || []).length, 2);
  assert.equal((folhaDeGlifos().match(/<symbol /g) || []).length, 16);
});
test('nenhum glifo usa pixels de fora dos quadrantes (sem eixo de cruz)', () => {
  for (let d = 0; d < 16; d++) for (const k of pixelsAcesos(d)) {
    const [x, y] = k.split(',').map(Number);
    assert.ok(x >= 1 && x <= 10 && y >= 1 && y <= 10);
  }
});
