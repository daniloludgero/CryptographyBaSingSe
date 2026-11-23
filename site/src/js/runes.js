// Sistema de glifos-chave (arte aprovada, Plano de Marca 8.3).
// Cada dígito hexadecimal (4 bits) é um quadrado 12x12 com quatro quadrantes 5x5:
//   bit 0 = superior esquerdo, bit 1 = superior direito, bit 2 = inferior esquerdo, bit 3 = inferior direito.
// Quadrante aceso = 1; apagado = 0. Nunca girar. Sem eixo central: não forma cruz, estrela nem crescente.
// Uma palavra de 16 bits é um bloco de 4 glifos em 2x2, dígito mais significativo primeiro, em ordem de leitura:
//   [d3 d2]
//   [d1 d0]
// O valor SEMPRE aparece também em texto (hexadecimal) ao lado. A figura nunca é a única informação.

export const COR = {
  moldura: '#533a28', apagado: '#3b2a1c', aceso: '#f2b84b', claro: '#fef8b6', escuro: '#c98a22',
};
export const QUADRANTES = [[0, 0], [5, 0], [0, 5], [5, 5]]; // deslocamentos (x, y) do bit 0..3

/** Pixels acesos (coordenadas 0..11) de um dígito hexadecimal. */
export function pixelsAcesos(digito) {
  const lit = new Set();
  QUADRANTES.forEach(([qx, qy], b) => {
    if ((digito >> b) & 1) for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) lit.add(`${1 + qx + x},${1 + qy + y}`);
  });
  return lit;
}

/** Cor de cada pixel 12x12 de um glifo (mesma regra de sombreamento da arte). */
export function corDoPixel(digito, x, y, lit = pixelsAcesos(digito)) {
  if (x === 0 || y === 0 || x === 11 || y === 11) return COR.moldura;
  if (!lit.has(`${x},${y}`)) return COR.apagado;
  let c = COR.aceso;
  if (!lit.has(`${x},${y - 1}`) || !lit.has(`${x - 1},${y}`)) c = COR.claro;
  if (!lit.has(`${x},${y + 1}`) || !lit.has(`${x + 1},${y}`)) c = COR.escuro;
  return c;
}

/** <symbol> SVG de um dígito, com retângulos agrupados por linha e cor. */
function simbolo(d) {
  const lit = pixelsAcesos(d);
  let r = '';
  for (let y = 0; y < 12; y++) {
    let x = 0;
    while (x < 12) {
      const c = corDoPixel(d, x, y, lit);
      let w = 1;
      while (x + w < 12 && corDoPixel(d, x + w, y, lit) === c) w++;
      r += `<rect x="${x}" y="${y}" width="${w}" height="1" fill="${c}"/>`;
      x += w;
    }
  }
  return `<symbol id="g${d.toString(16)}" viewBox="0 0 12 12">${r}</symbol>`;
}

/** Folha com os 16 símbolos; inserir uma única vez por página. */
export function folhaDeGlifos() {
  let s = '';
  for (let d = 0; d < 16; d++) s += simbolo(d);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" class="sprite-glifos" aria-hidden="true" focusable="false" shape-rendering="crispEdges">${s}</svg>`;
}

const POS = [[0, 0], [12, 0], [0, 12], [12, 12]]; // d3 d2 / d1 d0

/** SVG de um bloco (palavra de 16 bits). */
export function blocoSvg(palavra) {
  const ds = [(palavra >> 12) & 15, (palavra >> 8) & 15, (palavra >> 4) & 15, palavra & 15];
  const us = ds.map((d, i) => `<use href="#g${d.toString(16)}" x="${POS[i][0]}" y="${POS[i][1]}" width="12" height="12"/>`).join('');
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" shape-rendering="crispEdges">${us}</svg>`;
}

/** SVG de um byte (2 glifos lado a lado, nibble alto à esquerda), para o chaveiro. */
export function byteSvg(b) {
  const us = [(b >> 4) & 15, b & 15].map((d, i) => `<use href="#g${d.toString(16)}" x="${12 * i}" y="0" width="12" height="12"/>`).join('');
  return `<svg viewBox="0 0 24 12" aria-hidden="true" focusable="false" shape-rendering="crispEdges">${us}</svg>`;
}

export const hex4 = (w) => w.toString(16).padStart(4, '0');
export const hex2 = (b) => b.toString(16).padStart(2, '0');

/** Posição (centro do pixel, em unidades do viewBox 24x24) do quadrante do bit `bit` (0..15) de um bloco. */
export function centroDoBit(bit) {
  const nib = Math.floor(bit / 4), b = bit % 4;      // nib 0 = dígito menos significativo (d0)
  const pos = POS[3 - nib];                           // d0 -> posição 3 (BR) ... d3 -> posição 0 (TL)
  const [qx, qy] = QUADRANTES[b];
  return [pos[0] + 1 + qx + 2.5, pos[1] + 1 + qy + 2.5];
}
