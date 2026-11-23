// Worker da missão "Feixe de Espelhos": percorre os 65.536 valores de UMA palavra (as outras 31 ficam
// fixas) em uma instância reduzida de `rounds` rodadas e soma (XOR) as 32 saídas pré-hash.
// Também conta quantos valores distintos cada palavra de saída assume: quando a saída é uma permutação
// do feixe (65.536 distintos), a soma de todos os valores é zero por construção. O resultado vem do
// cálculo; nada é roteirizado. Cancelável com worker.terminate().
import { schedule, rawRounds, W } from './engine/rsd.js';
import { fromHex } from './engine/hash.js';

self.onmessage = (ev) => {
  const { chave, n, rounds, ativa, base } = ev.data;
  const t0 = performance.now();
  const sch = schedule(fromHex(chave), BigInt(n), rounds);
  const ent = Uint16Array.from(base);
  const out = new Uint16Array(W);
  const acc = new Uint16Array(W);
  const vistos = Array.from({ length: W }, () => new Uint8Array(65536));
  const LOTE = 4096;
  let tons = new Uint8Array(LOTE);
  for (let v = 0; v < 65536; v++) {
    ent[ativa] = v;
    rawRounds(ent, sch, rounds, out);
    for (let i = 0; i < W; i++) { acc[i] ^= out[i]; vistos[i][out[i]] = 1; }
    tons[v % LOTE] = out[ativa] & 3; // 2 bits reais da saída da palavra variada, para o mosaico
    if ((v + 1) % LOTE === 0) {
      if (v + 1 < 65536) { self.postMessage({ tipo: 'prog', feito: v + 1, tons }, [tons.buffer]); tons = new Uint8Array(LOTE); }
      else self.postMessage({ tipo: 'prog', feito: v + 1, tons });
    }
  }
  const distintos = vistos.map((a) => { let c = 0; for (let k = 0; k < 65536; k++) c += a[k]; return c; });
  self.postMessage({ tipo: 'fim', soma: Array.from(acc), distintos, ms: Math.round(performance.now() - t0) });
};
