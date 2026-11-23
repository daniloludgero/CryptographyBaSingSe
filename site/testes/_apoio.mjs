// Apoio aos testes E2E: servidor estático local, navegador e utilidades. Sem dependências além de
// playwright e axe-core (somente desenvolvimento; nada disso vai para o site).
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';
import { execFileSync } from 'node:child_process';

const AQUI = dirname(fileURLToPath(import.meta.url));
export const SITE = join(AQUI, '..');
export const DIST = join(SITE, 'dist');

const TIPOS = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
};

/** Faz o build e devolve { url, fechar }. O servidor só atende a pasta dist. */
export async function subirSite() {
  execFileSync(process.execPath, [join(SITE, 'ferramentas/build.mjs')], { stdio: 'pipe' });
  const servidor = createServer((req, res) => {
    let caminho = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (caminho.endsWith('/')) caminho += 'index.html';
    const arquivo = join(DIST, caminho);
    if (!arquivo.startsWith(DIST) || !existsSync(arquivo) || !statSync(arquivo).isFile()) { res.writeHead(404); res.end('não encontrado'); return; }
    res.writeHead(200, { 'content-type': TIPOS[extname(arquivo)] || 'application/octet-stream' });
    res.end(readFileSync(arquivo));
  });
  await new Promise((ok) => servidor.listen(0, '127.0.0.1', ok));
  const { port } = servidor.address();
  return { url: `http://127.0.0.1:${port}/`, porta: port, fechar: () => new Promise((ok) => servidor.close(ok)) };
}

export async function carregarPlaywright() {
  try { return await import('playwright'); } catch { /* tenta a instalação global */ }
  const { createRequire } = await import('node:module');
  const raiz = execFileSync('npm', ['root', '-g']).toString().trim();
  return createRequire(raiz + '/')('playwright');
}

export function axeFonte() {
  return readFileSync(join(SITE, 'node_modules/axe-core/axe.min.js'), 'utf8');
}

/** Lê os 16 bits de um bloco pelos pixels reais da tela (centro de cada quadrante) e devolve o valor. */
export async function lerBlocoPorPixels(page, seletorSvg) {
  const png = await page.locator(seletorSvg).first().screenshot();
  return page.evaluate(async (b64) => {
    const img = new Image();
    img.src = 'data:image/png;base64,' + b64;
    await img.decode();
    const c = document.createElement('canvas');
    c.width = img.width; c.height = img.height;
    const cx = c.getContext('2d', { willReadFrequently: true });
    cx.drawImage(img, 0, 0);
    const POS = [[0, 0], [12, 0], [0, 12], [12, 12]];
    const Q = [[0, 0], [5, 0], [0, 5], [5, 5]];
    let v = 0;
    for (let bit = 0; bit < 16; bit++) {
      const nib = Math.floor(bit / 4), b = bit % 4;
      const [px, py] = POS[3 - nib];
      const x = ((px + 1 + Q[b][0] + 2.5) / 24) * img.width;
      const y = ((py + 1 + Q[b][1] + 2.5) / 24) * img.height;
      const d = cx.getImageData(Math.floor(x), Math.floor(y), 1, 1).data;
      if ((d[0] + d[1] + d[2]) / 3 > 90) v |= 1 << bit; // acesos: amarelos (média > 130); apagado: #3b2a1c (média 44)
    }
    return v;
  }, png.toString('base64'));
}

export const esperar = (ms) => new Promise((ok) => setTimeout(ok, ms));
