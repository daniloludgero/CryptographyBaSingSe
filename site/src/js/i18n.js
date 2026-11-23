// Tradução: o build embute o dicionário do idioma da página em <script type="application/json" id="i18n">.
let D = {};
export function iniciarI18n() {
  const el = document.getElementById('i18n');
  D = el ? JSON.parse(el.textContent) : {};
}
export function t(chave, vars = {}) {
  const s = D[chave];
  if (s === undefined) return `⟦${chave}⟧`; // visível e detectável pelos testes
  return s.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? String(vars[k]) : `{${k}}`));
}
export const idioma = () => (document.documentElement.getAttribute('lang') || 'pt').slice(0, 2);
export const fmtNum = (n) => new Intl.NumberFormat(idioma() === 'pt' ? 'pt-BR' : 'en-US').format(n);
