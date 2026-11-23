// Comportamento comum: alternador de tema (claro/escuro/sistema).
(function () {
  var d = document.documentElement;
  var btn = document.getElementById('alternar-tema');
  var nome = document.getElementById('tema-nome');
  if (!btn) return;
  var idioma = (d.getAttribute('lang') || 'pt').slice(0, 2);
  var rot = idioma === 'en' ? { claro: 'light', escuro: 'dark', sistema: 'system' } : { claro: 'claro', escuro: 'escuro', sistema: 'sistema' };
  function atual() { var t = d.getAttribute('data-tema'); return t === 'claro' || t === 'escuro' ? t : 'sistema'; }
  function pintar() { var t = atual(); nome.textContent = rot[t]; btn.setAttribute('aria-pressed', t === 'escuro' ? 'true' : 'false'); }
  btn.addEventListener('click', function () {
    var prox = { sistema: 'claro', claro: 'escuro', escuro: 'sistema' }[atual()];
    if (prox === 'sistema') d.removeAttribute('data-tema'); else d.setAttribute('data-tema', prox);
    try { if (prox === 'sistema') localStorage.removeItem('basingse-tema'); else localStorage.setItem('basingse-tema', prox); } catch (e) { /* ignora */ }
    pintar();
  });
  pintar();
})();
