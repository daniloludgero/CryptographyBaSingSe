// Aplica o tema salvo antes da primeira pintura (evita "piscar"). Sem dependências.
// localStorage pode lançar exceção (janela privada, bloqueio): tudo em try/catch, e a página funciona sem ele.
(function () {
  var d = document.documentElement;
  d.classList.add('js');
  try {
    var t = localStorage.getItem('basingse-tema');
    if (t === 'claro' || t === 'escuro') d.setAttribute('data-tema', t);
    var m = localStorage.getItem('basingse-modo');
    if (m === 'explorar' || m === 'verificar') d.setAttribute('data-modo', m);
  } catch (e) { /* sem armazenamento: usa o tema do sistema */ }
  if (!d.hasAttribute('data-modo')) d.setAttribute('data-modo', 'explorar');
})();
