// Apply theme immediately before anything renders — prevents flash
(function(){
  const t = localStorage.getItem('ijroda_theme') || 'light';
  document.documentElement.setAttribute('data-theme', t);
})();
