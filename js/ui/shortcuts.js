// Lightweight command palette / keyboard shortcuts for SaaS UX
window.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    const q = prompt('Qidiruv / command: docs, ai, admin, saas, fishka');
    if(!q) return;
    const map = { docs:'docs', hujjat:'docs', ai:'aichat', chat:'aichat', admin:'admin', saas:'saas', fishka:'fishka', sozlama:'providers' };
    const key = Object.keys(map).find(k => q.toLowerCase().includes(k));
    if(key && window.showPanel) window.showPanel(map[key]);
  }
});
