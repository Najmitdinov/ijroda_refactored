async function injectHtml(targetSelector, url) {
  const target = document.querySelector(targetSelector);
  if (!target) throw new Error(`Include target not found: ${targetSelector}`);
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Include failed: ${url}`);
  target.innerHTML = await response.text();
}

async function injectPanelPartials() {
  const placeholders = [...document.querySelectorAll('[data-panel-include]')];
  await Promise.all(placeholders.map(async (node) => {
    const url = node.dataset.panelInclude;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Panel include failed: ${url}`);
    const wrapper = document.createElement('div');
    wrapper.innerHTML = await response.text();
    node.replaceWith(...wrapper.childNodes);
  }));
}

window.addEventListener('DOMContentLoaded', async () => {
  try {
    if (window.location.protocol === 'file:') {
      throw new Error("index.html faylini to'g'ridan-to'g'ri ochmang. Papkadagi start_ijroda.bat faylini ishga tushiring yoki lokal server orqali oching.");
    }
    await injectHtml('#app-root', './components/app-shell.html');
    await injectPanelPartials();
    await import('./app.js');
    await import('./ui/drag-drop.js');
    await import('./ui/shortcuts.js');
  } catch (error) {
    console.error(error);
    document.body.innerHTML = `<pre style="padding:24px;color:#b91c1c;white-space:pre-wrap;">Dastur yuklanmadi: ${error.message}</pre>`;
  }
});
