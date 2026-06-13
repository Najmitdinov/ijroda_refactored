import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../', import.meta.url);
const read = path => readFileSync(new URL(path, root), 'utf8');
const shell = read('components/app-shell.html');
const saas = read('components/panels/saas.html');
const superadmin = read('components/panels/superadmin.html');
const app = read('js/app.js');
const css = read('css/main.css');
const bootstrap = read('js/bootstrap.js');
const index = read('index.html');

assert.equal(
  (shell.match(/components\/panels\/saas\.html/g) || []).length,
  1,
  'SaaS panel partial app shell ichida aynan bir marta ulanadi'
);
assert.match(saas, /id="panel-saas"/, 'SaaS panel root mavjud');
assert.doesNotMatch(superadmin, /id="panel-saas"/, 'SaaS panel Super Admin panel ichiga joylashtirilmagan');

const requiredIds = [
  'saas-users',
  'saas-dau',
  'saas-orgs',
  'saas-ai',
  'saas-uploads',
  'saas-risk-count',
  'saas-health',
  'saas-plan-breakdown',
  'saas-org-rows',
  'saas-ai-chart',
  'saas-settings-form',
  'saas-risk-list',
  'saas-activity-list',
  'saas-ai-logs'
];
for (const id of requiredIds) {
  assert.match(saas, new RegExp(`id="${id}"`), `${id} elementi mavjud`);
}

const ids = [...saas.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
assert.deepEqual(duplicates, [], 'SaaS panel ichida takroriy ID yo‘q');

assert.match(app, /async function renderSaasConsole\(force=false\)/, 'SaaS render funksiyasi mavjud');
assert.match(app, /if \(name === 'saas'\) renderSaasConsole\(\);/, 'SaaS menyudan ochilganda yuklanadi');
assert.match(app, /window\.exportSaasSnapshot/, 'SaaS eksport funksiyasi mavjud');
assert.match(app, /window\.filterSaasOrganizations/, 'Tashkilot filtri mavjud');
assert.match(app, /window\.filterSaasAiLogs/, 'AI log filtri mavjud');
assert.match(app, /fallbackRef/, 'Firestore log so‘rovi uchun zaxira o‘qish mavjud');
assert.match(app, /readFailures:readErrors\.length/, 'Firestore o‘qish xatolari xavf signaliga ulanadi');
assert.match(app, /Sozlamalar saqlanmadi:/, 'Sozlama saqlash xatosi foydalanuvchiga ko‘rsatiladi');

for (const className of [
  '.saas-command-header',
  '.saas-kpi-grid',
  '.saas-grid-main',
  '.saas-feature-grid',
  '.saas-risk-row',
  '.saas-log-filters'
]) {
  assert.ok(css.includes(className), `${className} uslubi mavjud`);
}

assert.match(bootstrap, /20260614-saas-console1/, 'Bootstrap cache versiyasi yangilangan');
assert.equal(
  (index.match(/20260614-saas-console1/g) || []).length,
  5,
  'Index barcha asosiy assetlarni yangi versiya bilan yuklaydi'
);

console.log(`SaaS console testlari muvaffaqiyatli: ${requiredIds.length} ta UI nuqtasi va boshqaruv oqimlari tekshirildi.`);
