import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../js/app.js', import.meta.url), 'utf8');

function extractConst(name, nextName) {
  const start = source.indexOf(`const ${name} =`);
  const end = source.indexOf(`const ${nextName} =`, start);
  assert.ok(start >= 0 && end > start, `${name} topilmadi`);
  return source.slice(start, end);
}

function extractFunction(name) {
  const marker = `function ${name}(`;
  const start = source.indexOf(marker);
  assert.ok(start >= 0, `${name} topilmadi`);
  const nextFunction = source.indexOf('\nfunction ', start + marker.length);
  const nextAsyncFunction = source.indexOf('\nasync function ', start + marker.length);
  const candidates = [nextFunction, nextAsyncFunction].filter(index => index > start);
  const end = candidates.length ? Math.min(...candidates) : source.length;
  return source.slice(start, end).trim();
}

const functionNames = [
  'normalizeText',
  'getOrgText',
  'getRawField',
  'normalizeOrgName',
  'parseDate',
  'ahbDocumentSearchText',
  'getAhbCategoryByKey',
  'ahbCategoryCanon',
  'getAhbCategoryByLabel',
  'classifyAhbOfficialDocument',
  'normalizeAhbOfficialGroupName',
  'ahbGroupTitle',
  'findAhbRequestedMatch',
  'ahbDocSortValue',
  'groupAhbOfficialDocuments'
];

const runtime = new Function([
  extractConst('AHB_OFFICIAL_CATEGORIES', 'AHB_OFFICIAL_GROUPS'),
  'const AHB_OFFICIAL_GROUPS = AHB_OFFICIAL_CATEGORIES.map(category => category.label);',
  ...functionNames.map(extractFunction),
  'return { AHB_OFFICIAL_CATEGORIES, classifyAhbOfficialDocument, groupAhbOfficialDocuments };'
].join('\n\n'))();
const { AHB_OFFICIAL_CATEGORIES, classifyAhbOfficialDocument, groupAhbOfficialDocuments } = runtime;

const cases = [
  [{ docName:"O'zbekiston Respublikasi Prezidentining PF-12-son Farmoni" }, 'president_decree'],
  [{ docName:"O'zbekiston Respublikasi Prezidentining PQ-44-son Qarori" }, 'president_decision'],
  [{ fromOrg:"O'zbekiston Respublikasi Prezidenti", docType:'Farmoyish', docNum:'F-7' }, 'president_order'],
  [{ fromOrg:"O'zbekiston Respublikasi Prezidenti", docType:'Qonun', docNum:"O'RQ-100" }, 'president_law'],
  [{ fromOrg:'Vazirlar Mahkamasi', docType:'Farmon', docNum:'18' }, 'cabinet_decree'],
  [{ source:'VM', docName:'VMQ-192-son qarori' }, 'cabinet_decision'],
  [{ fromOrg:"O'zbekiston Respublikasi Vazirlar Mahkamasi", docType:'Qonun' }, 'cabinet_law'],
  [{ _raw:{ Yuboruvchi:'Vazirlar Mahkamasi', 'Hujjat turi':'Farmoyish', Raqam:'VMF-9' } }, 'cabinet_order'],
  [{ fromOrg:'Navoiy viloyati hokimligi', docName:'Nazorat xati' }, 'navoiy_governor_letter'],
  [{ docName:'Tashkilot nomi ko‘rsatilmagan xizmat xati' }, 'unclassified']
];

for(const [doc, expected] of cases) {
  assert.equal(classifyAhbOfficialDocument(doc).key, expected, JSON.stringify(doc));
}

const docs = cases.map(([doc], index) => ({ ...doc, docNum:doc.docNum || String(index + 1) }));
const requested = AHB_OFFICIAL_CATEGORIES
  .filter(category => !category.audit)
  .map(category => category.label);
const grouped = groupAhbOfficialDocuments(docs, requested);

assert.equal(grouped.totalInput, docs.length);
assert.equal(grouped.totalGrouped, docs.length);
assert.equal(grouped.unclassifiedCount, 1);
assert.equal(grouped.groups.size, AHB_OFFICIAL_CATEGORIES.length);

for(const category of AHB_OFFICIAL_CATEGORIES) {
  const rows = grouped.groups.get(category.label) || [];
  assert.equal(rows.length, 1, `${category.key} guruhida bitta hujjat bo‘lishi kerak`);
}

console.log(`OK: ${docs.length} ta hujjatning barchasi ${AHB_OFFICIAL_CATEGORIES.length} guruhga yo'qotishsiz saralandi.`);
