import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8');

function extractFunction(name) {
  const marker = `function ${name}(`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `${name} topilmadi`);
  const nextFunction = source.indexOf('\nfunction ', start + marker.length);
  const nextAsyncFunction = source.indexOf('\nasync function ', start + marker.length);
  const candidates = [nextFunction, nextAsyncFunction].filter(index => index > start);
  const end = candidates.length ? Math.min(...candidates) : source.length;
  return source.slice(start, end).trim();
}

const functionNames = [
  'parseAIJson',
  'normalizeText',
  'stripNonWordChars',
  'compactResponseText',
  'taskMeaningfulWords',
  'splitTaskSentences',
  'responseBodySimilarity',
  'responseLooksCopiedFromMemory',
  'responseTooSimilarToPrevious',
  'estimateResponseConfidence',
  'aiResponseTextValue',
  'extractAiResponseBody',
  'stripAiResponseWrapper',
  'decodeAiQuotedValue',
  'extractAiBodyFromLabeledText',
  'isLikelyAiResponseBody',
  'parseAiResponsePayload',
  'normalizeAiConfidence',
  'cleanGeneratedResponseBody',
  'enforceRequiredResponseOpening',
  'validateAiResponseDocument',
  'responseMissesRequiredExtra',
  'responseBodyLooksGeneric',
  'responseBodyFailsLegalQuality'
];

const runtime = new Function(`
  const RESPONSE_STOP_WORDS = new Set("bilan uchun hamda bo'yicha yuzasidan mazkur ushbu sizning tomonidan tashkil qilindi etildi bo'lgan bo'ladi tegishli masala masalasi yuborgan topshiriq topshirigingiz respublikasi viloyati tuman shahri".split(/\\s+/));
  ${functionNames.map(extractFunction).join('\n\n')}
  return { ${functionNames.join(', ')} };
`)();

const task = "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganilib, aniqlangan kamchiliklar bo'yicha ma'lumot berilsin.";
const body = [
  "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganildi.",
  "Kamchiliklarni bartaraf etish choralari belgilandi.",
  "Natija bo'yicha ma'lumot taqdim etiladi."
].join('\n');

const providerFormats = [
  JSON.stringify({ body, confidence_score:91 }),
  JSON.stringify({ result:{ document:{ main_text:body } }, confidence:0.91 }),
  JSON.stringify({ output:{ response_letter:{ paragraphs:body.split('\n') } }, confidence_score:'91' }),
  JSON.stringify({ choices:[{ message:{ content:JSON.stringify({ javob_matni:body, confidence_score:92 }) } }] }),
  JSON.stringify({ payload:{ hujjat_natijasi:{ asosiy_matn:body } }, confidence_score:90 }),
  JSON.stringify({ html:`<p>${body.split('\n').join('</p><p>')}</p>`, confidence_score:90 }),
  `body: "${body.replace(/\n/g, '\\n').replace(/"/g, '\\"')}"\nconfidence_score: 90`,
  `JAVOB_MATNI:\n${body}`,
  body,
  `\`\`\`json\n${JSON.stringify({ response_body:body, confidence_score:90 })}\n\`\`\``
];

for(const [index, raw] of providerFormats.entries()) {
  const payload = runtime.parseAiResponsePayload(raw);
  assert.ok(payload, `AI formati ${index + 1} parse qilinmadi`);
  assert.match(runtime.extractAiResponseBody(payload), /Nurota tumanidagi obyekt/);
  const checked = runtime.validateAiResponseDocument(payload, task, '', '', []);
  assert.equal(checked.ok, true, `AI formati ${index + 1}: ${checked.reason}`);
}

const officialBody = "Navoiy viloyati Qurilish va uy-joy kommunal xo'jaligi bosh boshqarmasi tomonidan Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganib chiqildi.\nAniqlangan kamchiliklar bo'yicha asoslantirilgan ma'lumot taqdim etiladi.";
assert.equal(
  runtime.compactResponseText(runtime.cleanGeneratedResponseBody(officialBody)),
  runtime.compactResponseText(officialBody)
);

const bodyWithHeader = `O'ZBEKISTON RESPUBLIKASI
QURILISH VA UY-JOY KOMMUNAL XO'JALIGI VAZIRLIGI
NAVOIY VILOYATI QURILISH VA UY-JOY KOMMUNAL XO'JALIGI BOSH BOSHQARMASI
210100 Navoiy shahri, Zarapetyan ko'chasi, 10-uy
Tel: (79)220-50-08

Mazkur topshiriqda ko'rsatilgan obyektning loyiha-smeta hujjatlari o'rganib chiqildi.
Aniqlangan holatlar bo'yicha tegishli ma'lumot taqdim etiladi.`;
const cleanedHeaderBody = runtime.cleanGeneratedResponseBody(bodyWithHeader);
assert.doesNotMatch(cleanedHeaderBody, /Zarapetyan|O'ZBEKISTON RESPUBLIKASI/);
assert.match(cleanedHeaderBody, /Mazkur topshiriqda/);

assert.equal(runtime.normalizeAiConfidence(0.91), 91);
assert.equal(runtime.normalizeAiConfidence('0,88'), 88);
assert.ok(body.replace(/\s+/g, ' ').length < 220);
assert.equal(runtime.responseBodyFailsLegalQuality(body, task, ''), false);
assert.equal(runtime.parseAIJson(body), null);

const repeatedNormativeBody = "Nurota tumanidagi obyekt bo'yicha topshiriq ko'rib chiqildi. Shaharsozlik normalari va qoidalari (ShNQ), qurilish me'yorlari va qoidalari (KMK) hamda boshqa normativ-huquqiy hujjatlar talablari asosida tegishli ma'lumotlar to'planmoqda. Natijasi yuzasidan axborot taqdim etiladi.";
assert.equal(
  runtime.responseBodyLooksGeneric(repeatedNormativeBody, task),
  true,
  'takroriy ShNQ/KMK qolipi rad etilishi kerak'
);
assert.equal(
  runtime.responseBodyLooksGeneric(
    "Nurota tumanidagi obyektning loyiha-smeta hujjatlari ShNQ 2.07.01-03 talablariga muvofiqligi yuzasidan o'rganildi. Aniqlangan kamchiliklar bo'yicha buyurtmachiga aniq ko'rsatmalar berildi. Natijasi yuzasidan ma'lumot taqdim etiladi.",
    task
  ),
  false,
  'aniq normativga mazmunli havola saqlanishi kerak'
);

console.log('AI response body parser: all checks passed.');
