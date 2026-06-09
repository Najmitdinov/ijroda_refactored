import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8');

function extractFunction(name) {
  const asyncMarker = `async function ${name}(`;
  const plainMarker = `function ${name}(`;
  const asyncStart = source.indexOf(asyncMarker);
  const marker = asyncStart >= 0 ? asyncMarker : plainMarker;
  const start = asyncStart >= 0 ? asyncStart : source.indexOf(plainMarker);
  assert.notEqual(start, -1, `${name} topilmadi`);
  const nextFunction = source.indexOf('\nfunction ', start + marker.length);
  const nextAsyncFunction = source.indexOf('\nasync function ', start + marker.length);
  const nextWindowAssignment = source.indexOf('\nwindow.', start + marker.length);
  const candidates = [nextFunction, nextAsyncFunction, nextWindowAssignment].filter(index => index > start);
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
  'responseBodyLooksIncomplete',
  'cleanGeneratedResponseBody',
  'enforceRequiredResponseOpening',
  'validateAiResponseDocument',
  'responseMissesRequiredExtra',
  'responseBodyLooksGeneric',
  'responseBodyFailsLegalQuality'
];

const runtime = new Function(`
  const RESPONSE_STOP_WORDS = new Set("bilan uchun hamda bo'yicha yuzasidan mazkur ushbu sizning tomonidan tashkil qilindi etildi bo'lgan bo'ladi tegishli masala masalasi yuborgan topshiriq topshirigingiz respublikasi viloyati tuman shahri".split(/\\s+/));
  let __mockAiResponses = [];
  let __mockAiCalls = 0;
  async function callTemplateAiDetailed() {
    __mockAiCalls += 1;
    if(!__mockAiResponses.length) throw new Error('Mock AI javobi qolmadi');
    return __mockAiResponses.shift();
  }
  ${functionNames.map(extractFunction).join('\n\n')}
  ${extractFunction('createAiOnlyResponseDocument')}
  return {
    ${functionNames.join(', ')},
    createAiOnlyResponseDocument,
    setMockAiResponses(values) { __mockAiResponses = values.slice(); __mockAiCalls = 0; },
    getMockAiCalls() { return __mockAiCalls; }
  };
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

assert.equal(runtime.responseBodyLooksIncomplete(
  "Mazkur topshiriq yuzasidan obyekt o'rganildi. Aniqlangan kamchiliklarni bartaraf etish choralari belgilandi."
), false);
assert.equal(runtime.responseBodyLooksIncomplete(
  "Mazkur topshiriq yuzasidan obyekt o'rganildi va"
), true);
assert.equal(runtime.responseBodyLooksIncomplete(
  "Mazkur topshiriq yuzasidan obyekt o'rganildi.",
  { truncated:true }
), true);
assert.equal(runtime.responseBodyLooksIncomplete(
  "Mazkur topshiriq yuzasidan (obyekt o'rganildi."
), true);

const truncatedPayload = {
  body:"Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganildi va",
  confidence_score:95,
  _generation:{ truncated:true }
};
assert.equal(
  runtime.validateAiResponseDocument(truncatedPayload, task, '', '', []).ok,
  false,
  'Token limitida uzilgan body rad etilishi kerak'
);

runtime.setMockAiResponses([
  {
    text:JSON.stringify({
      body:"Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganildi va",
      confidence_score:95
    }),
    provider:'Gemini',
    model:'gemini-test',
    finishReason:'MAX_TOKENS',
    truncated:true
  },
  {
    text:JSON.stringify({ body, confidence_score:95 }),
    provider:'Gemini',
    model:'gemini-test',
    finishReason:'STOP',
    truncated:false
  }
]);
const retried = await runtime.createAiOnlyResponseDocument(
  'To‘liq rasmiy javob xati yarat.',
  null,
  task,
  '',
  '',
  [],
  '',
  ''
);
assert.equal(runtime.getMockAiCalls(), 2, 'Uzilgan javobdan keyin AI qayta chaqirilishi kerak');
assert.equal(
  runtime.compactResponseText(retried.body),
  runtime.compactResponseText(body),
  'Qayta urinishda to‘liq body qabul qilinishi kerak'
);

const longBody = Array.from({ length:24 }, (_, index) =>
  `Masala ${index + 1} yuzasidan Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganilib, belgilangan chora-tadbirlar ijrosi nazoratga olindi.`
).join('\n\n') + "\n\nYakuniy natijalar bo'yicha asoslantirilgan ma'lumot belgilangan tartibda taqdim etiladi.";
assert.equal(runtime.responseBodyLooksIncomplete(longBody), false);
const longBodyCheck = runtime.validateAiResponseDocument({ body:longBody, confidence_score:95 }, task, '', '', []);
assert.equal(
  longBodyCheck.ok,
  true,
  `Ko‘p bandli, lekin to‘liq yakunlangan uzun xat qabul qilinishi kerak: ${longBodyCheck.reason}`
);

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

console.log('AI response body parser: all checks passed.');
