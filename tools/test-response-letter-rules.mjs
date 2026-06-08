import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const source = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8');

function extractFunction(name) {
  const marker = `function ${name}(`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `${name} topilmadi`);
  const nextFunction = source.indexOf('\nfunction ', start + marker.length);
  const nextAsyncFunction = source.indexOf('\nasync function ', start + marker.length);
  const candidates = [nextFunction, nextAsyncFunction].filter(x => x > start);
  const end = candidates.length ? Math.min(...candidates) : source.length;
  return source.slice(start, end).trim();
}

const names = [
  'parseAIJson',
  'normalizeText',
  'simpleHash',
  'stripNonWordChars',
  'compactResponseText',
  'aiProviderErrorMessage',
  'groqModelCandidates',
  'openRouterModelCandidates',
  'taskMeaningfulWords',
  'splitTaskSentences',
  'responseTaskProfile',
  'responseTaskProfileText',
  'normalizeResponseRecipientName',
  'responseOpeningFormula',
  'responseOpeningPlan',
  'aiResponseTextValue',
  'extractAiResponseBody',
  'stripAiResponseWrapper',
  'decodeAiQuotedValue',
  'extractAiBodyFromLabeledText',
  'isLikelyAiResponseBody',
  'parseAiResponsePayload',
  'normalizeAiConfidence',
  'cleanGeneratedResponseBody',
  'responseBodySimilarity',
  'responseLooksCopiedFromMemory',
  'responseTooSimilarToPrevious',
  'estimateResponseConfidence',
  'enforceRequiredResponseOpening',
  'validateAiResponseDocument',
  'responseMissesRequiredExtra',
  'responseBodyLooksGeneric',
  'responseUsesUnsupportedSpecialist',
  'responseBodyFailsLegalQuality'
];

const runtime = new Function(`
  const RESPONSE_STOP_WORDS = new Set("bilan uchun hamda bo'yicha yuzasidan mazkur ushbu sizning tomonidan tashkil qilindi etildi bo'lgan bo'ladi tegishli masala masalasi yuborgan topshiriq topshirigingiz respublikasi viloyati tuman shahri".split(/\\s+/));
  ${names.map(extractFunction).join('\n\n')}
  return { ${names.join(', ')} };
`)();

const officialBodyStartingWithOrg = "Navoiy viloyati Qurilish va uy-joy kommunal xo'jaligi bosh boshqarmasi Sizning 2026-yil 5-iyundagi 04-13/492-sonli xatingiz yuzasidan quyidagilarni ma'lum qiladi. Topshiriqda ko'rsatilgan obyektning loyiha-smeta hujjatlari o'rganib chiqildi. Aniqlangan holatlar bo'yicha asoslantirilgan ma'lumot taqdim etiladi.";
assert.equal(
  runtime.cleanGeneratedResponseBody(officialBodyStartingWithOrg),
  officialBodyStartingWithOrg,
  'tashkilot nomi qatnashgan mazmunli javob header deb o‘chirilmasligi kerak'
);

const bodyWithHeader = `O'ZBEKISTON RESPUBLIKASI
QURILISH VA UY-JOY KOMMUNAL XO'JALIGI VAZIRLIGI
NAVOIY VILOYATI QURILISH VA UY-JOY KOMMUNAL XO'JALIGI BOSH BOSHQARMASI
210100 Navoiy shahri, Zarapetyan ko'chasi, 10-uy
Tel: (79)220-50-08

Mazkur topshiriqda ko'rsatilgan obyektning loyiha-smeta hujjatlari o'rganib chiqildi.
Aniqlangan holatlar bo'yicha tegishli ma'lumot taqdim etiladi.`;
const cleanedBodyWithHeader = runtime.cleanGeneratedResponseBody(bodyWithHeader);
assert.doesNotMatch(cleanedBodyWithHeader, /Zarapetyan|O'ZBEKISTON RESPUBLIKASI/);
assert.match(cleanedBodyWithHeader, /Mazkur topshiriqda ko'rsatilgan obyekt/);

assert.equal(
  runtime.extractAiResponseBody({
    body: {
      paragraphs: [
        "Mazkur topshiriq bo'yicha loyiha hujjatlari o'rganib chiqildi.",
        "Natijasi yuzasidan asoslantirilgan axborot taqdim etiladi."
      ]
    }
  }),
  "Mazkur topshiriq bo'yicha loyiha hujjatlari o'rganib chiqildi.\n\nNatijasi yuzasidan asoslantirilgan axborot taqdim etiladi."
);
assert.equal(runtime.normalizeAiConfidence(0.91), 91);
assert.equal(runtime.normalizeAiConfidence('0,88'), 88);
assert.equal(runtime.parseAIJson("Mazkur topshiriq bo'yicha rasmiy javob matni."), null);

const parserTask = "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganilib, aniqlangan kamchiliklar bo'yicha ma'lumot berilsin.";
const parserBody = "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganib chiqildi. Aniqlangan kamchiliklar bo'yicha asoslantirilgan ma'lumot belgilangan tartibda taqdim etiladi.";
const providerFormats = [
  JSON.stringify({ body:parserBody, confidence_score:91 }),
  JSON.stringify({ result:{ document:{ main_text:parserBody } }, confidence:0.91 }),
  JSON.stringify({ output:{ response_letter:{ paragraphs:[
    "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganib chiqildi.",
    "Aniqlangan kamchiliklar bo'yicha asoslantirilgan ma'lumot belgilangan tartibda taqdim etiladi."
  ] } }, confidence_score:'91' }),
  JSON.stringify({ choices:[{ message:{ content:JSON.stringify({ javob_matni:parserBody, confidence_score:92 }) } }] }),
  JSON.stringify({ payload:{ hujjat_natijasi:{ asosiy_matn:parserBody } }, confidence_score:90 }),
  JSON.stringify({ html:`<p>${parserBody}</p>`, confidence_score:90 }),
  JSON.stringify({ body:{ opening:"Nurota tumanidagi obyekt bo'yicha topshiriq ko'rib chiqildi.", main:"Loyiha-smeta hujjatlari o'rganib chiqildi.", closing:"Aniqlangan kamchiliklar yuzasidan asoslantirilgan ma'lumot taqdim etiladi." }, confidence_score:90 }),
  `body: "${parserBody.replace(/"/g, '\\"')}"\nconfidence_score: 90`,
  `JAVOB_MATNI:\n${parserBody}`,
  parserBody,
  `\`\`\`json\n${JSON.stringify({ response_body:parserBody, confidence_score:90 })}\n\`\`\``
];
for(const [index, raw] of providerFormats.entries()) {
  const payload = runtime.parseAiResponsePayload(raw);
  assert.ok(payload, `provider formati ${index + 1} parse qilinmadi`);
  assert.match(runtime.extractAiResponseBody(payload), /Nurota tumanidagi obyekt/);
  const checked = runtime.validateAiResponseDocument(payload, parserTask, '', '', []);
  assert.equal(checked.ok, true, `provider formati ${index + 1}: ${checked.reason}`);
}
assert.equal(
  runtime.extractAiResponseBody(runtime.parseAiResponsePayload('{"title":"Javob xati","confidence_score":90}')),
  ''
);

const validatedStructuredResponse = runtime.validateAiResponseDocument(
  {
    body: {
      paragraphs: [
        "Navoiy viloyati Qurilish va uy-joy kommunal xo'jaligi bosh boshqarmasi tomonidan Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganib chiqildi.",
        "Aniqlangan holatlar va kamchiliklar bo'yicha asoslantirilgan ma'lumot belgilangan tartibda taqdim etiladi."
      ]
    },
    confidence_score: 0.91
  },
  "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganilib, aniqlangan kamchiliklar bo'yicha ma'lumot berilsin.",
  '',
  '',
  []
);
assert.equal(validatedStructuredResponse.ok, true, validatedStructuredResponse.reason);
assert.match(validatedStructuredResponse.body, /Qurilish va uy-joy kommunal xo'jaligi/);
assert.equal(validatedStructuredResponse.confidence, 91);

const infoProfile = runtime.responseTaskProfile(
  "Mazkur uslubiy qo'llanma ma'lumot va ijroda foydalanish uchun yuborilmoqda.",
  {}
);
assert.equal(infoProfile.primaryType, 'malumot_uchun');
assert.equal(infoProfile.informationOnly, true);
assert.equal(infoProfile.requiresPerson, false);

const seriousProfile = runtime.responseTaskProfile(
  "Prokuratura talabnomasi asosida obyektdagi noqonuniy qurilish va texnik nazorat kamchiliklarini 10 iyunga qadar bartaraf etish, ijrosini qat'iy nazoratga olish topshirildi.",
  {}
);
assert.equal(seriousProfile.primaryType, 'talabnoma_javobi');
assert.equal(seriousProfile.seriousness, 'yuqori');
assert.equal(seriousProfile.requiresPerson, false);

const dataProfile = runtime.responseTaskProfile(
  "Karmana tumanidagi 3 ta obyektning loyiha-smeta hujjatlari va ekspertiza xulosasi bo'yicha ma'lumot taqdim etilsin.",
  {}
);
assert.equal(dataProfile.primaryType, 'malumot_taqdim');

const personProfile = runtime.responseTaskProfile(
  "Qiziltepa tumaniga amaliy yordam ko'rsatish uchun mas'ul xodim biriktirilsin.",
  {}
);
assert.equal(personProfile.requiresPerson, true);

const infoOpening = runtime.responseOpeningPlan(
  infoProfile,
  "Navoiy viloyati hokimligiga",
  { date:"2026-yil 3-iyun", number:'02-14/586', kind:'xat' }
);
assert.match(infoOpening.requiredOpening, /^Sizning 2026-yil 3-iyundagi 02-14\/586-sonli xatingiz$/);

const seriousOpening = runtime.responseOpeningPlan(
  seriousProfile,
  "Navoiy viloyati prokuraturasiga",
  { date:"2026-yil 4-iyun", number:'10.2/4-8888', kind:'talabnoma' }
);
assert.match(seriousOpening.requiredOpening, /10\.2\/4-8888-sonli talabnomangiz$/);

const decisionOpening = runtime.responseOpeningPlan(
  runtime.responseTaskProfile(
    "Prezident qarori ijrosini ta'minlash, qurilish obyektlaridagi kamchiliklarni bartaraf etish va ijroni nazoratga olish topshirildi.",
    {}
  ),
  "Qurilish vazirligiga",
  { date:"2026-yil 4-iyun", number:'13-11/9516', kind:'topshiriq' }
);
assert.equal(decisionOpening.requiredOpening, '');
assert.ok(decisionOpening.alternatives.some(x => /Mazkur topshiriq|Topshiriqda belgilangan/.test(x)));

const shortTask = "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganilib, aniqlangan kamchiliklar bo'yicha ma'lumot berilsin.";
const shortBody = [
  "Nurota tumanidagi obyektning loyiha-smeta hujjatlari o'rganib chiqildi.",
  "Aniqlangan kamchiliklarni bartaraf etish bo'yicha tegishli choralar belgilandi.",
  "Natijasi yuzasidan asoslantirilgan ma'lumot taqdim etiladi."
].join('\n');
assert.ok(shortBody.replace(/\s+/g, ' ').length < 220, 'sinov xati 220 belgidan qisqa bo‘lishi kerak');
assert.equal(runtime.responseBodyFailsLegalQuality(shortBody, shortTask, ''), false);

const unsupportedBody = "Mazkur obyekt bo'yicha mas'ul xodim biriktirildi va nazorat ishlari tashkil etildi. Natijasi ma'lum qilinadi.";
assert.equal(runtime.responseUsesUnsupportedSpecialist(unsupportedBody, shortTask), true);
assert.equal(
  runtime.responseUsesUnsupportedSpecialist(
    unsupportedBody,
    "Mazkur obyekt bo'yicha nazorat olib borish uchun mas'ul xodim biriktirilsin."
  ),
  false
);

const extraWithPhone = "Ijrochi telefoni 79-220-50-11. Nurota obyektidagi kamchiliklarni bartaraf etish ishlari boshlandi.";
assert.equal(
  runtime.responseMissesRequiredExtra(
    "Nurota obyektidagi aniqlangan kamchiliklarni bartaraf etish ishlari boshlandi va ijro holati nazorat qilinmoqda.",
    extraWithPhone
  ),
  false
);

assert.match(source, /Faqat ma'lumot uchun kelgan hujjatga javobda/);
assert.match(source, /Mutaxassis.*faqat topshiriq yoki qo'shimcha ma'lumotda/i);
assert.match(source, /Oddiy yoki qisqa topshiriqda 3 ta aniq gap yetarli/);
assert.doesNotMatch(source, /if\(clean\.length < 220\) return true/);

const quotaMessage = runtime.aiProviderErrorMessage(
  'Gemini',
  429,
  'You exceeded your current quota. Quota exceeded for metric generate_content_free_tier_requests, limit: 0'
);
assert.match(quotaMessage, /Gemini kvotasi tugagan/);
assert.doesNotMatch(quotaMessage, /https?:\/\//);

assert.deepEqual(runtime.groqModelCandidates('llama-3.1-70b-versatile'), [
  'llama-3.3-70b-versatile',
  'openai/gpt-oss-120b',
  'qwen/qwen3-32b'
]);

const modelCandidates = runtime.openRouterModelCandidates([
  {
    id:'deepseek/deepseek-r1:free',
    architecture:{ output_modalities:['text'] },
    pricing:{ prompt:'0', completion:'0' },
    context_length:200000,
    expiration_date:null
  },
  {
    id:'qwen/qwen3-coder:free',
    architecture:{ output_modalities:['text'] },
    pricing:{ prompt:'0', completion:'0' },
    context_length:1000000,
    expiration_date:null
  },
  {
    id:'google/gemma-instruct:free',
    architecture:{ output_modalities:['text'] },
    pricing:{ prompt:'0', completion:'0' },
    context_length:260000,
    expiration_date:null
  }
], 'mistralai/mistral-7b-instruct');
assert.deepEqual(modelCandidates, ['google/gemma-instruct:free', 'qwen/qwen3-coder:free']);
assert.equal(modelCandidates.some(x => /deepseek/i.test(x)), false);

assert.match(source, /resolveOpenRouterModels/);
assert.doesNotMatch(
  source.slice(source.indexOf('async function callTemplateAi'), source.indexOf('function localTemplateAnalysis')),
  /mistralai\/mistral-7b-instruct/
);
assert.match(source, /let templateAiLastProof = null/);
assert.match(source, /AI provayder tasdig‘i olinmadi\. Sun’iy yoki lokal javob ishlatilmaydi/);
assert.match(source, /parsed\.ai_provider = aiProof\.provider/);
assert.match(source, /if\(!parsed\.ai_provider \|\| !parsed\.ai_model\)/);
assert.match(source, /aiOnly:true,\s*provider:parsed\.ai_provider,\s*model:parsed\.ai_model/s);
assert.match(source, /Javob xati faqat AI orqali yaratildi/);
assert.match(source, /name: 'Groq'.*model: 'llama-3\.3-70b-versatile'/s);
assert.match(source, /AI javobida asosiy body matni topilmadi/);
assert.doesNotMatch(source, /const noiseLine = .*QURILISH\\s\+VA\\s\+UY-JOY/);
assert.match(source, /parsed = parseAiResponsePayload\(rawAiResponse\)/);
assert.doesNotMatch(source, /parsed = parseAIJson\(await callTemplateAi\(strictPrompt/);

const realProviderResponseFile = process.env.IJRODA_REAL_AI_RESPONSE_FILE || '';
if(realProviderResponseFile) {
  assert.equal(existsSync(realProviderResponseFile), true, 'Real AI javob fayli topilmadi');
  const realRaw = readFileSync(realProviderResponseFile, 'utf8');
  const realPayload = runtime.parseAiResponsePayload(realRaw);
  assert.ok(realPayload, 'Real AI javobi parse qilinmadi');
  const realCheck = runtime.validateAiResponseDocument(
    realPayload,
    "Nurota tumanidagi qurilish obyektining loyiha-smeta hujjatlarini o'rganish va kamchiliklar bo'yicha ma'lumot berish topshirildi.",
    '',
    '',
    []
  );
  assert.equal(realCheck.ok, true, `Real AI javobi validatsiyadan o'tmadi: ${realCheck.reason}`);
  assert.ok(realCheck.body.length >= 80, 'Real AI body yetarli matn bermadi');
  console.log(`Real AI response pipeline passed: ${realCheck.body.length} body chars.`);
}

console.log('Response letter and AI provider rules: all checks passed.');
