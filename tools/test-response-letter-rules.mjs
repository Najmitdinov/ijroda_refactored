import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';

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
  'normalizeText',
  'normalizeOcrText',
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
  'cleanGeneratedResponseBody',
  'responseMissesRequiredExtra',
  'responseBodyLooksGeneric',
  'responseUsesUnsupportedSpecialist',
  'responseClaimsUnsupportedAction',
  'normalizeAiConfidence',
  'responseBodyFailsLegalQuality'
];

const runtime = new Function(`
  const RESPONSE_STOP_WORDS = new Set("bilan uchun hamda bo'yicha yuzasidan mazkur ushbu sizning tomonidan tashkil qilindi etildi bo'lgan bo'ladi tegishli masala masalasi yuborgan topshiriq topshirigingiz respublikasi viloyati tuman shahri".split(/\\s+/));
  ${names.map(extractFunction).join('\n\n')}
  return { ${names.join(', ')} };
`)();

assert.equal(runtime.normalizeOcrText("0'RQ-937-sonli qonun"), "O'RQ-937-sonli qonun");
assert.equal(runtime.normalizeOcrText('0.Shukurov'), 'O.Shukurov');

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

assert.equal(runtime.normalizeAiConfidence(0.8), 80);
assert.equal(runtime.normalizeAiConfidence('0,92'), 92);
assert.equal(runtime.normalizeAiConfidence(87), 87);
assert.equal(
  runtime.responseClaimsUnsupportedAction(
    "Mazkur xat ma'lumot uchun qabul qilindi. Topshiriq ijrosi yuzasidan zarur choralar ko'rilmoqda.",
    "Mazkur hujjat ma'lumot uchun yuborildi."
  ),
  true
);
assert.equal(
  runtime.responseClaimsUnsupportedAction(
    "Obyektda texnik ko'rik o'tkazildi va dalolatnoma tuzildi.",
    "Obyektda texnik ko'rik o'tkazilgani hamda dalolatnoma tuzilgani ma'lum qilindi."
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

const groqLimitMessage = runtime.aiProviderErrorMessage(
  'Groq',
  429,
  'Rate limit reached for model on tokens per minute (TPM)'
);
assert.match(groqLimitMessage, /boshqa Groq modeli yoki Gemini/);
assert.doesNotMatch(groqLimitMessage, /https?:\/\//);

const groqModels = runtime.groqModelCandidates('llama-3.1-70b-versatile');
assert.deepEqual(groqModels, [
  'llama-3.3-70b-versatile',
  'openai/gpt-oss-120b',
  'qwen/qwen3-32b'
]);
assert.equal(groqModels.some(x => /llama-3\.1-70b-versatile/i.test(x)), false);

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
assert.match(source, /async function readPdfAsText/);
assert.match(source, /async function readPdfOcrText/);
assert.match(source, /async function readImageOcrText/);
assert.match(source, /TesseractApi\.createWorker/);
assert.match(source, /LOCAL_OCR_LANGUAGES = \['uzb', 'rus', 'eng'\]/);
assert.match(source, /workerPath:`\$\{ocrAssetBase\}worker\.min\.js/);
assert.match(source, /corePath:`\$\{ocrAssetBase\}core`/);
assert.match(source, /langPath:`\$\{ocrAssetBase\}lang`/);
assert.match(source, /window\.pdfjsLib/);
assert.match(source, /pdfLib\.getDocument/);
assert.match(source, /if\(\/\\\.pdf\$\/i\.test\(file\.name\)\) return \(await readPdfAsText\(file, options\)\)/);
assert.match(source, /if\(text\.length >= 80\) return text;\s*return readPdfOcrText\(file, options\)/);
assert.match(source, /Skaner hujjat OCR qilinmoqda/);
assert.match(source, /AI javobida asosiy body matni topilmadi/);
assert.doesNotMatch(source, /const noiseLine = .*QURILISH\\s\+VA\\s\+UY-JOY/);
assert.match(source, /PDF yoki rasmda matn qatlami topilmadi/);

const vendorRoot = new URL('../assets/vendor/tesseract/', import.meta.url);
for(const relative of [
  'tesseract.min.js',
  'worker.min.js',
  'core/tesseract-core-lstm.wasm.js',
  'core/tesseract-core-simd-lstm.wasm.js',
  'core/tesseract-core-relaxedsimd-lstm.wasm.js'
]) {
  const file = new URL(relative, vendorRoot);
  assert.equal(existsSync(file), true, `${relative} topilmadi`);
  assert.ok(statSync(file).size > 50000, `${relative} bo'sh yoki noto'g'ri`);
}
for(const language of ['uzb', 'rus', 'eng']) {
  const file = new URL(`lang/${language}.traineddata.gz`, vendorRoot);
  assert.equal(existsSync(file), true, `${language} OCR modeli topilmadi`);
  assert.ok(gunzipSync(readFileSync(file)).length > 1000000, `${language} OCR modeli buzilgan`);
}
const templateProviderSource = source.slice(
  source.indexOf('async function callTemplateAi'),
  source.indexOf('function localTemplateAnalysis')
);
assert.ok(
  templateProviderSource.indexOf("localStorage.getItem('GROQ_API_KEY')") <
  templateProviderSource.indexOf("localStorage.getItem('GEMINI_API_KEY')"),
  'Groq javob xati uchun Gemini oldidan ishlashi kerak'
);
assert.doesNotMatch(
  templateProviderSource,
  /mistralai\/mistral-7b-instruct/
);
assert.match(templateProviderSource, /requestGroqText/);
assert.match(source, /providerPriority:\['Groq','Gemini','OpenRouter'\]/);
assert.match(source, /name: 'Groq'.*model: 'llama-3\.3-70b-versatile'/s);
assert.match(source, /Groq → Gemini → OpenRouter/);
assert.match(source, /let templateAiLastProof = null/);
assert.match(source, /AI provayder tasdig‘i olinmadi\. Sun’iy yoki lokal javob ishlatilmaydi/);
assert.match(source, /parsed\.ai_provider = aiProof\.provider/);
assert.match(source, /if\(!parsed\.ai_provider \|\| !parsed\.ai_model\)/);
assert.match(source, /aiOnly:true,\s*provider:parsed\.ai_provider,\s*model:parsed\.ai_model/s);
assert.match(source, /Javob xati faqat AI orqali yaratildi/);

console.log('Response letter, OCR and AI provider rules: 64 checks passed.');
