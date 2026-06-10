import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  IJRO_SEKTORLAR,
  IJRO_XODIMLAR,
  IJRO_TIZIM_XODIMLAR
} from '../js/data/ijro-default-data.js';

const source = fs.readFileSync(new URL('../js/app.js', import.meta.url), 'utf8');

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
  'employeeIdentityText',
  'employeeInitials',
  'sameEmployeeProfile',
  'mergeUniqueProfileValues',
  'mergeEmployeeProfile',
  'mergeEmployeeProfiles',
  'allIjroEmployeeProfiles',
  'fishkaEmployeeCandidates',
  'fishkaEmployeeFullName',
  'findFishkaEmployeeCandidate',
  'fishkaMatchTokens',
  'fishkaTokenOverlap',
  'bestFishkaResponsibility',
  'normalizeFishkaMatchBands',
  'calculateFishkaEvidenceConfidence',
  'enrichFishkaMatchResult'
];

const runtime = new Function(
  'IJRO_SEKTORLAR',
  'IJRO_XODIMLAR',
  'IJRO_TIZIM_XODIMLAR',
  `
    let xodimlarCache = [];
    ${functionNames.map(extractFunction).join('\n\n')}
    return {
      allIjroEmployeeProfiles,
      fishkaEmployeeCandidates,
      findFishkaEmployeeCandidate,
      enrichFishkaMatchResult
    };
  `
)(IJRO_SEKTORLAR, IJRO_XODIMLAR, IJRO_TIZIM_XODIMLAR);

const profiles = runtime.allIjroEmployeeProfiles();
assert.ok(profiles.length >= 65, `Birlashtirilgan profil soni kutilganidan kam: ${profiles.length}`);
assert.ok(profiles.length < IJRO_XODIMLAR.length + IJRO_TIZIM_XODIMLAR.length, 'Dublikat profillar birlashtirilmadi');

const oydinov = runtime.findFishkaEmployeeCandidate("Oydinov Shoxruz Ilhomiddin o'g'li", profiles);
assert.ok(oydinov, 'Oydinov Shoxruz profili topilmadi');
assert.ok(oydinov.tizimlar.includes('moderator.ttreklama.uz'));
assert.ok(oydinov.vakolatlar.some(value => /tashqi reklama/i.test(value)));

const scenarios = [
  {
    text: "104-son qaror ijrosi doirasida Navoiy viloyatidagi tashqi reklama obyektlarini moderator.ttreklama.uz tizimida ko'rib chiqish va xulosa kiritish topshirilsin.",
    result: {
      sektor: 'Transport va jamoat infratuzilmasi',
      xodim: "Oydinov Shoxruz Ilhomiddin o'g'li",
      hujjat_dalili: "tashqi reklama obyektlarini moderator.ttreklama.uz tizimida ko'rib chiqish va xulosa kiritish",
      xodim_vakolati: 'Tashqi reklama obyektlari, 104-son qaror',
      moslik_asosi: "Topshiriq tashqi reklama moderator tizimida xulosa kiritishga oid bo'lib, ushbu tizim Oydinov Shoxruzga biriktirilgan.",
      moslik_bandlari: [],
      ishonch: 92
    },
    expected: /Oydinov Shoxruz/
  },
  {
    text: "dx.mc.uz tizimi orqali obyekt uchun arxitektura-rejalashtirish topshirig'ini ishlab chiqish va belgilangan tartibda rasmiylashtirish so'ralsin.",
    result: {
      sektor: 'Arxitektura va hududlarni rejalashtirish',
      xodim: 'Quvondiqov Asilbek',
      hujjat_dalili: "obyekt uchun arxitektura-rejalashtirish topshirig'ini ishlab chiqish",
      xodim_vakolati: "Arxitektura-rejalashtirish topshirig'ini ishlab chiqish",
      moslik_asosi: "Hujjatdagi ART ishlab chiqish vazifasi Quvondiqov Asilbekning dx.mc.uz tizimidagi bevosita vakolatiga mos.",
      moslik_bandlari: [],
      ishonch: 91
    },
    expected: /Quvondiqov Asilbek/
  },
  {
    text: "cabinetpm2.gov.uz Virtual qabulxonasiga kelib tushgan murojaatni o'rganib, murojaatchiga asoslantirilgan javob yuborish ta'minlansin.",
    result: {
      sektor: 'Murojaatlar va dispetcherlik',
      xodim: 'Sobirov Oybek Boboqulovich',
      hujjat_dalili: "Virtual qabulxonasiga kelib tushgan murojaatni o'rganib, murojaatchiga asoslantirilgan javob yuborish",
      xodim_vakolati: 'Virtual qabulxona va fuqarolar murojaatlari',
      moslik_asosi: "Topshiriq cabinetpm2.gov.uz orqali kelgan murojaatga oid va ushbu portal moderatori sifatida Sobirov Oybekka biriktirilgan.",
      moslik_bandlari: [],
      ishonch: 90
    },
    expected: /Sobirov Oybek/
  }
];

for(const scenario of scenarios) {
  const enriched = runtime.enrichFishkaMatchResult(scenario.result, scenario.text);
  assert.equal(enriched._matchError, undefined, enriched._matchError);
  assert.match(enriched.xodim, scenario.expected);
  assert.equal(enriched.dalil_tasdiqlangan, true);
  assert.ok(enriched.ishonch >= 80, `${enriched.xodim}: ishonch ${enriched.ishonch}%`);
  assert.ok(enriched.xodim_vakolati.length >= 15);
  assert.ok(enriched.moslik_asosi.length >= 35);
}

const unknown = runtime.enrichFishkaMatchResult({
  xodim:'Bazaga Kiritilmagan Xodim',
  hujjat_dalili:'Hujjatdagi aniq topshiriq bandi',
  xodim_vakolati:'Noma’lum vakolat',
  moslik_asosi:'Moslik asosi mavjud emas.',
  ishonch:95
}, 'Hujjatdagi aniq topshiriq bandi');
assert.match(unknown._matchError, /bazasida topilmadi/i);

const missingEvidence = runtime.enrichFishkaMatchResult({
  xodim:'Quvondiqov Asilbek',
  hujjat_dalili:'',
  xodim_vakolati:'',
  moslik_asosi:'',
  ishonch:95
}, "Arxitektura-rejalashtirish topshirig'i ishlab chiqilsin.");
assert.match(missingEvidence._matchError, /aniq band/i);

console.log(`Fishka xodim mosligi: ${profiles.length} profil va ${scenarios.length} dalilli ssenariy muvaffaqiyatli tekshirildi.`);
