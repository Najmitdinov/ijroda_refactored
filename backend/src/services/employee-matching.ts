import type { EmployeeProfile } from '../types/shared.js';

interface EmployeeMatchResult {
  status: 'MATCHED' | 'NEEDS_REVIEW' | 'NOT_FOUND';
  employee_id?: string;
  display_name?: string;
  confidence_score: number;
  reasons: string[];
}

const cyrToLat: Record<string, string> = {
  а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'yo', ж: 'j', з: 'z', и: 'i', й: 'y',
  к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u',
  ф: 'f', х: 'x', ц: 's', ч: 'ch', ш: 'sh', щ: 'sh', ъ: '', ы: 'i', ь: '', э: 'e', ю: 'yu', я: 'ya',
  қ: 'q', ғ: 'g', ҳ: 'h', ў: 'o'
};

export function matchEmployee(rawName: string, employees: EmployeeProfile[]): EmployeeMatchResult {
  const query = normalizeName(rawName);
  const scored = employees.map((employee) => {
    const names = [
      `${employee.ism} ${employee.familiya}`,
      `${employee.familiya} ${employee.ism}`,
      `${employee.ism[0] ?? ''}. ${employee.familiya}`,
      `${employee.familiya} ${employee.ism[0] ?? ''}.`,
      employee.username ?? '',
      ...employee.aliases
    ].map(normalizeName);

    const score = Math.max(...names.map((candidate) => similarity(query, candidate)));
    return { employee, score };
  }).sort((a, b) => b.score - a.score)[0];

  if (!scored) return { status: 'NOT_FOUND', confidence_score: 0, reasons: ['employee list empty'] };

  const confidence = Math.round(scored.score * 100);
  return {
    status: confidence > 85 ? 'MATCHED' : confidence >= 60 ? 'NEEDS_REVIEW' : 'NOT_FOUND',
    employee_id: scored.employee.employee_id,
    display_name: `${scored.employee.ism} ${scored.employee.familiya}`,
    confidence_score: confidence,
    reasons: ['fuzzy matching', 'abbreviation analysis', 'transliteration normalization']
  };
}

function normalizeName(value: string) {
  return value
    .toLowerCase()
    .replace(/[а-яёқғҳў]/g, (char) => cyrToLat[char] ?? char)
    .replace(/[^a-z0-9\s.]/g, ' ')
    .replace(/\b([a-z])\./g, '$1 ')
    .replace(/\s+/g, ' ')
    .trim();
}

function similarity(a: string, b: string) {
  if (!a || !b) return 0;
  if (a === b) return 1;
  if (a.includes(b) || b.includes(a)) return 0.92;
  const distance = levenshtein(a, b);
  return 1 - distance / Math.max(a.length, b.length);
}

function levenshtein(a: string, b: string) {
  const dp = Array.from({ length: a.length + 1 }, () => Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length][b.length];
}
