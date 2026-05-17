import type { EduIjroParsedDocument, TaskPriority } from '../types/shared.js';

export async function parseEduIjroDocument(input: {
  fileName: string;
  mimeType: string;
  text: string;
}): Promise<EduIjroParsedDocument> {
  const text = input.text.replace(/\s+/g, ' ').trim();
  const deadline = text.match(/\b\d{1,2}[.\-/]\d{1,2}[.\-/]20\d{2}\b/)?.[0] ?? null;
  const executor = text.match(/(?:ijrochi|mas'?ul)\s*[:\-]\s*([A-ZА-ЯЎҚҒҲ][^.;,\n]{3,80})/i)?.[1]?.trim() ?? '';
  const department = text.match(/(?:bo['‘`ʻ]?lim|sektor|boshqarma)\s*[:\-]\s*([^.;,\n]{3,80})/i)?.[1]?.trim() ?? '';

  return {
    document_title: inferTitle(input.fileName, text),
    executor,
    deadline,
    department,
    status: 'NEW',
    priority: inferPriority(text),
    summary: text.slice(0, 600),
    source_text: text
  };
}

function inferTitle(fileName: string, text: string) {
  return text.split(/[.!?]\s/)[0]?.slice(0, 140) || fileName;
}

function inferPriority(text: string): TaskPriority {
  if (/zudlik|shoshilinch|bugun|darhol|tanqidiy/i.test(text)) return 'URGENT';
  if (/prezident|vazirlar mahkamasi|vazirlik|nazorat/i.test(text)) return 'IMPORTANT';
  return 'NORMAL';
}
