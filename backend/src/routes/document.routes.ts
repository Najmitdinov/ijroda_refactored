import { Router } from 'express';
import multer from 'multer';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { audit } from '../middleware/audit.js';
import { parseEduIjroDocument } from '../services/edu-parser.js';
import { analyzeTaskWithAi } from '../services/ai-analyzer.js';
import { query } from '../db/pool.js';

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });
const router = Router();
router.use(requireAuth);

router.post('/upload', requireRole('SUPER_ADMIN', 'RAHBAR', 'NAZORATCHI'), upload.single('file'), audit('document.upload'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'FILE_REQUIRED' });

  // Production OCR/DOCX/PDF extraction plugs into this boundary.
  const text = req.file.buffer.toString('utf8');
  const parsed = await parseEduIjroDocument({
    fileName: req.file.originalname,
    mimeType: req.file.mimetype,
    text
  });
  const ai = await analyzeTaskWithAi({ documentText: parsed.source_text });

  const saved = await query(
    `insert into documents (document_title, source_file_name, mime_type, extracted_text, ai_summary, priority)
     values ($1,$2,$3,$4,$5,$6) returning *`,
    [parsed.document_title, req.file.originalname, req.file.mimetype, parsed.source_text, ai.task_summary, ai.urgency]
  );

  res.status(201).json({ data: { document: saved.rows[0], parsed, ai } });
});

router.get('/', async (_req, res) => {
  const result = await query('select * from documents order by created_at desc limit 200');
  res.json({ data: result.rows });
});

export default router;
