import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { completeJson } from '../services/ai-provider.js';

const router = Router();
router.use(requireAuth);

router.post('/letter', async (req, res) => {
  const input = z.object({
    taskText: z.string(),
    recipient: z.string(),
    templateText: z.string().optional()
  }).parse(req.body);

  const data = await completeJson({
    system: 'You write professional Uzbek government response letters. Return JSON only.',
    prompt: JSON.stringify({
      output_schema: {
        recipient: 'string',
        subject: 'string',
        body: 'string',
        legal_basis: ['string'],
        confidence_score: 0
      },
      requirements: [
        'formal legal style',
        'professional government format',
        'do not invent laws',
        'body must not include header/signature'
      ],
      ...input
    })
  });

  res.json({ data });
});

export default router;
