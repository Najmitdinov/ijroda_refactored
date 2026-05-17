import { Router } from 'express';
import { z } from 'zod';
import { query } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { audit } from '../middleware/audit.js';
import { matchEmployee } from '../services/employee-matching.js';
import type { EmployeeProfile } from '../types/shared.js';

const router = Router();
router.use(requireAuth);

router.get('/', async (_req, res) => {
  const result = await query<EmployeeProfile>('select * from employees order by familiya, ism');
  res.json({ data: result.rows });
});

router.post('/', requireRole('SUPER_ADMIN', 'RAHBAR', 'NAZORATCHI'), audit('employee.create'), async (req, res) => {
  const input = z.object({
    ism: z.string(),
    familiya: z.string(),
    sharif: z.string().optional(),
    bolim: z.string(),
    lavozim: z.string(),
    telefon: z.string().optional(),
    telegram_id: z.string().optional(),
    username: z.string().optional(),
    aliases: z.array(z.string()).default([])
  }).parse(req.body);

  const result = await query(
    `insert into employees (ism, familiya, sharif, bolim, lavozim, telefon, telegram_id, username, aliases)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *`,
    [input.ism, input.familiya, input.sharif ?? '', input.bolim, input.lavozim, input.telefon ?? '', input.telegram_id ?? '', input.username ?? '', input.aliases]
  );
  res.status(201).json({ data: result.rows[0] });
});

router.post('/match', async (req, res) => {
  const input = z.object({ name: z.string().min(2) }).parse(req.body);
  const employees = (await query<EmployeeProfile>('select * from employees')).rows;
  res.json({ data: matchEmployee(input.name, employees) });
});

export default router;
