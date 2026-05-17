import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { env } from '../config/env.js';
import { query } from '../db/pool.js';
import { audit } from '../middleware/audit.js';

const router = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
});

router.post('/login', audit('auth.login'), async (req, res) => {
  const input = loginSchema.parse(req.body);
  const result = await query<{
    user_id: string;
    password_hash: string;
    role: string;
    employee_id: string | null;
    is_active: boolean;
  }>(
    'select user_id, password_hash, role, employee_id, is_active from users where email = $1',
    [input.email.toLowerCase()]
  );
  const user = result.rows[0];
  if (!user?.is_active || !(await bcrypt.compare(input.password, user.password_hash))) {
    return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
  }

  const payload = { user_id: user.user_id, role: user.role, employee_id: user.employee_id ?? undefined };
  const accessToken = jwt.sign(payload, env.JWT_SECRET, { expiresIn: '30m' });
  const refreshToken = jwt.sign(payload, env.JWT_REFRESH_SECRET, { expiresIn: '14d' });
  await query('insert into login_logs (user_id, ip_address, user_agent) values ($1, $2, $3)', [
    user.user_id,
    req.ip,
    req.header('user-agent') ?? ''
  ]);

  return res.json({ accessToken, refreshToken, user: payload });
});

export default router;
