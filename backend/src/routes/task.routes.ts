import { Router } from 'express';
import { z } from 'zod';
import { query } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { audit } from '../middleware/audit.js';
import { enqueueNotification } from '../services/notification-engine.js';

const router = Router();
router.use(requireAuth);

router.get('/', async (req, res) => {
  const mineOnly = req.query.mine === 'true' && req.user?.employee_id;
  const result = await query<{ task_id: string }>(
    `select t.*, e.ism, e.familiya, d.document_title
     from tasks t
     left join employees e on e.employee_id = t.executor_employee_id
     left join documents d on d.document_id = t.document_id
     ${mineOnly ? 'where t.executor_employee_id = $1' : ''}
     order by t.deadline nulls last, t.created_at desc
     limit 500`,
    mineOnly ? [req.user!.employee_id] : []
  );
  res.json({ data: result.rows });
});

router.post('/', audit('task.create'), async (req, res) => {
  const input = z.object({
    document_id: z.string().uuid(),
    executor_employee_id: z.string().uuid().optional(),
    department_id: z.string().uuid().optional(),
    title: z.string(),
    summary: z.string(),
    deadline: z.string().optional(),
    priority: z.enum(['LOW', 'NORMAL', 'IMPORTANT', 'URGENT', 'CRITICAL']).default('NORMAL')
  }).parse(req.body);

  const result = await query(
    `insert into tasks (document_id, executor_employee_id, department_id, title, summary, deadline, priority)
     values ($1,$2,$3,$4,$5,$6,$7) returning *`,
    [input.document_id, input.executor_employee_id ?? null, input.department_id ?? null, input.title, input.summary, input.deadline ?? null, input.priority]
  );
  if (input.executor_employee_id) {
    await enqueueNotification({
      employeeId: input.executor_employee_id,
      channel: 'TELEGRAM',
      title: 'Yangi topshiriq',
      body: input.summary,
      priority: input.priority,
      metadata: { task_id: result.rows[0].task_id }
    });
  }
  res.status(201).json({ data: result.rows[0] });
});

router.patch('/:taskId/status', audit('task.status'), async (req, res) => {
  const input = z.object({
    status: z.enum(['NEW', 'IN_PROGRESS', 'DONE', 'OVERDUE', 'CANCELLED'])
  }).parse(req.body);
  const result = await query(
    `update tasks set status = $1, updated_at = now() where task_id = $2 returning *`,
    [input.status, req.params.taskId]
  );
  res.json({ data: result.rows[0] });
});

export default router;
