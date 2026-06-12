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
    priority: z.enum(['LOW', 'NORMAL', 'IMPORTANT', 'URGENT', 'CRITICAL']).default('NORMAL'),
    external_id: z.string().optional(),
    letter_number: z.string().optional(),
    source_organization: z.string().optional(),
    organization_id: z.string().uuid().optional()
  }).parse(req.body);

  const result = await query(
    `insert into tasks (document_id, executor_employee_id, department_id, title, summary, deadline, priority)
     values ($1,$2,$3,$4,$5,$6,$7) returning *`,
    [input.document_id, input.executor_employee_id ?? null, input.department_id ?? null, input.title, input.summary, input.deadline ?? null, input.priority]
  );
  const task = result.rows[0];
  const letter = await query<{ letter_id: string }>(
    `insert into letters
       (organization_id, employee_id, document_id, task_id, external_id, letter_number, subject, body, deadline, status, urgency, source_organization)
     values ($1,$2,$3,$4,nullif($5,''),$6,$7,$8,$9,'NEW',$10,$11)
     on conflict (external_id) do update set
       employee_id = excluded.employee_id,
       task_id = excluded.task_id,
       subject = excluded.subject,
       body = excluded.body,
       deadline = excluded.deadline,
       urgency = excluded.urgency,
       updated_at = now()
     returning letter_id`,
    [
      input.organization_id ?? null,
      input.executor_employee_id ?? null,
      input.document_id,
      task.task_id,
      input.external_id ?? '',
      input.letter_number ?? '',
      input.title,
      input.summary,
      input.deadline ?? null,
      input.priority,
      input.source_organization ?? ''
    ]
  );
  if (input.executor_employee_id) {
    await enqueueNotification({
      employeeId: input.executor_employee_id,
      channel: 'TELEGRAM',
      title: 'Yangi topshiriq',
      body: input.summary,
      priority: input.priority,
      metadata: { task_id: task.task_id, letter_id: letter.rows[0]?.letter_id }
    });
  }
  res.status(201).json({ data: { ...task, letter_id: letter.rows[0]?.letter_id } });
});

router.patch('/:taskId/status', audit('task.status'), async (req, res) => {
  const input = z.object({
    status: z.enum(['NEW', 'IN_PROGRESS', 'DONE', 'OVERDUE', 'CANCELLED'])
  }).parse(req.body);
  const result = await query(
    `update tasks set status = $1, updated_at = now() where task_id = $2 returning *`,
    [input.status, req.params.taskId]
  );
  await query('update letters set status = $1, updated_at = now() where task_id = $2', [input.status, req.params.taskId]);
  res.json({ data: result.rows[0] });
});

export default router;
