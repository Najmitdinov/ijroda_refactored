import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { query } from '../db/pool.js';

const router = Router();
router.use(requireAuth);

router.get('/dashboard', async (_req, res) => {
  const [status, priority, employeeKpi] = await Promise.all([
    query('select status, count(*)::int as count from tasks group by status'),
    query('select priority, count(*)::int as count from tasks group by priority'),
    query(`
      select e.employee_id, e.ism, e.familiya,
             count(t.*)::int as total,
             count(*) filter (where t.status = 'DONE')::int as done,
             count(*) filter (where t.status = 'OVERDUE')::int as overdue
      from employees e
      left join tasks t on t.executor_employee_id = e.employee_id
      group by e.employee_id
      order by overdue desc, total desc
      limit 20
    `)
  ]);

  res.json({ data: { status: status.rows, priority: priority.rows, employeeKpi: employeeKpi.rows } });
});

export default router;
