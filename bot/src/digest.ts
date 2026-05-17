import type { Telegraf } from 'telegraf';
import { query } from './db.js';

interface DigestRow {
  telegram_id: string;
  title: string;
  priority: string;
  deadline: string | null;
  status: string;
}

export async function sendDailyDigest(bot: Telegraf) {
  const rows = (await query<DigestRow>(`
    select e.telegram_id, t.title, t.priority, t.deadline::text, t.status
    from tasks t
    join employees e on e.employee_id = t.executor_employee_id
    where e.telegram_id is not null
      and t.status in ('NEW', 'IN_PROGRESS', 'OVERDUE')
      and (t.deadline is null or t.deadline <= now() + interval '3 days')
    order by e.telegram_id, t.priority desc, t.deadline nulls last
  `)).rows;

  const grouped = new Map<string, DigestRow[]>();
  rows.forEach((row) => grouped.set(row.telegram_id, [...(grouped.get(row.telegram_id) ?? []), row]));

  for (const [telegramId, tasks] of grouped) {
    const urgent = tasks.filter((task) => ['URGENT', 'CRITICAL'].includes(task.priority));
    const overdue = tasks.filter((task) => task.status === 'OVERDUE');
    const body = [
      '📌 Kunlik ijro digest',
      `Bugungi/yaqin topshiriqlar: ${tasks.length}`,
      `Shoshilinch: ${urgent.length}`,
      `Kechikkan: ${overdue.length}`,
      '',
      ...tasks.slice(0, 12).map((task, idx) => `${idx + 1}. [${task.priority}] ${task.title} — ${task.deadline ?? 'muddatsiz'}`)
    ].join('\n');
    await bot.telegram.sendMessage(telegramId, body);
  }
}
