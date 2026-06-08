import 'dotenv/config';
import cron from 'node-cron';
import { Markup, Telegraf } from 'telegraf';
import { query } from './db.js';
import { sendDailyDigest } from './digest.js';

const token = process.env.TELEGRAM_BOT_TOKEN;
if (!token) throw new Error('TELEGRAM_BOT_TOKEN is required');

const bot = new Telegraf(token);

bot.start(async (ctx) => {
  const telegramId = String(ctx.from.id);
  await query(
    `insert into telegram_sessions (telegram_id, username, first_name, last_name, state)
     values ($1,$2,$3,$4,'AWAITING_EMPLOYEE_ID')
     on conflict (telegram_id) do update set username = excluded.username, state = 'AWAITING_EMPLOYEE_ID', updated_at = now()`,
    [telegramId, ctx.from.username ?? '', ctx.from.first_name ?? '', ctx.from.last_name ?? '']
  );
  await ctx.reply('Assalomu alaykum. Ro‘yxatdan o‘tish uchun employee_id yuboring.');
});

bot.command('tasks', async (ctx) => {
  const rows = (await query<{
    task_id: string;
    title: string;
    priority: string;
    deadline: string | null;
  }>(`
    select t.task_id, t.title, t.priority, t.deadline::text
    from tasks t
    join employees e on e.employee_id = t.executor_employee_id
    where e.telegram_id = $1 and t.status in ('NEW','IN_PROGRESS','OVERDUE')
    order by t.deadline nulls last limit 15
  `, [String(ctx.from.id)])).rows;

  if (!rows.length) return ctx.reply('Aktiv topshiriqlar topilmadi.');
  for (const task of rows) {
    await ctx.reply(
      `[${task.priority}] ${task.title}\nMuddat: ${task.deadline ?? 'muddatsiz'}`,
      Markup.inlineKeyboard([
        Markup.button.callback('✅ Bajarildi', `done:${task.task_id}`),
        Markup.button.callback('📄 AI summary', `summary:${task.task_id}`)
      ])
    );
  }
});

bot.on('text', async (ctx) => {
  const telegramId = String(ctx.from.id);
  const text = ctx.message.text.trim();
  const session = (await query<{ state: string }>('select state from telegram_sessions where telegram_id = $1', [telegramId])).rows[0];

  if (session?.state === 'AWAITING_EMPLOYEE_ID') {
    const employee = (await query<{ employee_id: string; ism: string; familiya: string }>('update employees set telegram_id = $1, username = $2 where employee_id::text = $3 returning employee_id, ism, familiya', [
      telegramId,
      ctx.from.username ?? '',
      text
    ])).rows[0];
    if (!employee) return ctx.reply('employee_id topilmadi. Qayta tekshirib yuboring.');
    await query('update telegram_sessions set employee_id = $1, state = $2 where telegram_id = $3', [employee.employee_id, 'ACTIVE', telegramId]);
    return ctx.reply(`Ro‘yxatdan o‘tdingiz: ${employee.ism} ${employee.familiya}. /tasks buyrug‘i orqali vazifalarni ko‘ring.`);
  }

  return ctx.reply('Buyruqlar: /tasks — topshiriqlar, /start — qayta ro‘yxatdan o‘tish.');
});

bot.on(['document', 'photo', 'voice'], async (ctx) => {
  await query(
    `insert into attachments (uploaded_by_telegram_id, file_kind, metadata)
     values ($1, $2, $3)`,
    [String(ctx.from.id), ctx.updateType, JSON.stringify(ctx.message)]
  );
  await ctx.reply('Fayl qabul qilindi. Operator uni topshiriqqa biriktirishi mumkin.');
});

bot.action(/^done:(.+)$/, async (ctx) => {
  const taskId = ctx.match[1];
  await query('update tasks set status = $1, updated_at = now() where task_id = $2', ['DONE', taskId]);
  await ctx.answerCbQuery('Bajarildi deb belgilandi');
  await ctx.editMessageReplyMarkup(undefined);
});

bot.action(/^summary:(.+)$/, async (ctx) => {
  const taskId = ctx.match[1];
  const task = (await query<{ summary: string }>('select summary from tasks where task_id = $1', [taskId])).rows[0];
  await ctx.answerCbQuery();
  await ctx.reply(task?.summary || 'Summary topilmadi.');
});

cron.schedule('0 8 * * *', () => {
  sendDailyDigest(bot).catch((error) => console.error('[digest]', error));
}, { timezone: 'Asia/Tashkent' });

bot.launch();
console.log('[bot] launched');

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
