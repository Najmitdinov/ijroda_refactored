import { env } from '../config/env.js';
import { query } from '../db/pool.js';

const telegramBase = () => {
  if (!env.TELEGRAM_BOT_TOKEN) throw new Error('TELEGRAM_BOT_TOKEN_MISSING');
  return `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}`;
};

export async function telegramApi<T = unknown>(method: string, payload?: Record<string, unknown>): Promise<T> {
  const response = await fetch(`${telegramBase()}/${method}`, {
    method: payload ? 'POST' : 'GET',
    headers: payload ? { 'content-type': 'application/json' } : undefined,
    body: payload ? JSON.stringify(payload) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    throw new Error(data.description || `Telegram HTTP ${response.status}`);
  }
  return data.result as T;
}

export async function getTelegramStatus() {
  const configured = !!env.TELEGRAM_BOT_TOKEN;
  if (!configured) {
    return {
      configured,
      bot: null,
      webhook: null,
      database: await getTelegramDatabaseStats()
    };
  }
  const [bot, webhook, database] = await Promise.all([
    telegramApi('getMe'),
    telegramApi('getWebhookInfo'),
    getTelegramDatabaseStats()
  ]);
  return { configured, bot, webhook, database };
}

export async function setTelegramWebhook(url: string) {
  if (!url.startsWith('https://')) throw new Error('Webhook URL https:// bilan boshlanishi kerak');
  return telegramApi('setWebhook', {
    url,
    secret_token: env.TELEGRAM_WEBHOOK_SECRET || undefined,
    allowed_updates: ['message', 'callback_query']
  });
}

export async function deleteTelegramWebhook() {
  return telegramApi('deleteWebhook', { drop_pending_updates: false });
}

export async function sendTelegramMessage(chatId: string, text: string) {
  return telegramApi('sendMessage', {
    chat_id: chatId,
    text: text.slice(0, 3900),
    parse_mode: 'HTML',
    disable_web_page_preview: true
  });
}

export async function sendTelegramDailyDigest(chatId?: string) {
  const rows = (await query<{
    telegram_id: string;
    title: string;
    priority: string;
    deadline: string | null;
    status: string;
  }>(`
    select e.telegram_id, t.title, t.priority, t.deadline::text, t.status
    from tasks t
    join employees e on e.employee_id = t.executor_employee_id
    where e.telegram_id is not null
      and t.status in ('NEW','IN_PROGRESS','OVERDUE')
      and ($1::text is null or e.telegram_id = $1)
    order by e.telegram_id, t.priority desc, t.deadline nulls last
    limit 200
  `, [chatId || null])).rows;

  const grouped = new Map<string, typeof rows>();
  rows.forEach((row) => grouped.set(row.telegram_id, [...(grouped.get(row.telegram_id) ?? []), row]));

  let sent = 0;
  for (const [telegramId, tasks] of grouped) {
    const critical = tasks.filter((task) => ['URGENT', 'CRITICAL'].includes(task.priority)).length;
    const overdue = tasks.filter((task) => task.status === 'OVERDUE').length;
    const body = [
      '<b>Kunlik ijro digest</b>',
      `Jami aktiv topshiriqlar: <b>${tasks.length}</b>`,
      `Shoshilinch: <b>${critical}</b>`,
      `Kechikkan: <b>${overdue}</b>`,
      '',
      ...tasks.slice(0, 12).map((task, index) => `${index + 1}. [${task.priority}] ${escapeHtml(task.title)} - ${task.deadline ?? 'muddatsiz'}`)
    ].join('\n');
    await sendTelegramMessage(telegramId, body);
    sent += 1;
  }
  return { recipients: grouped.size, sent };
}

async function getTelegramDatabaseStats() {
  type CountRow = { count: number };
  const [linkedEmployees, sessions, pendingNotifications] = await Promise.all([
    query<CountRow>('select count(*)::int as count from employees where telegram_id is not null'),
    query<CountRow>('select count(*)::int as count from telegram_sessions'),
    query<CountRow>("select count(*)::int as count from notifications where channel = 'TELEGRAM' and sent_at is null")
  ]);
  return {
    linkedEmployees: linkedEmployees.rows[0]?.count ?? 0,
    sessions: sessions.rows[0]?.count ?? 0,
    pendingNotifications: pendingNotifications.rows[0]?.count ?? 0
  };
}

function escapeHtml(input: string) {
  return input.replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[char] || char));
}
