import { env, getPublicBackendUrl } from '../config/env.js';
import { checkDatabase, query } from '../db/pool.js';

const telegramBase = () => {
  if (!env.TELEGRAM_BOT_TOKEN) throw new Error('TELEGRAM_BOT_TOKEN_MISSING');
  return `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}`;
};

type TelegramApiResponse<T> = {
  ok?: boolean;
  result?: T;
  description?: string;
  error_code?: number;
  parameters?: {
    retry_after?: number;
  };
};

type InlineKeyboardButton = {
  text: string;
  callback_data?: string;
  url?: string;
};

type SendOptions = {
  replyMarkup?: Record<string, unknown>;
  disableWebPagePreview?: boolean;
};

let telegramQueue: Promise<unknown> = Promise.resolve();
const queueStats = {
  queued: 0,
  sent: 0,
  failed: 0,
  lastError: ''
};

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function queueTelegramJob<T>(job: () => Promise<T>): Promise<T> {
  queueStats.queued += 1;
  const run = telegramQueue.then(job, job);
  telegramQueue = run
    .then(() => {
      queueStats.sent += 1;
    })
    .catch((error) => {
      queueStats.failed += 1;
      queueStats.lastError = error instanceof Error ? error.message : String(error);
    });
  return run;
}

export async function telegramApi<T = unknown>(method: string, payload?: Record<string, unknown>): Promise<T> {
  let lastError: Error | undefined;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await fetch(`${telegramBase()}/${method}`, {
        method: payload ? 'POST' : 'GET',
        headers: payload ? { 'content-type': 'application/json' } : undefined,
        body: payload ? JSON.stringify(payload) : undefined,
        signal: AbortSignal.timeout(15_000)
      });
      const data = await response.json().catch(() => ({})) as TelegramApiResponse<T>;
      if (response.status === 429 && data.parameters?.retry_after) {
        await sleep(Math.min(data.parameters.retry_after * 1000, 10_000));
        continue;
      }
      if (!response.ok || data.ok === false) {
        throw new Error(data.description || `Telegram HTTP ${response.status}`);
      }
      console.log('[telegram] api ok', { method, attempt });
      return data.result as T;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      console.warn('[telegram] api failed', { method, attempt, error: lastError.message });
      if (attempt < 3) await sleep(400 * attempt);
    }
  }
  throw lastError || new Error(`Telegram API failed: ${method}`);
}

export async function getTelegramStatus() {
  const configured = !!env.TELEGRAM_BOT_TOKEN;
  if (!configured) {
    return {
      configured,
      bot: null,
      webhook: null,
      database: await getTelegramDatabaseStats(),
      queue: queueStats
    };
  }
  const [bot, webhook, database, dbHealth] = await Promise.all([
    telegramApi('getMe'),
    telegramApi('getWebhookInfo'),
    getTelegramDatabaseStats(),
    checkDatabase()
  ]);
  const expectedWebhookUrl = getTelegramWebhookUrl();
  return {
    configured,
    bot,
    webhook,
    webhookExpectedUrl: expectedWebhookUrl,
    webhookActive: Boolean((webhook as { url?: string })?.url && (!expectedWebhookUrl || (webhook as { url?: string }).url === expectedWebhookUrl)),
    database,
    databaseHealth: dbHealth,
    queue: queueStats
  };
}

export function getTelegramWebhookUrl(url?: string) {
  const explicit = (url || env.TELEGRAM_WEBHOOK_URL || '').trim();
  if (explicit) return explicit.replace(/\/+$/, '');
  const publicUrl = getPublicBackendUrl();
  return publicUrl ? `${publicUrl}/api/telegram/webhook/update` : '';
}

export async function setTelegramWebhook(url?: string) {
  const webhookUrl = getTelegramWebhookUrl(url);
  if (!webhookUrl) throw new Error('WEBHOOK_URL_REQUIRED');
  if (!webhookUrl.startsWith('https://')) throw new Error('Webhook URL https:// bilan boshlanishi kerak');
  return telegramApi('setWebhook', {
    url: webhookUrl,
    secret_token: env.TELEGRAM_WEBHOOK_SECRET || undefined,
    allowed_updates: ['message', 'callback_query'],
    drop_pending_updates: false,
    max_connections: 40
  });
}

export async function deleteTelegramWebhook() {
  return telegramApi('deleteWebhook', { drop_pending_updates: false });
}

export async function validateTelegramWebhook(url?: string) {
  const webhook = await telegramApi<{ url?: string; last_error_message?: string; pending_update_count?: number }>('getWebhookInfo');
  const expectedUrl = getTelegramWebhookUrl(url);
  return {
    ok: Boolean(webhook.url && (!expectedUrl || webhook.url === expectedUrl) && !webhook.last_error_message),
    expectedUrl,
    webhook
  };
}

export async function sendTelegramMessage(chatId: string, text: string, options: SendOptions = {}) {
  return queueTelegramJob(() => telegramApi('sendMessage', {
    chat_id: chatId,
    text: text.slice(0, 3900),
    parse_mode: 'HTML',
    disable_web_page_preview: options.disableWebPagePreview ?? true,
    reply_markup: options.replyMarkup
  }));
}

export async function sendTelegramPhoto(chatId: string, photo: string, caption = '', options: SendOptions = {}) {
  return queueTelegramJob(() => telegramApi('sendPhoto', {
    chat_id: chatId,
    photo,
    caption: caption.slice(0, 1000),
    parse_mode: 'HTML',
    reply_markup: options.replyMarkup
  }));
}

export function inlineKeyboard(rows: InlineKeyboardButton[][]) {
  return { inline_keyboard: rows };
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

export async function flushPendingTelegramNotifications(limit = 50) {
  const rows = (await query<{
    notification_id: string;
    telegram_id: string;
    title: string;
    body: string;
  }>(`
    select n.notification_id, e.telegram_id, n.title, n.body
    from notifications n
    join employees e on e.employee_id = n.employee_id
    where n.channel = 'TELEGRAM'
      and n.sent_at is null
      and e.telegram_id is not null
    order by n.created_at
    limit $1
  `, [limit])).rows;

  let sent = 0;
  for (const row of rows) {
    await sendTelegramMessage(row.telegram_id, `<b>${escapeHtml(row.title)}</b>\n${escapeHtml(row.body)}`);
    await query('update notifications set sent_at = now() where notification_id = $1', [row.notification_id]);
    sent += 1;
  }
  return { queued: rows.length, sent };
}

async function getTelegramDatabaseStats() {
  type CountRow = { count: number };
  try {
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
  } catch (error) {
    console.warn('[telegram] database stats unavailable', error);
    return {
      linkedEmployees: 0,
      sessions: 0,
      pendingNotifications: 0,
      databaseUnavailable: true
    };
  }
}

function escapeHtml(input: string) {
  return input.replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[char] || char));
}
