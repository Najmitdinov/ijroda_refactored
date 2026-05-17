import { query } from '../db/pool.js';
import { sendTelegramMessage, telegramApi } from './telegram-service.js';

type TelegramUpdate = {
  message?: {
    message_id: number;
    text?: string;
    document?: unknown;
    photo?: unknown;
    voice?: unknown;
    chat: { id: number | string };
    from?: { id: number | string; username?: string; first_name?: string; last_name?: string };
  };
  callback_query?: {
    id: string;
    data?: string;
    message?: { message_id: number; chat: { id: number | string } };
    from: { id: number | string };
  };
};

export async function handleTelegramUpdate(update: TelegramUpdate) {
  if (update.callback_query) return handleCallback(update.callback_query);
  if (update.message) return handleMessage(update.message);
  return { ignored: true };
}

async function handleMessage(message: NonNullable<TelegramUpdate['message']>) {
  const chatId = String(message.chat.id);
  const telegramId = String(message.from?.id ?? message.chat.id);
  const text = (message.text || '').trim();

  if (text === '/start') {
    await query(
      `insert into telegram_sessions (telegram_id, username, first_name, last_name, state)
       values ($1,$2,$3,$4,'AWAITING_EMPLOYEE_ID')
       on conflict (telegram_id) do update set username = excluded.username, state = 'AWAITING_EMPLOYEE_ID', updated_at = now()`,
      [telegramId, message.from?.username ?? '', message.from?.first_name ?? '', message.from?.last_name ?? '']
    );
    await sendTelegramMessage(chatId, 'Assalomu alaykum. Royxatdan otish uchun employee_id yuboring.');
    return { handled: 'start' };
  }

  if (text === '/tasks') {
    await sendTasks(chatId, telegramId);
    return { handled: 'tasks' };
  }

  if (message.document || message.photo || message.voice) {
    await query(
      `insert into attachments (uploaded_by_telegram_id, file_kind, metadata)
       values ($1, $2, $3)`,
      [telegramId, message.document ? 'document' : message.photo ? 'photo' : 'voice', JSON.stringify(message)]
    );
    await sendTelegramMessage(chatId, 'Fayl qabul qilindi. Operator uni topshiriqqa biriktirishi mumkin.');
    return { handled: 'file' };
  }

  const session = (await query<{ state: string }>('select state from telegram_sessions where telegram_id = $1', [telegramId])).rows[0];
  if (session?.state === 'AWAITING_EMPLOYEE_ID' && text) {
    const employee = (await query<{ employee_id: string; ism: string; familiya: string }>(
      'update employees set telegram_id = $1, username = $2 where employee_id::text = $3 returning employee_id, ism, familiya',
      [telegramId, message.from?.username ?? '', text]
    )).rows[0];
    if (!employee) {
      await sendTelegramMessage(chatId, 'employee_id topilmadi. Qayta tekshirib yuboring.');
      return { handled: 'employee_not_found' };
    }
    await query('update telegram_sessions set employee_id = $1, state = $2, updated_at = now() where telegram_id = $3', [
      employee.employee_id,
      'ACTIVE',
      telegramId
    ]);
    await sendTelegramMessage(chatId, `Royxatdan otdingiz: ${employee.ism} ${employee.familiya}. /tasks buyrugi orqali vazifalarni koring.`);
    return { handled: 'employee_linked' };
  }

  await sendTelegramMessage(chatId, 'Buyruqlar: /tasks - topshiriqlar, /start - qayta royxatdan otish.');
  return { handled: 'fallback' };
}

async function sendTasks(chatId: string, telegramId: string) {
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
  `, [telegramId])).rows;

  if (!rows.length) {
    await sendTelegramMessage(chatId, 'Aktiv topshiriqlar topilmadi.');
    return;
  }

  for (const task of rows) {
    await telegramApi('sendMessage', {
      chat_id: chatId,
      text: `[${task.priority}] ${task.title}\nMuddat: ${task.deadline ?? 'muddatsiz'}`,
      reply_markup: {
        inline_keyboard: [[
          { text: 'Bajarildi', callback_data: `done:${task.task_id}` },
          { text: 'AI summary', callback_data: `summary:${task.task_id}` }
        ]]
      }
    });
  }
}

async function handleCallback(callback: NonNullable<TelegramUpdate['callback_query']>) {
  const data = callback.data || '';
  const chatId = callback.message?.chat.id ? String(callback.message.chat.id) : String(callback.from.id);

  if (data.startsWith('done:')) {
    const taskId = data.slice('done:'.length);
    await query('update tasks set status = $1, updated_at = now() where task_id = $2', ['DONE', taskId]);
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Bajarildi deb belgilandi' });
    if (callback.message) {
      await telegramApi('editMessageReplyMarkup', {
        chat_id: chatId,
        message_id: callback.message.message_id,
        reply_markup: { inline_keyboard: [] }
      });
    }
    return { handled: 'done' };
  }

  if (data.startsWith('summary:')) {
    const taskId = data.slice('summary:'.length);
    const task = (await query<{ summary: string }>('select summary from tasks where task_id = $1', [taskId])).rows[0];
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id });
    await sendTelegramMessage(chatId, task?.summary || 'Summary topilmadi.');
    return { handled: 'summary' };
  }

  await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Nomalum amal' });
  return { ignored: 'unknown_callback' };
}
