import { query } from '../db/pool.js';
import { inlineKeyboard, sendTelegramMessage, telegramApi } from './telegram-service.js';

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

const spamBucket = new Map<string, { count: number; resetAt: number }>();

export async function handleTelegramUpdate(update: TelegramUpdate) {
  if (update.callback_query) return handleCallback(update.callback_query);
  if (update.message) return handleMessage(update.message);
  return { ignored: true };
}

async function handleMessage(message: NonNullable<TelegramUpdate['message']>) {
  const chatId = String(message.chat.id);
  const telegramId = String(message.from?.id ?? message.chat.id);
  const text = (message.text || '').trim();
  if (isSpam(telegramId)) {
    console.warn('[telegram] spam protection triggered', { telegramId });
    await sendTelegramMessage(chatId, 'Juda kop sorov yuborildi. Iltimos, birozdan keyin urinib koring.');
    return { ignored: 'rate_limited' };
  }

  console.log('[telegram] message received', {
    chatId,
    telegramId,
    hasText: Boolean(text),
    hasFile: Boolean(message.document || message.photo || message.voice)
  });

  if (text.startsWith('/start')) {
    const employeeCredential = text.replace(/^\/start(?:@\w+)?/i, '').trim();
    await query(
      `insert into telegram_sessions (telegram_id, username, first_name, last_name, state)
       values ($1,$2,$3,$4,'AWAITING_EMPLOYEE_ID')
       on conflict (telegram_id) do update set username = excluded.username, state = 'AWAITING_EMPLOYEE_ID', updated_at = now()`,
      [telegramId, message.from?.username ?? '', message.from?.first_name ?? '', message.from?.last_name ?? '']
    );
    if (employeeCredential) return linkEmployee(chatId, telegramId, employeeCredential, message.from?.username ?? '');
    await sendTelegramMessage(
      chatId,
      'Assalomu alaykum. Ro‘yxatdan o‘tish uchun xodim ID, telefon raqami yoki F.I.Sh.ni yuboring.\n\nBuyruqlar:\n/tasks - aktiv xatlar\n/settings - bot sozlamalari\n/help - yordam',
      {
        replyMarkup: inlineKeyboard([
          [{ text: 'Aktiv xatlar', callback_data: 'tasks' }],
          [{ text: 'Sozlamalar', callback_data: 'settings' }]
        ])
      }
    );
    return { handled: 'start' };
  }

  if (/^\/(tasks|today)(?:@\w+)?$/i.test(text)) {
    await sendTasks(chatId, telegramId);
    return { handled: 'tasks' };
  }

  if (/^\/settings(?:@\w+)?$/i.test(text)) {
    await sendSettings(chatId, telegramId);
    return { handled: 'settings' };
  }

  if (/^\/help(?:@\w+)?$/i.test(text)) {
    await sendTelegramMessage(
      chatId,
      'Ijro nazorati bot buyruqlari:\n/tasks - sizga biriktirilgan aktiv xatlar\n/today - bugungi va yaqin muddatli xatlar\n/settings - eslatma va til sozlamalari\n/start - qayta ro‘yxatdan o‘tish'
    );
    return { handled: 'help' };
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
    return linkEmployee(chatId, telegramId, text, message.from?.username ?? '');
  }

  await sendTelegramMessage(chatId, 'Buyruqlar: /tasks - aktiv xatlar, /settings - sozlamalar, /start - qayta ro‘yxatdan o‘tish.');
  return { handled: 'fallback' };
}

function isSpam(telegramId: string) {
  const now = Date.now();
  const bucket = spamBucket.get(telegramId);
  if (!bucket || bucket.resetAt < now) {
    spamBucket.set(telegramId, { count: 1, resetAt: now + 60_000 });
    return false;
  }
  bucket.count += 1;
  return bucket.count > 20;
}

async function linkEmployee(chatId: string, telegramId: string, credential: string, username: string) {
  const employee = (await query<{ employee_id: string; ism: string; familiya: string }>(
    `with matched as (
       select employee_id
       from employees
       where active = true
         and (
           employee_id::text = $3
           or (
             length(regexp_replace($3, '\\D', '', 'g')) >= 7
             and regexp_replace(coalesce(telefon, ''), '\\D', '', 'g') = regexp_replace($3, '\\D', '', 'g')
           )
           or lower(concat_ws(' ', familiya, ism, sharif)) = lower($3)
           or lower(concat_ws(' ', ism, familiya, sharif)) = lower($3)
         )
       order by
         case when employee_id::text = $3 then 0
              when length(regexp_replace($3, '\\D', '', 'g')) >= 7
                   and regexp_replace(coalesce(telefon, ''), '\\D', '', 'g') = regexp_replace($3, '\\D', '', 'g') then 1
              else 2 end
       limit 1
     )
     update employees e set
       telegram_id = $1,
       username = $2,
       bot_status = 'ACTIVE',
       registered_at = coalesce(registered_at, now()),
       updated_at = now()
     from matched
     where e.employee_id = matched.employee_id
     returning e.employee_id, e.ism, e.familiya`,
    [telegramId, username, credential.trim()]
  )).rows[0];
  if (!employee) {
    await sendTelegramMessage(chatId, 'Xodim topilmadi. ID, telefon raqami yoki F.I.Sh.ni dasturdagi ma’lumot bilan bir xil yozib qayta yuboring.');
    return { handled: 'employee_not_found' };
  }
  await query('update telegram_sessions set employee_id = $1, state = $2, updated_at = now() where telegram_id = $3', [
    employee.employee_id,
    'ACTIVE',
    telegramId
  ]);
  await query(
    `insert into bot_settings (employee_id)
     values ($1)
     on conflict (employee_id) do nothing`,
    [employee.employee_id]
  );
  await sendTelegramMessage(
    chatId,
    `Ro‘yxatdan o‘tdingiz: ${escapeHtml(employee.ism)} ${escapeHtml(employee.familiya)}.\n/tasks buyrug‘i orqali sizga biriktirilgan xatlarni ko‘ring.`,
    {
      replyMarkup: inlineKeyboard([
        [{ text: 'Xatlarni ko‘rish', callback_data: 'tasks' }],
        [{ text: 'Sozlamalar', callback_data: 'settings' }]
      ])
    }
  );
  return { handled: 'employee_linked' };
}

async function sendTasks(chatId: string, telegramId: string) {
  const rows = (await query<{
    item_id: string;
    item_type: 'LETTER' | 'TASK';
    letter_number: string;
    title: string;
    priority: string;
    deadline: string | null;
  }>(`
    select *
    from (
      select l.letter_id::text as item_id, 'LETTER'::text as item_type,
             l.letter_number, l.subject as title, l.urgency::text as priority, l.deadline::text
      from letters l
      join employees e on e.employee_id = l.employee_id
      where e.telegram_id = $1 and l.status not in ('DONE','CANCELLED')

      union all

      select t.task_id::text as item_id, 'TASK'::text as item_type,
             ''::text as letter_number, t.title, t.priority::text, t.deadline::date::text
      from tasks t
      join employees e on e.employee_id = t.executor_employee_id
      left join letters l on l.task_id = t.task_id
      where e.telegram_id = $1
        and l.letter_id is null
        and t.status in ('NEW','IN_PROGRESS','OVERDUE')
    ) items
    order by deadline nulls last
    limit 20
  `, [telegramId])).rows;

  if (!rows.length) {
    await sendTelegramMessage(chatId, 'Sizga biriktirilgan aktiv xatlar topilmadi.');
    return;
  }

  for (const task of rows) {
    const itemKey = task.item_type === 'LETTER' ? `letter:${task.item_id}` : `task:${task.item_id}`;
    const number = task.letter_number ? `№ ${escapeHtml(task.letter_number)}\n` : '';
    await sendTelegramMessage(
      chatId,
      `${number}<b>[${task.priority}]</b> ${escapeHtml(task.title)}\nMuddat: ${escapeHtml(task.deadline ?? 'muddatsiz')}`,
      {
        replyMarkup: inlineKeyboard([[
          { text: 'Bajarildi', callback_data: `done:${itemKey}` },
          { text: 'Batafsil', callback_data: `summary:${itemKey}` }
        ]])
      }
    );
  }
}

async function sendSettings(chatId: string, telegramId: string) {
  const settings = (await query<{
    reminder_time: string;
    active: boolean;
    language: string;
  }>(
    `select to_char(bs.reminder_time, 'HH24:MI') as reminder_time, bs.active, bs.language
     from employees e
     join bot_settings bs on bs.employee_id = e.employee_id
     where e.telegram_id = $1`,
    [telegramId]
  )).rows[0];
  if (!settings) {
    await sendTelegramMessage(chatId, 'Avval /start orqali ro‘yxatdan o‘ting.');
    return;
  }
  await sendTelegramMessage(
    chatId,
    `Bot sozlamalari\nEslatma vaqti: ${settings.reminder_time}\nBildirishnomalar: ${settings.active ? 'yoqilgan' : 'o‘chirilgan'}\nTil: ${settings.language}`,
    {
      replyMarkup: inlineKeyboard([
        [{ text: settings.active ? 'Bildirishnomani o‘chirish' : 'Bildirishnomani yoqish', callback_data: 'settings:toggle' }],
        [
          { text: 'O‘zbek', callback_data: 'settings:lang:uz' },
          { text: 'Ўзбек', callback_data: 'settings:lang:uz_cyrl' },
          { text: 'Русский', callback_data: 'settings:lang:ru' }
        ],
        [
          { text: '08:00', callback_data: 'settings:time:08:00' },
          { text: '09:00', callback_data: 'settings:time:09:00' },
          { text: '10:00', callback_data: 'settings:time:10:00' }
        ]
      ])
    }
  );
}

async function handleCallback(callback: NonNullable<TelegramUpdate['callback_query']>) {
  const data = callback.data || '';
  const chatId = callback.message?.chat.id ? String(callback.message.chat.id) : String(callback.from.id);
  console.log('[telegram] callback received', { data, chatId });

  if (data === 'tasks') {
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id });
    await sendTasks(chatId, String(callback.from.id));
    return { handled: 'tasks_callback' };
  }

  if (data === 'settings') {
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id });
    await sendSettings(chatId, String(callback.from.id));
    return { handled: 'settings_callback' };
  }

  if (data === 'settings:toggle') {
    await query(
      `update bot_settings bs set active = not bs.active, updated_at = now()
       from employees e
       where bs.employee_id = e.employee_id and e.telegram_id = $1`,
      [String(callback.from.id)]
    );
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Sozlama yangilandi' });
    await sendSettings(chatId, String(callback.from.id));
    return { handled: 'settings_toggle' };
  }

  if (data.startsWith('settings:lang:')) {
    const language = data.slice('settings:lang:'.length);
    if (!['uz', 'uz_cyrl', 'ru'].includes(language)) return { ignored: 'invalid_language' };
    await query(
      `update bot_settings bs set language = $2, updated_at = now()
       from employees e
       where bs.employee_id = e.employee_id and e.telegram_id = $1`,
      [String(callback.from.id), language]
    );
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Til yangilandi' });
    return { handled: 'settings_language' };
  }

  if (data.startsWith('settings:time:')) {
    const reminderTime = data.slice('settings:time:'.length);
    if (!/^(08|09|10):00$/.test(reminderTime)) return { ignored: 'invalid_reminder_time' };
    await query(
      `update bot_settings bs set reminder_time = $2::time, updated_at = now()
       from employees e
       where bs.employee_id = e.employee_id and e.telegram_id = $1`,
      [String(callback.from.id), reminderTime]
    );
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: `Eslatma ${reminderTime} ga o‘rnatildi` });
    return { handled: 'settings_time' };
  }

  if (data.startsWith('done:')) {
    const [itemType, itemId] = data.slice('done:'.length).split(':');
    const table = itemType === 'letter' ? 'letters' : itemType === 'task' ? 'tasks' : '';
    const idColumn = itemType === 'letter' ? 'letter_id' : 'task_id';
    const employeeColumn = itemType === 'letter' ? 'employee_id' : 'executor_employee_id';
    if (!table || !itemId) return { ignored: 'invalid_done_callback' };
    const updated = await query(
      `update ${table} item set status = 'DONE', updated_at = now()
       from employees e
       where item.${idColumn} = $1
         and item.${employeeColumn} = e.employee_id
         and e.telegram_id = $2
       returning item.${idColumn}`,
      [itemId, String(callback.from.id)]
    );
    if (!updated.rowCount) {
      await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Ushbu xat sizga biriktirilmagan' });
      return { ignored: 'not_owner' };
    }
    if (itemType === 'letter') {
      await query(
        `update tasks set status = 'DONE', updated_at = now()
         where task_id = (select task_id from letters where letter_id = $1)`,
        [itemId]
      );
    } else {
      await query(`update letters set status = 'DONE', updated_at = now() where task_id = $1`, [itemId]);
    }
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
    const [itemType, itemId] = data.slice('summary:'.length).split(':');
    const task = itemType === 'letter'
      ? (await query<{ summary: string }>(
          `select coalesce(nullif(l.body, ''), l.subject) as summary
           from letters l join employees e on e.employee_id = l.employee_id
           where l.letter_id = $1 and e.telegram_id = $2`,
          [itemId, String(callback.from.id)]
        )).rows[0]
      : (await query<{ summary: string }>(
          `select t.summary
           from tasks t join employees e on e.employee_id = t.executor_employee_id
           where t.task_id = $1 and e.telegram_id = $2`,
          [itemId, String(callback.from.id)]
        )).rows[0];
    await telegramApi('answerCallbackQuery', { callback_query_id: callback.id });
    await sendTelegramMessage(chatId, task?.summary ? escapeHtml(task.summary) : 'Batafsil ma’lumot topilmadi.');
    return { handled: 'summary' };
  }

  await telegramApi('answerCallbackQuery', { callback_query_id: callback.id, text: 'Nomalum amal' });
  return { ignored: 'unknown_callback' };
}

function escapeHtml(input: string) {
  return input.replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[char] || char));
}
