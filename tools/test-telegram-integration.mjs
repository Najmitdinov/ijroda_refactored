import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import http from 'node:http';

const schemaSql = await readFile(new URL('../database/migrations/002_telegram_bot_schema.sql', import.meta.url), 'utf8');
for (const table of ['organizations', 'letters', 'notification_logs', 'bot_settings']) {
  assert.match(schemaSql, new RegExp(`create table if not exists ${table}\\b`, 'i'), `${table} jadvali migratsiyada topilmadi`);
}
const appSource = await readFile(new URL('../js/app.js', import.meta.url), 'utf8');
assert.match(appSource, /function buildTelegramDatabasePayload/);
assert.match(appSource, /callTelegramBackend\('\/sync'/);
assert.match(appSource, /applyTelegramLetterStatuses/);

const updateHandlerSource = await readFile(new URL('../backend/src/services/telegram-update-handler.ts', import.meta.url), 'utf8');
assert.match(updateHandlerSource, /\/settings/);
assert.match(updateHandlerSource, /letters/);
assert.match(updateHandlerSource, /length\(regexp_replace\(\$3,[\s\S]*\)\) >= 7/);

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address()));
  });
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

let webhook = { url: '', pending_update_count: 0 };
let setWebhookPayload = null;
const fakeTelegram = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
  const method = req.url?.split('/').pop();
  let result;

  if (method === 'getMe') {
    result = { id: 1, is_bot: true, username: 'ijro_test_bot', first_name: 'Ijro Test' };
  } else if (method === 'getWebhookInfo') {
    result = webhook;
  } else if (method === 'setWebhook') {
    setWebhookPayload = body;
    webhook = { url: body.url, pending_update_count: 0 };
    result = true;
  } else if (method === 'sendMessage') {
    result = { message_id: 1, chat: { id: body.chat_id }, text: body.text };
  } else {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false, description: `Unknown method: ${method}` }));
    return;
  }

  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ ok: true, result }));
});

const fakeAddress = await listen(fakeTelegram);
const fakeTelegramBase = `http://127.0.0.1:${fakeAddress.port}`;

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgres://test:test@127.0.0.1:1/ijro_test';
process.env.JWT_SECRET = 'test-jwt-secret-with-at-least-24-characters';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-with-at-least-24-characters';
process.env.TELEGRAM_BOT_TOKEN = 'TEST_TOKEN';
process.env.TELEGRAM_API_BASE = fakeTelegramBase;
process.env.TELEGRAM_ADMIN_SECRET = 'admin secret containing spaces';
delete process.env.TELEGRAM_WEBHOOK_SECRET;
process.env.PUBLIC_BACKEND_URL = 'https://example.railway.app';

const telegramService = await import('../backend/src/services/telegram-service.ts');
const { pool } = await import('../backend/src/db/pool.ts');
const telegramRouter = (await import('../backend/src/routes/telegram.routes.ts')).default;
const express = (await import('express')).default;

const derivedSecret = telegramService.getTelegramWebhookSecret();
assert.match(derivedSecret, /^[a-f0-9]{64}$/);

const setupResult = await telegramService.ensureTelegramWebhook();
assert.equal(setupResult.configured, true);
assert.equal(setupResult.changed, true);
assert.equal(setWebhookPayload.url, 'https://example.railway.app/api/telegram/webhook/update');
assert.equal(setWebhookPayload.secret_token, derivedSecret);

const publicStatus = await telegramService.getTelegramPublicStatus();
assert.equal(publicStatus.configured, true);
assert.equal(publicStatus.webhookActive, true);
assert.equal(publicStatus.bot.username, 'ijro_test_bot');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use('/api/telegram', telegramRouter);
const api = http.createServer(app);
const apiAddress = await listen(api);
const apiBase = `http://127.0.0.1:${apiAddress.port}`;

const publicStatusResponse = await fetch(`${apiBase}/api/telegram/public-status`);
assert.equal(publicStatusResponse.status, 200);
assert.equal((await publicStatusResponse.json()).data.bot.username, 'ijro_test_bot');

const protectedStatusResponse = await fetch(`${apiBase}/api/telegram/status`);
assert.equal(protectedStatusResponse.status, 403);

const rejectedWebhookResponse = await fetch(`${apiBase}/api/telegram/webhook/update`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ update_id: 1000 })
});
assert.equal(rejectedWebhookResponse.status, 403);

const started = Date.now();
const webhookResponse = await fetch(`${apiBase}/api/telegram/webhook/update`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'x-telegram-bot-api-secret-token': derivedSecret
  },
  body: JSON.stringify({
    update_id: 1001,
    message: {
      message_id: 10,
      text: '/start',
      chat: { id: 12345 },
      from: { id: 12345, first_name: 'Test' }
    }
  })
});
const elapsed = Date.now() - started;
assert.equal(webhookResponse.status, 200);
assert.equal((await webhookResponse.json()).accepted, true);
assert.ok(elapsed < 1000, `Webhook juda sekin javob berdi: ${elapsed} ms`);

await new Promise((resolve) => setTimeout(resolve, 150));
await close(api);
await pool.end();
await close(fakeTelegram);

console.log(`Telegram integratsiyasi: webhook auto-setup, public status va ${elapsed} ms tezkor qabul muvaffaqiyatli.`);
