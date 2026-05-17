import { Router } from 'express';
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { env } from '../config/env.js';
import {
  deleteTelegramWebhook,
  getTelegramStatus,
  sendTelegramDailyDigest,
  sendTelegramMessage,
  setTelegramWebhook
} from '../services/telegram-service.js';
import { handleTelegramUpdate } from '../services/telegram-update-handler.js';

const router = Router();

function requireTelegramAdmin(req: Request, res: Response, next: NextFunction) {
  if (!env.TELEGRAM_ADMIN_SECRET) return next();
  const secret = req.header('x-telegram-admin-secret');
  if (secret !== env.TELEGRAM_ADMIN_SECRET) return res.status(403).json({ error: 'TELEGRAM_ADMIN_FORBIDDEN' });
  return next();
}

router.get('/status', requireTelegramAdmin, async (_req, res) => {
  res.json({ data: await getTelegramStatus() });
});

router.post('/test', requireTelegramAdmin, async (req, res) => {
  const input = z.object({
    chatId: z.string().min(1),
    text: z.string().optional()
  }).parse(req.body);
  const result = await sendTelegramMessage(
    input.chatId,
    input.text || '<b>Ijro AI</b>\nTelegram bot backend orqali muvaffaqiyatli ulandi.'
  );
  res.json({ data: result });
});

router.post('/digest', requireTelegramAdmin, async (req, res) => {
  const input = z.object({ chatId: z.string().optional() }).parse(req.body ?? {});
  res.json({ data: await sendTelegramDailyDigest(input.chatId) });
});

router.post('/webhook', requireTelegramAdmin, async (req, res) => {
  const input = z.object({ url: z.string().url() }).parse(req.body);
  res.json({ data: await setTelegramWebhook(input.url) });
});

router.delete('/webhook', requireTelegramAdmin, async (_req, res) => {
  res.json({ data: await deleteTelegramWebhook() });
});

router.post('/webhook/update', async (req, res) => {
  if (env.TELEGRAM_WEBHOOK_SECRET) {
    const secret = req.header('x-telegram-bot-api-secret-token');
    if (secret !== env.TELEGRAM_WEBHOOK_SECRET) return res.status(403).json({ error: 'INVALID_TELEGRAM_SECRET' });
  }
  res.json({ data: await handleTelegramUpdate(req.body) });
});

export default router;
