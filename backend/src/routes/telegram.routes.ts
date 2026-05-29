import { Router } from 'express';
import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { env } from '../config/env.js';
import {
  deleteTelegramWebhook,
  flushPendingTelegramNotifications,
  getTelegramWebhookUrl,
  getTelegramStatus,
  sendTelegramDailyDigest,
  sendTelegramMessage,
  sendTelegramPhoto,
  setTelegramWebhook,
  validateTelegramWebhook
} from '../services/telegram-service.js';
import { handleTelegramUpdate } from '../services/telegram-update-handler.js';

const router = Router();
const adminLimiter = rateLimit({ windowMs: 60_000, limit: 40, standardHeaders: true, legacyHeaders: false });
const webhookLimiter = rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: true, legacyHeaders: false });

function requireTelegramAdmin(req: Request, res: Response, next: NextFunction) {
  const secret = req.header('x-telegram-admin-secret');
  if (env.TELEGRAM_ADMIN_SECRET && secret === env.TELEGRAM_ADMIN_SECRET) return next();

  const token = req.header('authorization')?.replace(/^Bearer\s+/i, '');
  if (token) {
    try {
      const user = jwt.verify(token, env.JWT_SECRET) as { role?: string };
      if (['SUPER_ADMIN', 'RAHBAR'].includes(user.role || '')) return next();
    } catch {
      return res.status(401).json({ error: 'INVALID_TOKEN' });
    }
  }

  if (env.NODE_ENV === 'production' && !env.TELEGRAM_ADMIN_SECRET) {
    return res.status(503).json({ error: 'TELEGRAM_ADMIN_SECRET_NOT_CONFIGURED' });
  }

  if (env.NODE_ENV !== 'production' && !env.TELEGRAM_ADMIN_SECRET) return next();
  return res.status(403).json({ error: 'TELEGRAM_ADMIN_FORBIDDEN' });
}

function validateTelegramWebhookSecret(req: Request, res: Response, next: NextFunction) {
  if (!env.TELEGRAM_WEBHOOK_SECRET) {
    if (env.NODE_ENV === 'production') return res.status(503).json({ error: 'TELEGRAM_WEBHOOK_SECRET_NOT_CONFIGURED' });
    return next();
  }
  const secret = req.header('x-telegram-bot-api-secret-token');
  if (secret !== env.TELEGRAM_WEBHOOK_SECRET) {
    console.warn('[telegram] invalid webhook secret', { ip: req.ip });
    return res.status(403).json({ error: 'INVALID_TELEGRAM_SECRET' });
  }
  return next();
}

router.get('/status', adminLimiter, requireTelegramAdmin, async (_req, res) => {
  res.json({ data: await getTelegramStatus() });
});

router.post('/test', adminLimiter, requireTelegramAdmin, async (req, res) => {
  const input = z.object({
    chatId: z.string().optional(),
    text: z.string().optional(),
    message: z.string().optional(),
    photoUrl: z.string().url().optional()
  }).parse(req.body);
  const chatId = input.chatId || env.TELEGRAM_TEST_CHAT_ID;
  if (!chatId) return res.status(400).json({ error: 'TELEGRAM_CHAT_ID_REQUIRED' });
  const message = input.message || input.text || '<b>Ijro AI</b>\nTelegram bot backend orqali muvaffaqiyatli ulandi.';
  const result = input.photoUrl
    ? await sendTelegramPhoto(chatId, input.photoUrl, message)
    : await sendTelegramMessage(chatId, message);
  res.json({ data: result });
});

router.post('/digest', adminLimiter, requireTelegramAdmin, async (req, res) => {
  const input = z.object({ chatId: z.string().optional() }).parse(req.body ?? {});
  res.json({ data: await sendTelegramDailyDigest(input.chatId) });
});

router.post('/notifications/flush', adminLimiter, requireTelegramAdmin, async (req, res) => {
  const input = z.object({ limit: z.coerce.number().min(1).max(200).optional() }).parse(req.body ?? {});
  res.json({ data: await flushPendingTelegramNotifications(input.limit ?? 50) });
});

router.post('/webhook', adminLimiter, requireTelegramAdmin, async (req, res) => {
  const input = z.object({ url: z.string().url().optional() }).parse(req.body ?? {});
  const webhookUrl = getTelegramWebhookUrl(input.url);
  const result = await setTelegramWebhook(webhookUrl);
  res.json({ data: { result, webhookUrl } });
});

router.post('/webhook/setup', adminLimiter, requireTelegramAdmin, async (req, res) => {
  const input = z.object({ url: z.string().url().optional() }).parse(req.body ?? {});
  const webhookUrl = getTelegramWebhookUrl(input.url);
  const result = await setTelegramWebhook(webhookUrl);
  const validation = await validateTelegramWebhook(webhookUrl);
  res.json({ data: { result, validation, webhookUrl } });
});

router.get('/webhook/validate', adminLimiter, requireTelegramAdmin, async (req, res) => {
  const url = typeof req.query.url === 'string' ? req.query.url : undefined;
  res.json({ data: await validateTelegramWebhook(url) });
});

router.delete('/webhook', adminLimiter, requireTelegramAdmin, async (_req, res) => {
  res.json({ data: await deleteTelegramWebhook() });
});

router.post('/webhook/update', webhookLimiter, validateTelegramWebhookSecret, async (req, res) => {
  const updateId = typeof req.body?.update_id === 'number' ? req.body.update_id : undefined;
  console.log('[telegram] webhook update', {
    updateId,
    hasMessage: Boolean(req.body?.message),
    hasCallback: Boolean(req.body?.callback_query)
  });
  const data = await handleTelegramUpdate(req.body);
  res.json({ ok: true, data });
});

export default router;
