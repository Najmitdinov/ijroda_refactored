import { Router } from 'express';
import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { env } from '../config/env.js';
import {
  deleteTelegramWebhook,
  getTelegramPublicStatus,
  getTelegramWebhookSecret,
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
const publicStatusLimiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false });

function asyncRoute(handler: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

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
  const expectedSecret = getTelegramWebhookSecret();
  if (!expectedSecret) {
    if (env.NODE_ENV === 'production') return res.status(503).json({ error: 'TELEGRAM_WEBHOOK_SECRET_NOT_CONFIGURED' });
    return next();
  }
  const secret = req.header('x-telegram-bot-api-secret-token');
  if (secret !== expectedSecret) {
    console.warn('[telegram] invalid webhook secret', { ip: req.ip });
    return res.status(403).json({ error: 'INVALID_TELEGRAM_SECRET' });
  }
  return next();
}

router.get('/public-status', publicStatusLimiter, asyncRoute(async (_req, res) => {
  res.json({ data: await getTelegramPublicStatus() });
}));

router.get('/status', adminLimiter, requireTelegramAdmin, asyncRoute(async (_req, res) => {
  res.json({ data: await getTelegramStatus() });
}));

router.post('/test', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const input = z.object({
    chatId: z.string().optional(),
    text: z.string().optional(),
    message: z.string().optional(),
    photoUrl: z.string().url().optional()
  }).parse(req.body);
  const chatId = input.chatId || env.TELEGRAM_TEST_CHAT_ID;
  if (!chatId) return res.status(400).json({ error: 'TELEGRAM_CHAT_ID_REQUIRED' });
  const message = input.message || input.text || 'Ijro AI\nTelegram bot backend orqali muvaffaqiyatli ulandi.';
  const safeMessage = escapeHtml(message);
  const result = input.photoUrl
    ? await sendTelegramPhoto(chatId, input.photoUrl, safeMessage)
    : await sendTelegramMessage(chatId, safeMessage);
  res.json({ data: result });
}));

router.post('/digest', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const input = z.object({ chatId: z.string().optional() }).parse(req.body ?? {});
  res.json({ data: await sendTelegramDailyDigest(input.chatId) });
}));

router.post('/notifications/flush', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const input = z.object({ limit: z.coerce.number().min(1).max(200).optional() }).parse(req.body ?? {});
  res.json({ data: await flushPendingTelegramNotifications(input.limit ?? 50) });
}));

router.post('/webhook', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const input = z.object({ url: z.string().url().optional() }).parse(req.body ?? {});
  const webhookUrl = getTelegramWebhookUrl(input.url);
  const result = await setTelegramWebhook(webhookUrl);
  res.json({ data: { result, webhookUrl } });
}));

router.post('/webhook/setup', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const input = z.object({ url: z.string().url().optional() }).parse(req.body ?? {});
  const webhookUrl = getTelegramWebhookUrl(input.url);
  const result = await setTelegramWebhook(webhookUrl);
  const validation = await validateTelegramWebhook(webhookUrl);
  res.json({ data: { result, validation, webhookUrl } });
}));

router.get('/webhook/validate', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const url = typeof req.query.url === 'string' ? req.query.url : undefined;
  res.json({ data: await validateTelegramWebhook(url) });
}));

router.delete('/webhook', adminLimiter, requireTelegramAdmin, asyncRoute(async (_req, res) => {
  res.json({ data: await deleteTelegramWebhook() });
}));

router.post('/webhook/update', webhookLimiter, validateTelegramWebhookSecret, (req, res) => {
  const updateId = typeof req.body?.update_id === 'number' ? req.body.update_id : undefined;
  console.log('[telegram] webhook update', {
    updateId,
    hasMessage: Boolean(req.body?.message),
    hasCallback: Boolean(req.body?.callback_query)
  });
  res.status(200).json({ ok: true, accepted: true, updateId });
  void handleTelegramUpdate(req.body).catch((error) => {
    console.error('[telegram] webhook processing failed', {
      updateId,
      error: error instanceof Error ? error.message : String(error)
    });
  });
});

function escapeHtml(input: string) {
  return input.replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[char] || char));
}

export default router;
