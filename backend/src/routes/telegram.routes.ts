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
import { syncTelegramBotData } from '../services/telegram-sync.js';
import { query } from '../db/pool.js';

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

router.get('/schema-status', publicStatusLimiter, asyncRoute(async (_req, res) => {
  const result = await query<{
    organizations: boolean;
    letters: boolean;
    notification_logs: boolean;
    bot_settings: boolean;
  }>(
    `select
       to_regclass('public.organizations') is not null as organizations,
       to_regclass('public.letters') is not null as letters,
       to_regclass('public.notification_logs') is not null as notification_logs,
       to_regclass('public.bot_settings') is not null as bot_settings`
  );
  const tables = result.rows[0];
  res.json({ data: { ready: Boolean(tables && Object.values(tables).every(Boolean)), tables } });
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

router.post('/sync', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const organizationSchema = z.object({
    externalId: z.string().optional(),
    name: z.string().min(1),
    address: z.string().optional()
  });
  const employeeSchema = z.object({
    externalId: z.string().optional(),
    organizationExternalId: z.string().optional(),
    organizationName: z.string().optional(),
    fullName: z.string().min(1),
    phone: z.string().optional(),
    position: z.string().optional(),
    department: z.string().optional(),
    active: z.boolean().optional()
  });
  const letterSchema = z.object({
    externalId: z.string().min(1),
    organizationExternalId: z.string().optional(),
    organizationName: z.string().optional(),
    employeeExternalId: z.string().optional(),
    executorName: z.string().optional(),
    letterNumber: z.string().optional(),
    subject: z.string().min(1),
    body: z.string().optional(),
    deadline: z.string().optional(),
    status: z.enum(['NEW', 'IN_PROGRESS', 'DONE', 'OVERDUE', 'CANCELLED']).optional(),
    urgency: z.enum(['LOW', 'NORMAL', 'IMPORTANT', 'URGENT', 'CRITICAL']).optional(),
    sourceOrganization: z.string().optional()
  });
  const input = z.object({
    organizations: z.array(organizationSchema).max(500).optional(),
    employees: z.array(employeeSchema).max(1000).optional(),
    letters: z.array(letterSchema).max(2000).optional(),
    flushNotifications: z.boolean().default(true)
  }).parse(req.body ?? {});

  const synced = await syncTelegramBotData(input);
  const notificationResult = input.flushNotifications && synced.queuedNotifications
    ? await flushPendingTelegramNotifications(Math.min(200, synced.queuedNotifications))
    : { queued: synced.queuedNotifications, sent: 0 };
  res.json({ data: { ...synced, notifications: notificationResult } });
}));

router.get('/letters/statuses', adminLimiter, requireTelegramAdmin, asyncRoute(async (req, res) => {
  const updatedAfter = typeof req.query.updatedAfter === 'string' ? req.query.updatedAfter : null;
  const result = await query(
    `select external_id, status, updated_at
     from letters
     where external_id is not null
       and ($1::timestamptz is null or updated_at > $1::timestamptz)
     order by updated_at desc
     limit 2000`,
    [updatedAfter]
  );
  res.json({ data: result.rows });
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
