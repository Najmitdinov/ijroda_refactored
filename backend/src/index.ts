import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { env, corsOrigins } from './config/env.js';
import { errorHandler } from './middleware/error.js';
import authRoutes from './routes/auth.routes.js';
import employeeRoutes from './routes/employee.routes.js';
import documentRoutes from './routes/document.routes.js';
import taskRoutes from './routes/task.routes.js';
import analyticsRoutes from './routes/analytics.routes.js';
import aiRoutes from './routes/ai.routes.js';
import telegramRoutes from './routes/telegram.routes.js';
import { ensureTelegramWebhook, sendScheduledTelegramDigests } from './services/telegram-service.js';

const app = express();

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    const normalized = origin.replace(/\/+$/, '');
    if (corsOrigins.includes(normalized)) return callback(null, true);
    return callback(new Error(`CORS_NOT_ALLOWED:${origin}`));
  },
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 180, standardHeaders: true, legacyHeaders: false }));

app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - started;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'log';
    console[level]('[http]', {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      ms,
      ip: req.ip
    });
  });
  next();
});

app.get('/health', (_req, res) => res.json({ ok: true, service: 'ijro-ai-backend' }));
app.use('/api/auth', authRoutes);
app.use('/api/employees', employeeRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/telegram', telegramRoutes);
app.use(errorHandler);

app.listen(env.API_PORT, () => {
  console.log(`[api] listening on :${env.API_PORT}`);
  void ensureTelegramWebhook()
    .then((result) => console.log('[telegram] startup webhook check', result))
    .catch((error) => console.error('[telegram] startup webhook setup failed', error));
  const runTelegramSchedule = () => {
    void sendScheduledTelegramDigests()
      .then((result) => {
        if (result.due) console.log('[telegram] scheduled digest', result);
      })
      .catch((error) => console.error('[telegram] scheduled digest failed', error));
  };
  setTimeout(runTelegramSchedule, 15_000);
  setInterval(runTelegramSchedule, 60_000).unref();
});
