import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import dotenv from 'dotenv';
import { z } from 'zod';

for (const path of [resolve(process.cwd(), '.env'), resolve(process.cwd(), 'backend', '.env')]) {
  if (existsSync(path)) dotenv.config({ path, override: false });
}

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().optional(),
  API_PORT: z.coerce.number().optional(),
  CORS_ORIGINS: z.string().default('https://najmitdinov.github.io,http://127.0.0.1:5177,http://localhost:5177,http://127.0.0.1:8080,http://localhost:8080'),
  DATABASE_URL: z.string().min(1),
  DATABASE_SSL: z.string().optional(),
  JWT_SECRET: z.string().min(24),
  JWT_REFRESH_SECRET: z.string().min(24),
  TELEGRAM_BOT_TOKEN: z.string().optional(),
  TELEGRAM_WEBHOOK_SECRET: z.string().optional(),
  TELEGRAM_ADMIN_SECRET: z.string().optional(),
  TELEGRAM_TEST_CHAT_ID: z.string().optional(),
  TELEGRAM_WEBHOOK_URL: z.string().optional(),
  PUBLIC_BACKEND_URL: z.string().optional(),
  RAILWAY_PUBLIC_DOMAIN: z.string().optional(),
  GROQ_API_KEY: z.string().optional(),
  GROQ_MODEL: z.string().optional(),
  OPENROUTER_API_KEY: z.string().optional(),
  GEMINI_API_KEY: z.string().optional(),
  OPENAI_API_KEY: z.string().optional()
});

const parsedEnv = envSchema.parse(process.env);

export const env = {
  ...parsedEnv,
  API_PORT: Number(parsedEnv.PORT || parsedEnv.API_PORT || 3000)
};

export const corsOrigins = env.CORS_ORIGINS.split(',').map((origin) => origin.trim().replace(/\/+$/, '')).filter(Boolean);

export function getPublicBackendUrl() {
  const explicit = env.PUBLIC_BACKEND_URL || env.TELEGRAM_WEBHOOK_URL?.replace(/\/api\/telegram\/webhook\/update\/?$/, '');
  if (explicit) return explicit.replace(/\/+$/, '');
  if (env.RAILWAY_PUBLIC_DOMAIN) return `https://${env.RAILWAY_PUBLIC_DOMAIN.replace(/^https?:\/\//, '').replace(/\/+$/, '')}`;
  return '';
}
