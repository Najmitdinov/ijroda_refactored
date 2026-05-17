# Enterprise AI Ijro Platform

This repository now contains a production-oriented monorepo scaffold for an
AI-powered edu.ijro monitoring platform.

## Modules

- `frontend/` — React, Vite, TailwindCSS, Shadcn-style primitives, Framer Motion dashboard.
- `backend/` — Node.js, Express, JWT/RBAC, parser, AI analyzer, tasks, employees, analytics.
- `bot/` — Telegraf.js Telegram bot with registration, daily digest and task actions.
- `ai/` — shared AI JSON schemas.
- `database/` — PostgreSQL schema and indexes.
- `storage/` — file storage layout and security notes.
- `utils/` — cross-runtime TypeScript contracts.

## Security Model

- AI keys are backend-only.
- Frontend talks only to `/api/*`.
- JWT access tokens are short-lived.
- Role permissions are enforced by backend middleware.
- Audit logs are written for sensitive actions.
- Notifications are queued in PostgreSQL and can be moved to BullMQ workers.

## AI Provider Order

1. OpenRouter
2. Gemini
3. DeepSeek
4. OpenAI fallback

Every AI response must be strict JSON and validated against schemas before use.

## Telegram Flow

1. User sends `/start`.
2. Bot asks for `employee_id`.
3. Employee record is linked with `telegram_id`.
4. `/tasks` returns active tasks with inline buttons.
5. Daily digest is sent at 08:00 Asia/Tashkent.

## Database

Run `database/migrations/001_initial_schema.sql` against PostgreSQL before starting
backend and bot.

## Next Production Steps

- Add OCR extraction workers for PDF/image/screenshot files.
- Move notification dispatch to BullMQ with Redis.
- Add Firebase Admin realtime sync for dashboard counters.
- Add Vercel/Firebase Hosting deployment workflows.
- Add e2e tests for auth, upload, employee matching and Telegram actions.
