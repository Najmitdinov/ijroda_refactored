# Telegram + Railway production setup

## Railway environment variables

Set these variables in the Railway backend service:

```env
NODE_ENV=production
DATABASE_URL=
JWT_SECRET=
JWT_REFRESH_SECRET=
TELEGRAM_BOT_TOKEN=
TELEGRAM_WEBHOOK_SECRET=
TELEGRAM_ADMIN_SECRET=
TELEGRAM_TEST_CHAT_ID=1165868975
CORS_ORIGINS=https://najmitdinov.github.io,http://127.0.0.1:5177,http://localhost:5177
PUBLIC_BACKEND_URL=https://YOUR-RAILWAY-DOMAIN
TELEGRAM_WEBHOOK_URL=https://YOUR-RAILWAY-DOMAIN/api/telegram/webhook/update
```

`JWT_SECRET`, `JWT_REFRESH_SECRET`, `TELEGRAM_WEBHOOK_SECRET`, and `TELEGRAM_ADMIN_SECRET` must be long random strings.

If `TELEGRAM_WEBHOOK_SECRET` is omitted, the backend derives a Telegram-compatible webhook secret from
`TELEGRAM_ADMIN_SECRET`. On every production start the backend validates the current Telegram webhook and
automatically restores it when it is missing, points to an old URL, or Telegram reports an error.

## Deploy

Railway uses `railway.toml`:

```sh
npm --workspace backend run build
npm --workspace backend run migrate:prod
npm --workspace backend run start
```

The backend listens on Railway's dynamic port through `process.env.PORT`.

## Database migration

Run once after `DATABASE_URL` is configured:

```sh
npm --workspace backend run build
npm --workspace backend run migrate:prod
```

The initial migration is idempotent and can be run again safely.

## Webhook setup

From the frontend Integrations page, fill:

- Backend API URL: `https://YOUR-RAILWAY-DOMAIN`
- Admin secret: `TELEGRAM_ADMIN_SECRET`
- Test chat ID: `1165868975`
- Webhook URL: `https://YOUR-RAILWAY-DOMAIN/api/telegram/webhook/update`

Then click `Connect Telegram` or `Setup Webhook`.

Equivalent curl:

```sh
curl -X POST "https://YOUR-RAILWAY-DOMAIN/api/telegram/webhook/setup" \
  -H "content-type: application/json" \
  -H "x-telegram-admin-secret: $TELEGRAM_ADMIN_SECRET" \
  -d '{"url":"https://YOUR-RAILWAY-DOMAIN/api/telegram/webhook/update"}'
```

## Test message

```sh
curl -X POST "https://YOUR-RAILWAY-DOMAIN/api/telegram/test" \
  -H "content-type: application/json" \
  -H "x-telegram-admin-secret: $TELEGRAM_ADMIN_SECRET" \
  -d '{"chatId":"1165868975","message":"Test notification"}'
```

## Status checks

```sh
curl "https://YOUR-RAILWAY-DOMAIN/health"
curl "https://YOUR-RAILWAY-DOMAIN/api/telegram/status" \
  -H "x-telegram-admin-secret: $TELEGRAM_ADMIN_SECRET"
```

The status response reports bot info, webhook URL, webhook activity, database health, linked Telegram employees, sessions, pending notifications, and queue errors.

The read-only endpoint below does not require the admin secret and is used by the frontend status cards:

```sh
curl "https://YOUR-RAILWAY-DOMAIN/api/telegram/public-status"
```
