import pg from 'pg';
import type { QueryResultRow } from 'pg';
import { env } from '../config/env.js';

function shouldUseSsl() {
  if (env.DATABASE_SSL) return ['1', 'true', 'require'].includes(env.DATABASE_SSL.toLowerCase());
  return /sslmode=require|neon\.tech|supabase\.co/i.test(env.DATABASE_URL);
}

export const pool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  ssl: shouldUseSsl() ? { rejectUnauthorized: false } : undefined
});

pool.on('error', (error) => {
  console.error('[db] idle client error', error);
});

export async function query<T extends QueryResultRow = QueryResultRow>(text: string, params: unknown[] = []) {
  const started = Date.now();
  const result = await pool.query<T>(text, params);
  const elapsed = Date.now() - started;
  if (elapsed > 750) {
    console.warn('[db] slow query', { elapsed, text: text.slice(0, 120) });
  }
  return result;
}

export async function checkDatabase() {
  const started = Date.now();
  try {
    const result = await pool.query<{ ok: number; now: string }>('select 1 as ok, now()::text as now');
    return {
      ok: result.rows[0]?.ok === 1,
      latencyMs: Date.now() - started,
      serverTime: result.rows[0]?.now
    };
  } catch (error) {
    console.error('[db] health check failed', error);
    return {
      ok: false,
      latencyMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}
