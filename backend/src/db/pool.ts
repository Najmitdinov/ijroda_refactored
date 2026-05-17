import pg from 'pg';
import { env } from '../config/env.js';

export const pool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

export async function query<T = unknown>(text: string, params: unknown[] = []) {
  const started = Date.now();
  const result = await pool.query<T>(text, params);
  const elapsed = Date.now() - started;
  if (elapsed > 750) {
    console.warn('[db] slow query', { elapsed, text: text.slice(0, 120) });
  }
  return result;
}
