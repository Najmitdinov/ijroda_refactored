import 'dotenv/config';
import pg from 'pg';

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10
});

export async function query<T = unknown>(text: string, params: unknown[] = []) {
  return pool.query<T>(text, params);
}
