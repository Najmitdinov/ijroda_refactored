import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pool } from './pool.js';

const migrationsDir = resolve(process.cwd(), '..', 'database', 'migrations');
const migrations = (await readdir(migrationsDir))
  .filter((file) => /^\d+.*\.sql$/i.test(file))
  .sort()
  .map((file) => resolve(migrationsDir, file));

for (const file of migrations) {
  console.log('[db:migrate] running', file);
  const sql = await readFile(file, 'utf8');
  await pool.query(sql);
  console.log('[db:migrate] done', file);
}

await pool.end();
