import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pool } from './pool.js';

const migrations = [
  resolve(process.cwd(), '..', 'database', 'migrations', '001_initial_schema.sql')
];

for (const file of migrations) {
  console.log('[db:migrate] running', file);
  const sql = await readFile(file, 'utf8');
  await pool.query(sql);
  console.log('[db:migrate] done', file);
}

await pool.end();
