import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL env var');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSLMODE === 'disable' ? false : undefined });

async function ensureMigrationsTable(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function getAppliedMigrations(client) {
  const res = await client.query('SELECT id FROM schema_migrations ORDER BY id ASC');
  return new Set(res.rows.map((r) => r.id));
}

async function applyMigration(client, id, sql) {
  await client.query('BEGIN');
  try {
    await client.query(sql);
    await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [id]);
    await client.query('COMMIT');
    console.log(`[migrate] applied ${id}`);
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function main() {
  const client = await pool.connect();
  try {
    await ensureMigrationsTable(client);

    const migrationsDir = path.join(__dirname, 'migrations');
    const files = (await fs.readdir(migrationsDir))
      .filter((f) => f.endsWith('.sql'))
      .sort();

    const applied = await getAppliedMigrations(client);

    for (const file of files) {
      const id = file;
      if (applied.has(id)) {
        continue;
      }
      const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
      await applyMigration(client, id, sql);
    }

    console.log('[migrate] done');
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((e) => {
  console.error('[migrate] failed', e);
  process.exit(1);
});
