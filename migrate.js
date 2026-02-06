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

function isTransientDbError(e) {
  const code = e && e.code ? String(e.code) : '';
  // 57P03: the database system is starting up
  // ECONNRESET: connection reset by peer (often during startup / failover)
  return code === '57P03' || code === 'ECONNRESET';
}

async function withRetry(fn, { attempts, baseDelayMs }) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      if (!isTransientDbError(e) || i === attempts - 1) {
        throw e;
      }
      const delay = baseDelayMs * Math.pow(2, i);
      console.warn(`[migrate] transient db error (${e.code || e.message}); retrying in ${delay}ms`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

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
  const client = await withRetry(() => pool.connect(), { attempts: 6, baseDelayMs: 500 });
  try {
    await withRetry(() => ensureMigrationsTable(client), { attempts: 6, baseDelayMs: 500 });

    const migrationsDir = path.join(__dirname, 'migrations');
    const files = (await fs.readdir(migrationsDir))
      .filter((f) => f.endsWith('.sql'))
      .sort();

    const applied = await withRetry(() => getAppliedMigrations(client), { attempts: 6, baseDelayMs: 500 });

    for (const file of files) {
      const id = file;
      if (applied.has(id)) {
        continue;
      }
      const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
      await withRetry(() => applyMigration(client, id, sql), { attempts: 6, baseDelayMs: 500 });
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
