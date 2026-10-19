// Minimal D1Database shim on node:sqlite for fast unit tests. Applies migrations/*.sql in order.
// Supports prepare().bind().first/all/run/raw and db.batch() (atomic) and db.exec().
import { DatabaseSync } from 'node:sqlite';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

class Stmt {
  constructor(private db: DatabaseSync, private sql: string, private params: unknown[] = []) {}
  bind(...params: unknown[]) { return new Stmt(this.db, this.sql, params.map(p => (p === undefined ? null : typeof p === 'boolean' ? Number(p) : p))); }
  private s() { return this.db.prepare(this.sql); }
  async first<T = any>(col?: string): Promise<T | null> { const r = this.s().get(...(this.params as any[])) as any; if (!r) return null; return (col ? r[col] : { ...r }) as T; }
  async all<T = any>() { const rows = this.s().all(...(this.params as any[])).map(r => ({ ...(r as any) })); return { results: rows as T[], success: true, meta: {} }; }
  async raw<T = any[]>() { return this.s().all(...(this.params as any[])).map(r => Object.values(r as any)) as T[]; }
  async run() { const r = this.s().run(...(this.params as any[])); return { success: true, results: [], meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } }; }
  runSync() { const r = this.s().run(...(this.params as any[])); return { success: true, results: [], meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } }; }
}

/** `upTo`: apply migrations up to and including this file name (e.g. '0001_auth.sql' for the core alone). */
export function createTestDb(o: { upTo?: string } = {}): D1Database {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON;');
  const dir = join(process.cwd(), 'migrations');
  for (const f of readdirSync(dir).filter(f => f.endsWith('.sql')).sort()) {
    if (o.upTo && f > o.upTo) break;
    db.exec(readFileSync(join(dir, f), 'utf8'));
  }
  const api = {
    prepare: (sql: string) => new Stmt(db, sql),
    async batch(stmts: Stmt[]) {
      db.exec('BEGIN');
      try { const out = stmts.map(s => (s as any).runSync()); db.exec('COMMIT'); return out; }
      catch (e) { db.exec('ROLLBACK'); throw e; }
    },
    async exec(sql: string) { db.exec(sql); return { count: 0, duration: 0 }; },
    dump: async () => { throw new Error('not supported'); },
    withSession: () => api,
  };
  return api as unknown as D1Database;
}
