// Short-lived ceremony state in `auth_flows`: WebAuthn challenges, OAuth state/PKCE/nonce, signup drafts.
// Workers keep no memory between requests, so every step is stored in D1; flows are single use and expire.
import { randomToken } from './crypto';

export type FlowKind = 'passkey-register' | 'passkey-login' | 'reauth' | 'signup' | 'oauth' | 'oauth-resume' | 'recovery';
export const FLOW_TTL = 10 * 60_000;
const ID_RE = /^[A-Za-z0-9_-]{16,128}$/;

export interface Flow<T> { id: string; kind: FlowKind; data: T; userId: string | null; expiresAt: number; createdAt: number }

export async function createFlow<T>(db: D1Database, kind: FlowKind, data: T, opts: { userId?: string | null; ttlMs?: number; id?: string; at?: number } = {}): Promise<string> {
  const id = opts.id ?? randomToken(24);
  const at = opts.at ?? Date.now();
  await db.prepare('INSERT INTO auth_flows (id, kind, data, user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(id, kind, JSON.stringify(data), opts.userId ?? null, at + (opts.ttlMs ?? FLOW_TTL), at).run();
  return id;
}

type FlowRow = { id: string; kind: FlowKind; data: string; user_id: string | null; expires_at: number; created_at: number };
const toFlow = <T>(r: FlowRow): Flow<T> => ({ id: r.id, kind: r.kind, data: JSON.parse(r.data) as T, userId: r.user_id, expiresAt: r.expires_at, createdAt: r.created_at });

/** Single use: deletes and returns the flow if it exists, has this kind and has not expired. */
export async function takeFlow<T>(db: D1Database, id: unknown, kind: FlowKind, at = Date.now()): Promise<Flow<T> | null> {
  if (typeof id !== 'string' || !ID_RE.test(id)) return null;
  const r = await db.prepare('DELETE FROM auth_flows WHERE id = ? AND kind = ? RETURNING *').bind(id, kind).first<FlowRow>();
  if (!r || r.expires_at <= at) return null;
  return toFlow<T>(r);
}

/** Read without consuming: for retry-safe steps (finishing a signup is idempotent per flow). */
export async function peekFlow<T>(db: D1Database, id: unknown, kind: FlowKind, at = Date.now()): Promise<Flow<T> | null> {
  if (typeof id !== 'string' || !ID_RE.test(id)) return null;
  const r = await db.prepare('SELECT * FROM auth_flows WHERE id = ? AND kind = ? AND expires_at > ?').bind(id, kind, at).first<FlowRow>();
  return r ? toFlow<T>(r) : null;
}
