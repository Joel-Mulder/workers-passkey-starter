// User rows, the Result type the services return, and audit statements.
import type { AuthConfig } from './config';
import { uuid } from './crypto';
import type { ErrorStatus } from './http';
import type { SessionUser, UserStatus } from './types';

export interface UserRow {
  id: string;
  username: string;
  name: string;
  status: UserStatus;
  access_version: number;
  created_at: number;
  updated_at: number;
}

export const isBlocked = (status: string) => status !== 'active';

export const toSessionUser = (u: UserRow): SessionUser => ({ id: u.id, username: u.username, name: u.name, status: u.status });

export async function getUser(db: D1Database, id: string): Promise<UserRow | null> {
  return db.prepare('SELECT id, username, name, status, access_version, created_at, updated_at FROM users WHERE id = ?').bind(id).first<UserRow>();
}

/** Ways a user can sign in (passkeys + linked Google/Apple identities). */
export async function signInMethodCount(db: D1Database, userId: string): Promise<{ passkeys: number; identities: number }> {
  const r = await db.prepare('SELECT (SELECT COUNT(*) FROM passkeys WHERE user_id = ?1) AS passkeys, (SELECT COUNT(*) FROM oauth_identities WHERE user_id = ?1) AS identities')
    .bind(userId).first<{ passkeys: number; identities: number }>();
  return { passkeys: r?.passkeys ?? 0, identities: r?.identities ?? 0 };
}

/** Service result; routes map a Fail onto a JSON error or a page. */
/** `userId` is set on account_suspended so routes can ask the modules why (explainBlocked). */
export type Fail = { ok: false; status: ErrorStatus; code: string; message: string; userId?: string };
export type Result<T extends object = object> = ({ ok: true } & T) | Fail;
export const fail = (status: ErrorStatus, code: string, message: string): Fail => ({ ok: false, status, code, message });

export const blockedFail = (userId?: string): Fail => ({ ...fail(403, 'account_suspended', 'This account has been suspended.'), ...(userId ? { userId } : {}) });

export interface AuditEntry { actorId: string | null; action: string; targetUserId?: string | null; details?: Record<string, unknown> }

/**
 * Audit row for the same batch as the change it records, written only when the SQL `condition` holds (using the
 * bound `params`), e.g. 'changes() = 1' right after the change. Empty when auditing is off.
 */
export function auditStmts(db: D1Database, cfg: Pick<AuthConfig, 'audit'>, e: AuditEntry, at = Date.now(), condition?: string, params: unknown[] = []): D1PreparedStatement[] {
  if (!cfg.audit) return [];
  const values = [uuid(), e.actorId, e.action, e.targetUserId ?? null, e.details ? JSON.stringify(e.details) : null, at];
  return [condition
    ? db.prepare(`INSERT INTO audit_log (id, actor_id, action, target_user_id, details, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE ${condition}`).bind(...values, ...params)
    : db.prepare('INSERT INTO audit_log (id, actor_id, action, target_user_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)').bind(...values)];
}
