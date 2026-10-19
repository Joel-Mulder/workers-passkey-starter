// Self-service on a signed-in account: linked Google/Apple identities, sign out everywhere, the account summary.
import type { AuthConfig } from './config';
import { listPasskeys, type PasskeyView } from './passkeys';
import { changeAndRotateStmts, rotateAccessStmts } from './session';
import { auditStmts, fail, getUser, type Result } from './users';
import type { Provider, SessionUser } from './types';

export const MSG = {
  lastMethod: 'You can’t remove your last way to sign in. Add a passkey first.',
  notFound: 'This link doesn’t exist (any more).',
};

export interface IdentityView { id: string; provider: Provider; email: string | null; createdAt: number; lastUsedAt: number | null }

export interface AccountView { user: SessionUser; passkeys: PasskeyView[]; identities: IdentityView[] }

export async function listIdentities(db: D1Database, userId: string): Promise<IdentityView[]> {
  const rows = (await db.prepare('SELECT id, provider, email, created_at, last_used_at FROM oauth_identities WHERE user_id = ? ORDER BY created_at').bind(userId)
    .all<{ id: string; provider: Provider; email: string | null; created_at: number; last_used_at: number | null }>()).results;
  return rows.map(r => ({ id: r.id, provider: r.provider, email: r.email, createdAt: r.created_at, lastUsedAt: r.last_used_at }));
}

export async function accountView(db: D1Database, userId: string): Promise<AccountView | null> {
  const u = await getUser(db, userId);
  if (!u) return null;
  return { user: { id: u.id, username: u.username, name: u.name, status: u.status }, passkeys: await listPasskeys(db, userId), identities: await listIdentities(db, userId) };
}

/**
 * Unlink Google/Apple, never the last way to sign in. In the same batch access_version advances: other sessions end,
 * this device (`keepSessionId`) moves to the new version.
 */
export async function unlinkIdentity(db: D1Database, cfg: Pick<AuthConfig, 'audit'>, userId: string, identityId: string, at = Date.now(), keepSessionId: string | null = null): Promise<Result> {
  const res = await db.batch(changeAndRotateStmts(db,
    db.prepare(`DELETE FROM oauth_identities WHERE id = ?1 AND user_id = ?2
      AND (SELECT COUNT(*) FROM passkeys WHERE user_id = ?2) + (SELECT COUNT(*) FROM oauth_identities WHERE user_id = ?2) > 1`).bind(identityId, userId),
    auditStmts(db, cfg, { actorId: userId, action: 'identity-unlinked', targetUserId: userId, details: { identityId } }, at, 'changes() = 1'),
    userId, keepSessionId, at));
  if (res[0]?.meta.changes === 1) return { ok: true };
  const exists = await db.prepare('SELECT 1 FROM oauth_identities WHERE id = ? AND user_id = ?').bind(identityId, userId).first();
  return exists ? fail(409, 'last_sign_in_method', MSG.lastMethod) : fail(404, 'not_found', MSG.notFound);
}

/** Sign out on every other device (the route requires fresh auth); this device stays signed in. Returns how many ended. */
export async function signOutOtherSessions(db: D1Database, cfg: Pick<AuthConfig, 'audit'>, userId: string, keepSessionId: string, at = Date.now()): Promise<{ revoked: number }> {
  const res = await db.batch([
    ...rotateAccessStmts(db, userId, keepSessionId, at),
    ...auditStmts(db, cfg, { actorId: userId, action: 'sessions-revoked', targetUserId: userId }, at),
  ]);
  return { revoked: res[2]?.meta.changes ?? 0 };
}

/** Housekeeping for a cron trigger: expired sessions, flows and rate counters. */
export async function cleanupExpired(db: D1Database, at = Date.now()): Promise<void> {
  await db.batch([
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(at),
    db.prepare('DELETE FROM auth_flows WHERE expires_at <= ?').bind(at),
    db.prepare('DELETE FROM rate_counters WHERE expires_at <= ?').bind(at),
  ]);
}
