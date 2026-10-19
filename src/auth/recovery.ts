// Account recovery for someone who lost every passkey: a one-time link (15 minutes, single use). Finishing it
// registers ONE new passkey and removes everything else that could still sign in or change the account: all other
// passkeys, all sessions (access_version advances), linked Google/Apple accounts, pending flows and the user's
// other recovery links.
//
// The kit has no admin or mail: your code decides who may get a link and how it reaches them, then calls
// auth.issueRecoveryLink(env, userId) and sends the URL (e.g. after a support check, or by mail to a verified address).
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
import type { AuthConfig } from './config';
import { randomToken, sha256Hex, uuid } from './crypto';
import { createFlow, takeFlow } from './flows';
import { passkeyInsertStmt, registrationOptions, verifyRegistration } from './passkeys';
import { hitRateLimit } from './rate-limit';
import { auditStmts, blockedFail, fail, getUser, isBlocked, type Result, type UserRow } from './users';
import type { AuthBindings } from './types';

type Env = Pick<AuthBindings, 'DB' | 'APP_ORIGIN' | 'PASSKEY_RP_ID'>;

export const RECOVERY_TTL = 15 * 60_000;
/** Recovery ceremonies one link may start per rate-limit window (the route also limits per IP). */
export const RECOVERY_STARTS_PER_TOKEN = 10;
export const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export const MSG = {
  invalid: 'This recovery link is incorrect, has already been used or has expired. Ask for a new link.',
  expired: 'Recovery took too long. Open the recovery link again.',
  busy: 'Too many attempts with this recovery link. Wait a few minutes and try again.',
  notAllowed: 'This account doesn’t exist or is suspended.',
};

/**
 * Issue a recovery link for `userId` (replacing their earlier unused links). Returns the URL to send. Only call it
 * after you have verified that the person asking really owns the account: the link takes over the account.
 */
export async function issueRecoveryLink(env: Env, cfg: Pick<AuthConfig, 'audit' | 'path'>, userId: string, o: { ttlMs?: number; actorId?: string | null } = {}, at = Date.now()):
  Promise<Result<{ id: string; url: string; expiresAt: number }>> {
  const user = await getUser(env.DB, userId);
  if (!user || isBlocked(user.status)) return fail(409, 'recovery_not_allowed', MSG.notAllowed);
  const token = randomToken(32);
  const id = uuid();
  const expiresAt = at + (o.ttlMs ?? RECOVERY_TTL);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM recovery_tokens WHERE user_id = ? AND used_at IS NULL').bind(userId),
    env.DB.prepare('INSERT INTO recovery_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, userId, await sha256Hex(token), expiresAt, at),
    ...auditStmts(env.DB, cfg, { actorId: o.actorId ?? null, action: 'recovery-issued', targetUserId: userId }, at),
  ]);
  return { ok: true, id, url: `${env.APP_ORIGIN}${cfg.path(`/auth/recover/${token}`)}`, expiresAt };
}

interface TokenRow { id: string; user_id: string; expires_at: number; used_at: number | null }
interface RecoveryFlow { challenge: string; tokenId: string }

export async function inspectRecovery(db: D1Database, token: unknown, at = Date.now()): Promise<{ ok: true; tokenId: string; user: UserRow } | { ok: false; message: string }> {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return { ok: false, message: MSG.invalid };
  const t = await db.prepare('SELECT id, user_id, expires_at, used_at FROM recovery_tokens WHERE token_hash = ?').bind(await sha256Hex(token)).first<TokenRow>();
  if (!t || t.used_at != null || t.expires_at <= at) return { ok: false, message: MSG.invalid };
  const user = await getUser(db, t.user_id);
  if (!user || isBlocked(user.status)) return { ok: false, message: MSG.invalid };
  return { ok: true, tokenId: t.id, user };
}

export async function startRecovery(env: Env, cfg: Pick<AuthConfig, 'appName' | 'flowStartWindowMs'>, token: unknown, at = Date.now()): Promise<Result<{ flowId: string; options: PublicKeyCredentialCreationOptionsJSON }>> {
  const r = await inspectRecovery(env.DB, token, at);
  if (!r.ok) return fail(400, 'recovery_invalid', r.message);
  const limit = await hitRateLimit(env.DB, `recovery:token:${r.tokenId}`, RECOVERY_STARTS_PER_TOKEN, cfg.flowStartWindowMs, at);
  if (!limit.allowed) return fail(429, 'rate_limited', MSG.busy);
  // No excludeCredentials: the old passkeys are about to be removed, re-registering on the same device is fine.
  const options = await registrationOptions(env, cfg, { userId: r.user.id, username: r.user.username, name: r.user.name });
  const flowId = await createFlow<RecoveryFlow>(env.DB, 'recovery', { challenge: options.challenge, tokenId: r.tokenId }, { userId: r.user.id, at });
  return { ok: true, flowId, options };
}

export async function finishRecovery(env: Env, cfg: Pick<AuthConfig, 'audit'>, flowId: unknown, response: unknown, at = Date.now()): Promise<Result<{ user: UserRow; tokenId: string }>> {
  const db = env.DB;
  const flow = await takeFlow<RecoveryFlow>(db, flowId, 'recovery', at);
  if (!flow || !flow.userId) return fail(400, 'flow_expired', MSG.expired);
  const userId = flow.userId;
  const v = await verifyRegistration(env, response, flow.data.challenge);
  if (!v.ok) return v;
  // Every write is conditional on THIS flow having consumed the token: used_by_flow holds the (single-use, random)
  // flow id. A timestamp would not prove it: two flows can finish in the same millisecond.
  const consumed = { sql: 'EXISTS (SELECT 1 FROM recovery_tokens WHERE id = ? AND used_by_flow = ?)', params: [flow.data.tokenId, flow.id] };
  let res: D1Result[];
  try {
    res = await db.batch([
      db.prepare(`UPDATE recovery_tokens SET used_at = ?1, used_by_flow = ?4 WHERE id = ?2 AND user_id = ?3 AND used_at IS NULL AND expires_at > ?1
          AND EXISTS (SELECT 1 FROM users WHERE id = ?3 AND status = 'active')`).bind(at, flow.data.tokenId, userId, flow.id),
      db.prepare(`DELETE FROM passkeys WHERE user_id = ? AND ${consumed.sql}`).bind(userId, ...consumed.params),
      passkeyInsertStmt(db, userId, v.passkey, at, consumed),
      db.prepare(`UPDATE users SET access_version = access_version + 1, updated_at = ? WHERE id = ? AND ${consumed.sql}`).bind(at, userId, ...consumed.params),
      db.prepare(`DELETE FROM sessions WHERE user_id = ? AND ${consumed.sql}`).bind(userId, ...consumed.params),
      // Whoever had access before may have linked their own Google/Apple account or started a flow: none of it survives.
      db.prepare(`DELETE FROM oauth_identities WHERE user_id = ? AND ${consumed.sql}`).bind(userId, ...consumed.params),
      db.prepare(`DELETE FROM auth_flows WHERE user_id = ? AND ${consumed.sql}`).bind(userId, ...consumed.params),
      // Other outstanding links for this account; this one stays (marked used) so the guard above keeps holding.
      db.prepare(`DELETE FROM recovery_tokens WHERE user_id = ? AND id <> ? AND ${consumed.sql}`).bind(userId, flow.data.tokenId, ...consumed.params),
      ...auditStmts(db, cfg, { actorId: userId, action: 'recovery-completed', targetUserId: userId }, at, consumed.sql, consumed.params),
    ]);
  } catch (e) {
    // The new passkey already belongs to another account: nothing was written (the batch rolled back).
    if (String(e).includes('UNIQUE')) return fail(409, 'passkey_duplicate', 'This passkey is already linked to another account.');
    throw e;
  }
  if (res[0]?.meta.changes !== 1) {
    const u = await getUser(db, userId);
    return u && isBlocked(u.status) ? blockedFail(u.id) : fail(400, 'recovery_invalid', MSG.invalid);
  }
  return { ok: true, user: (await getUser(db, userId))!, tokenId: flow.data.tokenId };
}
