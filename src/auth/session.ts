// Database sessions. The cookie holds a random token; D1 stores only SHA-256(token) in sessions.id.
// Sliding expiry, instant revocation through users.access_version, step-up ("fresh auth") through authenticated_at.
import type { MiddlewareHandler } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AuthConfig } from './config';
import { randomToken, sha256Hex } from './crypto';
import { jsonError } from './http';
import { isBlocked, toSessionUser, type UserRow } from './users';
import type { AuthContext, AuthEnv, AuthMethod, SessionInfo } from './types';

const MSG = {
  authRequired: 'Sign in to continue.',
  reauth: 'Confirm it’s you and try again.',
};

type JoinRow = UserRow & { s_id: string; s_access_version: number; auth_method: AuthMethod; authenticated_at: number; s_expires_at: number; s_created_at: number };

export interface Resolved { session: SessionInfo | null; invalid: boolean; renewedUntil?: number }

/** Validate a cookie token against D1. Deletes sessions that are expired, revoked or whose user is blocked. */
export async function resolveSession(db: D1Database, cfg: AuthConfig, token: string | undefined, at = Date.now()): Promise<Resolved> {
  if (!token) return { session: null, invalid: false };
  if (token.length > 128) return { session: null, invalid: true };
  const id = await sha256Hex(token);
  const row = await db.prepare(
    `SELECT s.id AS s_id, s.access_version AS s_access_version, s.auth_method, s.authenticated_at, s.expires_at AS s_expires_at, s.created_at AS s_created_at,
            u.id, u.username, u.name, u.status, u.access_version, u.created_at, u.updated_at
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`,
  ).bind(id).first<JoinRow>();
  if (!row || row.s_expires_at <= at || at - row.s_created_at >= cfg.maxSessionAgeMs || isBlocked(row.status) || row.access_version !== row.s_access_version) {
    await db.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
    return { session: null, invalid: true };
  }
  let expiresAt = row.s_expires_at;
  let renewedUntil: number | undefined;
  if (at - (expiresAt - cfg.sessionTtlMs) > cfg.renewAfterMs) {
    // Slide, but never past the absolute lifetime.
    expiresAt = renewedUntil = Math.min(at + cfg.sessionTtlMs, row.s_created_at + cfg.maxSessionAgeMs);
    await db.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').bind(expiresAt, id).run();
  }
  return { session: { id, user: toSessionUser(row), authMethod: row.auth_method, authenticatedAt: row.authenticated_at, expiresAt }, invalid: false, renewedUntil };
}

export const secureCookies = (c: AuthContext) => c.env.APP_ENV !== 'local';

/**
 * Cookie name with a browser-enforced prefix when deployed: `__Host-` for Path=/ (no Domain attribute allowed, so a
 * sibling subdomain can't plant or overwrite it), `__Secure-` otherwise. Local dev over http keeps the plain name.
 */
export const cookieName = (c: AuthContext, base: string, path: string) =>
  secureCookies(c) ? (path === '/' ? '__Host-' : '__Secure-') + base : base;
const sessionCookieName = (c: AuthContext, cfg: AuthConfig) => cookieName(c, cfg.cookies.session, cfg.cookies.path);

const sessionCookie = (c: AuthContext, cfg: AuthConfig, maxAgeMs: number) =>
  ({ httpOnly: true, sameSite: 'Lax' as const, path: cfg.cookies.path, secure: secureCookies(c), maxAge: Math.max(0, Math.floor(maxAgeMs / 1000)) });

/** Middleware: resolve the cookie into c.var.session (null when signed out), renewing or clearing the cookie. */
export function sessionMiddleware(cfg: AuthConfig): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const token = getCookie(c, sessionCookieName(c, cfg));
    const r = await resolveSession(c.env.DB, cfg, token);
    if (r.invalid) deleteCookie(c, sessionCookieName(c, cfg), { path: cfg.cookies.path, secure: secureCookies(c) });
    else if (r.renewedUntil && token) setCookie(c, sessionCookieName(c, cfg), token, sessionCookie(c, cfg, r.renewedUntil - Date.now()));
    c.set('session', r.session);
    await next();
  };
}

/** Insert a session row; returns the cookie token. */
export async function insertSession(db: D1Database, cfg: AuthConfig, user: UserRow, authMethod: AuthMethod, at = Date.now()): Promise<{ token: string; info: SessionInfo }> {
  const token = randomToken(32);
  const id = await sha256Hex(token);
  const expiresAt = at + cfg.sessionTtlMs;
  await db.prepare('INSERT INTO sessions (id, user_id, access_version, auth_method, authenticated_at, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, user.id, user.access_version, authMethod, at, at, expiresAt).run();
  return { token, info: { id, user: toSessionUser(user), authMethod, authenticatedAt: at, expiresAt } };
}

/** Sign in on this device: replaces this device's current session and sets the cookie. */
export async function createSession(c: AuthContext, cfg: AuthConfig, user: UserRow, authMethod: AuthMethod): Promise<SessionInfo> {
  const old = getCookie(c, sessionCookieName(c, cfg));
  if (old && old.length <= 128) await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(await sha256Hex(old)).run();
  const { token, info } = await insertSession(c.env.DB, cfg, user, authMethod);
  setCookie(c, sessionCookieName(c, cfg), token, sessionCookie(c, cfg, cfg.sessionTtlMs));
  c.set('session', info);
  return info;
}

/** Sign out this device only. */
export async function destroySession(c: AuthContext, cfg: AuthConfig): Promise<void> {
  const token = getCookie(c, sessionCookieName(c, cfg));
  if (token && token.length <= 128) await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(await sha256Hex(token)).run();
  deleteCookie(c, sessionCookieName(c, cfg), { path: cfg.cookies.path, secure: secureCookies(c) });
  c.set('session', null);
}

/**
 * End every session of `userId` except `keepSessionId` by advancing users.access_version. Three statements for one
 * batch: bump the version (only when `when` holds, e.g. 'changes() = 1' right after the change it belongs to), move
 * the kept session to the current version, and delete the user's sessions whose version is now stale. Without a bump
 * nothing is stale, so the last two change nothing.
 */
export function rotateAccessStmts(db: D1Database, userId: string, keepSessionId: string | null | undefined, at: number, when?: string): D1PreparedStatement[] {
  return [
    db.prepare(`UPDATE users SET access_version = access_version + 1, updated_at = ? WHERE id = ?${when ? ` AND ${when}` : ''}`).bind(at, userId),
    db.prepare('UPDATE sessions SET access_version = (SELECT access_version FROM users WHERE id = ?1) WHERE id = ?2 AND user_id = ?1').bind(userId, keepSessionId ?? ''),
    db.prepare('DELETE FROM sessions WHERE user_id = ?1 AND id IS NOT ?2 AND access_version != (SELECT access_version FROM users WHERE id = ?1)').bind(userId, keepSessionId ?? null),
  ];
}

/**
 * A change that removes a way into the account, then rotateAccessStmts, in one batch. The audit row and the bump
 * both require 'changes() = 1': the audit row follows the change directly, and the bump follows the audit row (which
 * was only written when the change happened) or, with auditing off, the change itself. Index 0 is the change.
 */
export function changeAndRotateStmts(db: D1Database, change: D1PreparedStatement, audit: D1PreparedStatement[], userId: string, keepSessionId: string | null, at: number): D1PreparedStatement[] {
  return [change, ...audit, ...rotateAccessStmts(db, userId, keepSessionId, at, 'changes() = 1')];
}

/** Sign a user out everywhere, this device included (e.g. after you suspend them). */
export async function revokeAllSessions(db: D1Database, userId: string, at = Date.now()): Promise<void> {
  await db.batch(rotateAccessStmts(db, userId, null, at));
}

/** Record a fresh passkey/provider confirmation for this session (step-up). */
export async function markFreshAuth(db: D1Database, sessionId: string, at = Date.now()): Promise<void> {
  await db.prepare('UPDATE sessions SET authenticated_at = ? WHERE id = ?').bind(at, sessionId).run();
}

export const isFresh = (s: SessionInfo | null | undefined, maxAgeMs: number, at = Date.now()) => !!s && at - s.authenticatedAt <= maxAgeMs;

// ───────────── Guards ─────────────

export function wantsJson(c: AuthContext): boolean {
  if (new URL(c.req.url).pathname.includes('/api/')) return true;
  const accept = c.req.header('accept') ?? '';
  return accept.includes('application/json') && !accept.includes('text/html');
}

export function loginPath(c: AuthContext, cfg: AuthConfig): string {
  const u = new URL(c.req.url);
  const back = c.req.method === 'GET' ? u.pathname + u.search : cfg.afterSignInPath;
  return `${cfg.path('/auth/login')}?returnTo=${encodeURIComponent(back)}`;
}

/** Signed in: pages redirect to the login page, APIs answer 401. */
export function requireUser(cfg: AuthConfig): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    if (c.get('session')) return next();
    return wantsJson(c) ? jsonError(c, 401, 'auth_required', MSG.authRequired) : c.redirect(loginPath(c, cfg));
  };
}

/**
 * Step-up: the session signed in or re-confirmed (passkey or Google/Apple) within `maxAgeMs`. Otherwise 403
 * reauth_required; the client runs reauthenticate() (public/auth/passkey.js) and the user clicks again.
 */
export function requireFreshAuth(cfg: AuthConfig, maxAgeMs = cfg.freshAuthMs): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const s = c.get('session');
    if (!s) return jsonError(c, 401, 'auth_required', MSG.authRequired);
    if (!isFresh(s, maxAgeMs)) return jsonError(c, 403, 'reauth_required', MSG.reauth);
    return next();
  };
}
