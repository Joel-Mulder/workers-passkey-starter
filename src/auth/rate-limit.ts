// Fixed-window counters in `rate_counters` (one atomic upsert that refuses to count past the limit), the client-IP
// HMAC used in their keys, and security events.
import type { AuthConfig } from './config';
import { hmac } from './crypto';
import { logIncident } from './http';
import type { AuthBindings, AuthContext, SecurityEvent } from './types';

export interface RateResult { allowed: boolean; count: number; retryAfterSec: number }

export async function hitRateLimit(db: D1Database, key: string, limit: number, windowMs: number, at = Date.now()): Promise<RateResult> {
  const windowStart = Math.floor(at / windowMs) * windowMs;
  const expiresAt = windowStart + windowMs;
  const row = await db.prepare(
    `INSERT INTO rate_counters (key, window_start, count, expires_at) VALUES (?1, ?2, 1, ?3)
     ON CONFLICT (key, window_start) DO UPDATE SET count = rate_counters.count + 1 WHERE rate_counters.count < ?4
     RETURNING count`,
  ).bind(key, windowStart, expiresAt, limit).first<{ count: number }>();
  if (row) return { allowed: true, count: row.count, retryAfterSec: 0 };
  return { allowed: false, count: limit, retryAfterSec: Math.max(1, Math.ceil((expiresAt - at) / 1000)) };
}

/** Client IP as Cloudflare saw it at ingress. Never trust X-Forwarded-For. Local dev shares one value. */
export const clientIp = (req: Request) => (req.headers.get('CF-Connecting-IP') ?? 'local').trim().toLowerCase().slice(0, 64);

/** hmac(SESSION_SECRET, 'ratelimit', ip): the IP itself is never stored. */
export const ipHash = (env: Pick<AuthBindings, 'SESSION_SECRET'>, req: Request, resolve: (req: Request) => string = clientIp) =>
  hmac(env.SESSION_SECRET, 'ratelimit', String(resolve(req) || 'unknown').trim().toLowerCase().slice(0, 64));

/** Short source code for security events (the first 16 characters of ipHash). */
export const sourceOf = (hash: string) => hash.slice(0, 16);

/** Report a security event for the current request through cfg.onSecurityEvent. Never throws. */
export async function noteSecurityEvent(c: AuthContext, cfg: AuthConfig, e: Omit<SecurityEvent, 'source'>): Promise<void> {
  try {
    await cfg.onSecurityEvent({ ...e, source: sourceOf(await ipHash(c.env, c.req.raw, cfg.clientIp)) }, c);
  } catch (err) {
    logIncident('security-event', err);
  }
}

/**
 * Count one unauthenticated flow start for this IP under `purpose`. Returns null when allowed, else the
 * Retry-After seconds (the header is set and a 'throttled' event reported).
 */
export async function flowStartLimited(c: AuthContext, cfg: AuthConfig, purpose: string): Promise<number | null> {
  const res = await hitRateLimit(c.env.DB, `${purpose}:ip:${await ipHash(c.env, c.req.raw, cfg.clientIp)}`, cfg.flowStartsPerWindow, cfg.flowStartWindowMs);
  if (res.allowed) return null;
  c.header('Retry-After', String(res.retryAfterSec));
  await noteSecurityEvent(c, cfg, { kind: 'throttled', code: purpose });
  return res.retryAfterSec;
}
