// Small HTTP helpers shared by the routes.
import type { AuthConfig } from './config';
import type { AuthContext } from './types';

export type ErrorStatus = 400 | 401 | 403 | 404 | 409 | 422 | 429 | 500 | 503;

/** Uniform JSON error: { error: { code, message } }. `code` is stable (clients branch on it), `message` is for people. */
export function jsonError(c: AuthContext, status: ErrorStatus, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}

/**
 * Only same-app relative return targets (prevents open redirects): a path under basePath, never `//host` or a
 * backslash/newline trick. Anything else gives `fallback`.
 */
export function safeReturnTo(cfg: AuthConfig, value: string | undefined | null, fallback = cfg.afterSignInPath): string {
  if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('/') || value.startsWith('//') || /[\r\n\\]/.test(value)) return fallback;
  if (cfg.basePath && value !== cfg.basePath && !value.startsWith(cfg.basePath + '/') && !value.startsWith(cfg.basePath + '?')) return fallback;
  return value;
}

/** Parse a JSON body of at most `max` bytes (the global body limit already capped the stream). */
export async function readJson<T>(c: AuthContext, max = 64 * 1024): Promise<T | null> {
  const buf = await c.req.arrayBuffer();
  if (buf.byteLength > max) return null;
  try { return JSON.parse(new TextDecoder().decode(buf)) as T; } catch { return null; }
}

/**
 * Log an error without its message (messages can hold tokens or personal data); returns a short incident id to
 * show the user. `where` is a fixed label, never a concrete path.
 */
export function logIncident(where: string, err: unknown): string {
  const id = crypto.randomUUID().slice(0, 8);
  console.error(JSON.stringify({ incident: id, where, kind: err instanceof Error ? err.name : typeof err }));
  return id;
}
