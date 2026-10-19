// Request hardening: security headers (CSP with a per-response nonce, Permissions-Policy for WebAuthn), the CSRF
// origin check and a body limit that counts actual bytes.
import type { MiddlewareHandler } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import type { AuthConfig } from './config';
import { randomToken } from './crypto';
import { noteSecurityEvent } from './rate-limit';
import type { AuthEnv } from './types';

export interface SecurityHeaderOptions {
  /** Extra CSP sources, e.g. { 'img-src': ['https://cdn.example.com'] }. */
  csp?: Partial<Record<'script-src' | 'style-src' | 'img-src' | 'font-src' | 'connect-src' | 'frame-src' | 'form-action', string[]>>;
}

/**
 * Security headers. HTML responses get a strict CSP: scripts only with the per-response nonce (c.get('nonce')),
 * form posts only to this origin and to Google/Apple. Every response gets nosniff, a referrer policy, no framing,
 * COOP, HSTS (outside local dev) and a Permissions-Policy that allows WebAuthn for this origin only.
 */
export function securityHeaders(o: SecurityHeaderOptions = {}): MiddlewareHandler<AuthEnv> {
  const extra = (k: keyof NonNullable<SecurityHeaderOptions['csp']>) => (o.csp?.[k]?.length ? ' ' + o.csp[k]!.join(' ') : '');
  return async (c, next) => {
    const nonce = randomToken(16);
    c.set('nonce', nonce);
    await next();
    const h = c.res.headers;
    if ((h.get('content-type') ?? '').includes('text/html')) {
      h.set('Content-Security-Policy', [
        "default-src 'self'",
        `script-src 'nonce-${nonce}' 'strict-dynamic'${extra('script-src')}`,
        `style-src 'self'${extra('style-src')}`,
        `img-src 'self' data:${extra('img-src')}`,
        `font-src 'self'${extra('font-src')}`,
        `connect-src 'self'${extra('connect-src')}`,
        `frame-src 'self'${extra('frame-src')}`,
        "object-src 'none'",
        "base-uri 'none'",
        // The provider start routes redirect to Google/Apple; browsers apply form-action to redirects after a form post.
        `form-action 'self' https://accounts.google.com https://appleid.apple.com${extra('form-action')}`,
        "frame-ancestors 'none'",
      ].join('; '));
      if (!h.has('Cache-Control')) h.set('Cache-Control', 'no-store');
    }
    h.set('X-Content-Type-Options', 'nosniff');
    h.set('Referrer-Policy', h.get('Referrer-Policy') === 'no-referrer' ? 'no-referrer' : 'same-origin');
    h.set('X-Frame-Options', 'DENY');
    h.set('Cross-Origin-Opener-Policy', 'same-origin');
    h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)');
    if (c.env.APP_ENV !== 'local') h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  };
}

/**
 * CSRF: every write (not GET/HEAD/OPTIONS) must carry Origin = APP_ORIGIN. Together with SameSite=Lax cookies this
 * replaces CSRF tokens. Apple's callback arrives as a cross-site form post and is exempt (state + binding cookie +
 * nonce protect it).
 */
export function originCheck(cfg: AuthConfig): MiddlewareHandler<AuthEnv> {
  const appleCallback = cfg.path('/auth/apple/callback');
  return async (c, next) => {
    const m = c.req.method;
    if (m !== 'GET' && m !== 'HEAD' && m !== 'OPTIONS') {
      const origin = c.req.header('origin');
      if (new URL(c.req.url).pathname !== appleCallback && origin !== c.env.APP_ORIGIN) {
        await noteSecurityEvent(c, cfg, { kind: 'origin-blocked', code: origin ? 'foreign_origin' : 'no_origin' });
        return c.text('Forbidden', 403);
      }
    }
    await next();
  };
}

/**
 * Request bodies of at most `maxBytes` (default 256 KB). Counts the bytes actually received, so a chunked body without
 * Content-Length (e.g. a forged Apple form post) is cut off before any parser reads it.
 */
export const bodyLimitGuard = (maxBytes = 256 * 1024): MiddlewareHandler<AuthEnv> =>
  bodyLimit({ maxSize: maxBytes, onError: c => c.text('Payload too large', 413) });
