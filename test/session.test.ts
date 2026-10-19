import { describe, expect, it } from 'vitest';
import { Hono } from 'hono';
import { insertSession, isFresh, requireFreshAuth, requireUser, resolveSession, revokeAllSessions, sessionMiddleware } from '../src/auth/session';
import { validateName, validateUsername } from '../src/auth/validation';
import { safeReturnTo } from '../src/auth/http';
import type { AuthEnv } from '../src/auth/types';
import { count, insertUser, makeCfg, makeEnv } from './helpers/auth';

const cfg = makeCfg();

describe('validation', () => {
  it('accepts and lowercases valid usernames', () => {
    expect(validateUsername('  Jan.de-Vries_1 ')).toEqual({ ok: true, value: 'jan.de-vries_1' });
  });
  it.each(['ab', '_abc', '-abc', 'a'.repeat(33), 'jan vries', 'jan@x', ''])('rejects username %j', u => {
    expect(validateUsername(u).ok).toBe(false);
  });
  it('validates names of 2–100 characters and collapses whitespace', () => {
    expect(validateName('A').ok).toBe(false);
    expect(validateName('Jo').ok).toBe(true);
    expect(validateName('x'.repeat(101)).ok).toBe(false);
    expect(validateName('a\u0000b').ok).toBe(false);
    expect(validateName('  Jan   Jansen ')).toEqual({ ok: true, value: 'Jan Jansen' });
  });
});

describe('safe return targets', () => {
  it('allows same-app paths only', () => {
    expect(safeReturnTo(cfg, '/dashboard?x=1')).toBe('/dashboard?x=1');
    for (const bad of ['//evil.example', 'https://evil.example', '/\\evil', '/a\nb', 'relative', undefined]) expect(safeReturnTo(cfg, bad)).toBe('/');
    const app = makeCfg({ basePath: '/app' });
    expect(safeReturnTo(app, '/app/x')).toBe('/app/x');
    expect(safeReturnTo(app, '/other')).toBe('/app/');
    expect(safeReturnTo(app, '/application')).toBe('/app/');
  });
});

describe('sessions', () => {
  it('stores only the token hash and resolves the session', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const { token, info } = await insertSession(env.DB, cfg, user, 'passkey');
    expect(info.id).not.toBe(token);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions WHERE id = ?', token)).toBe(0);
    const r = await resolveSession(env.DB, cfg, token);
    expect(r.session?.user).toEqual({ id: user.id, username: user.username, name: user.name, status: 'active' });
    expect((await resolveSession(env.DB, cfg, 'not-a-token')).invalid).toBe(true);
    expect((await resolveSession(env.DB, cfg, 'x'.repeat(200))).invalid).toBe(true);
  });

  it('ends sessions when access_version changes or the user is suspended', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const a = await insertSession(env.DB, cfg, user, 'passkey');
    const b = await insertSession(env.DB, cfg, user, 'google');
    await revokeAllSessions(env.DB, user.id);
    expect((await resolveSession(env.DB, cfg, a.token)).session).toBeNull();
    expect((await resolveSession(env.DB, cfg, b.token)).session).toBeNull();
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions')).toBe(0);

    const fresh = await insertUser(env.DB);
    const s = await insertSession(env.DB, cfg, fresh, 'passkey');
    await env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(fresh.id).run();
    expect((await resolveSession(env.DB, cfg, s.token)).session).toBeNull();
  });

  it('slides once older than renewAfter and expires after the TTL', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const t0 = 1_800_000_000_000;
    const { token } = await insertSession(env.DB, cfg, user, 'passkey', t0);
    expect((await resolveSession(env.DB, cfg, token, t0 + 1000)).renewedUntil).toBeUndefined();
    const later = t0 + cfg.renewAfterMs + 1000;
    expect((await resolveSession(env.DB, cfg, token, later)).renewedUntil).toBe(later + cfg.sessionTtlMs);
    expect((await resolveSession(env.DB, cfg, token, later + cfg.sessionTtlMs + 1)).session).toBeNull();
  });

  it('fresh auth lasts freshAuthMs', () => {
    const s = { authenticatedAt: 1000 } as never;
    expect(isFresh(s, cfg.freshAuthMs, 1000 + cfg.freshAuthMs)).toBe(true);
    expect(isFresh(s, cfg.freshAuthMs, 1001 + cfg.freshAuthMs)).toBe(false);
    expect(isFresh(null, cfg.freshAuthMs)).toBe(false);
  });
});

describe('guards', () => {
  function app(env: ReturnType<typeof makeEnv>) {
    const a = new Hono<AuthEnv>();
    a.use('*', sessionMiddleware(cfg));
    a.get('/page', requireUser(cfg), c => c.text('ok'));
    a.get('/api/x', requireUser(cfg), c => c.text('ok'));
    a.post('/api/sensitive', requireFreshAuth(cfg), c => c.text('ok'));
    return (path: string, init: RequestInit = {}) => a.request(path, init, env);
  }

  it('redirects pages to the login page and answers 401 JSON for APIs', async () => {
    const req = app(makeEnv());
    const page = await req('/page?x=1');
    expect(page.status).toBe(302);
    expect(page.headers.get('location')).toBe('/auth/login?returnTo=%2Fpage%3Fx%3D1');
    const api = await req('/api/x');
    expect(api.status).toBe(401);
    expect(await api.json()).toMatchObject({ error: { code: 'auth_required' } });
  });

  it('requireFreshAuth answers 403 reauth_required for stale sessions', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const stale = await insertSession(env.DB, cfg, user, 'passkey', Date.now() - 6 * 60_000);
    const req = app(env);
    const res = await req('/api/sensitive', { method: 'POST', headers: { cookie: `auth_session=${stale.token}` } });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: { code: 'reauth_required', message: expect.any(String) } });
    const fresh = await insertSession(env.DB, cfg, user, 'passkey');
    expect((await req('/api/sensitive', { method: 'POST', headers: { cookie: `auth_session=${fresh.token}` } })).status).toBe(200);
  });

  it('clears the cookie of a dead session', async () => {
    const res = await app(makeEnv())('/page', { headers: { cookie: 'auth_session=gone' } });
    expect(res.headers.getSetCookie().join()).toMatch(/auth_session=;.*Max-Age=0/);
  });
});
