// Fixes from the second full security audit: router-level CSRF, JSON content type, cookie prefixes, absolute session
// lifetime, no session on a repeated passkey signup, no-store on the API, fail-closed SESSION_SECRET, clientIp,
// RP-scoped "last sign-in method" guard and bidi controls in names.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import worker from '../src/index';
import { createAuth, type AuthEnv } from '../src/auth';
import { insertSession, resolveSession } from '../src/auth/session';
import { deletePasskey } from '../src/auth/passkeys';
import { hmac } from '../src/auth/crypto';
import { validateName } from '../src/auth/validation';
import { client, count, insertPasskey, insertUser, makeCfg, makeEnv, mockRegistration, setCookieOf } from './helpers/auth';

afterEach(() => vi.restoreAllMocks());
const cfg = makeCfg();
const json = (body: unknown) => ({ method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } });

describe('CSRF', () => {
  it('auth.routes checks the Origin itself, even when the app forgets auth.originCheck', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const auth = createAuth({ appName: 'Bare' });
    const a = new Hono<AuthEnv>();
    a.use('*', auth.session); // no app-level originCheck
    a.route('/', auth.routes);
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const s = await insertSession(env.DB, cfg, u, 'passkey');
    const res = await client((r, e) => a.fetch(r, e), env)('/auth/api/sign-out-everywhere', { method: 'POST', origin: 'https://evil.example', cookie: `auth_session=${s.token}` });
    expect(res.status).toBe(403);
  });

  it('JSON endpoints ignore bodies that are not application/json', async () => {
    const req = client(worker.fetch, makeEnv());
    const plain = await req('/auth/api/signup/options', { method: 'POST', body: JSON.stringify({ name: 'Anna', username: 'anna' }), headers: { 'content-type': 'text/plain' } });
    expect(plain.status).toBe(400);
    expect((await req('/auth/api/signup/options', json({ name: 'Anna', username: 'anna' }))).status).toBe(200);
  });
});

describe('cookies', () => {
  it('deployed cookies carry __Host- (path /) or __Secure- (sub-path) prefixes; local dev keeps plain names', async () => {
    mockRegistration('cred-p');
    const env = makeEnv({ APP_ENV: 'production' });
    const req = client(worker.fetch, env);
    const opts = await (await req('/auth/api/signup/options', json({ name: 'Anna', username: 'anna' }))).json() as { flowId: string };
    const res = await req('/auth/api/signup/verify', json({ flowId: opts.flowId, response: { id: 'cred-p', rawId: 'cred-p', type: 'public-key', response: {} } }));
    const raw = setCookieOf(res, '__Host-auth_session')!;
    expect(raw).toMatch(/Path=\//);
    expect(raw).not.toMatch(/Domain=/i);
    expect(setCookieOf(res, 'auth_session')).toBeUndefined();
    // The prefixed cookie is what the server reads back.
    const pair = raw.split(';')[0];
    expect((await req('/auth/api/sign-out-everywhere', { method: 'POST', cookie: pair })).status).not.toBe(401);
  });
});

describe('sessions', () => {
  it('end maxSessionAgeMs after sign-in however often they slide, and renewal never passes that point', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const t0 = 1_800_000_000_000;
    const { token } = await insertSession(env.DB, cfg, user, 'passkey', t0);
    const nearEnd = t0 + cfg.maxSessionAgeMs - cfg.renewAfterMs;
    // Keep it alive by sliding every few weeks.
    for (let t = t0 + 20 * 86_400_000; t < nearEnd; t += 20 * 86_400_000) expect((await resolveSession(env.DB, cfg, token, t)).session).not.toBeNull();
    const last = await resolveSession(env.DB, cfg, token, nearEnd);
    expect(last.renewedUntil).toBe(t0 + cfg.maxSessionAgeMs);
    expect((await resolveSession(env.DB, cfg, token, t0 + cfg.maxSessionAgeMs)).session).toBeNull();
  });

  it('a repeated passkey signup (same flow and response) does not hand out another session', async () => {
    mockRegistration('cred-r');
    const env = makeEnv();
    const req = client(worker.fetch, env);
    const opts = await (await req('/auth/api/signup/options', json({ name: 'Rae', username: 'rae' }))).json() as { flowId: string };
    const body = json({ flowId: opts.flowId, response: { id: 'cred-r', rawId: 'cred-r', type: 'public-key', response: {} } });
    expect(setCookieOf(await req('/auth/api/signup/verify', body), 'auth_session')).toBeTruthy();
    const replay = await req('/auth/api/signup/verify', body);
    expect(replay.status).toBe(200);
    expect(setCookieOf(replay, 'auth_session')).toBeUndefined();
    expect(((await replay.json()) as { redirect: string }).redirect).toMatch(/^\/auth\/login/);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions')).toBe(1);
  });
});

describe('responses and secrets', () => {
  it('auth API responses are never cached, even when the app sets no security headers', async () => {
    const auth = createAuth({ appName: 'Bare' });
    const a = new Hono<AuthEnv>();
    a.use('*', auth.session);
    a.route('/', auth.routes);
    const res = await client((r, e) => a.fetch(r, e), makeEnv())('/auth/api/passkey/login/options', json({}));
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  it('a missing or short SESSION_SECRET fails closed', async () => {
    await expect(hmac('', 'ratelimit', 'ip')).rejects.toThrow(/SESSION_SECRET/);
    await expect(hmac('short', 'ratelimit', 'ip')).rejects.toThrow(/SESSION_SECRET/);
    expect(await hmac('x'.repeat(32), 'ratelimit', 'ip')).toBeTruthy();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await client(worker.fetch, makeEnv({ SESSION_SECRET: '' }))('/auth/api/passkey/login/options', json({}));
    expect(res.status).toBeGreaterThanOrEqual(500);
  });

  it('clientIp decides which address the per-IP limits count', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const auth = createAuth({ appName: 'Ip', flowStartsPerWindow: 2, clientIp: req => req.headers.get('x-test-client') ?? 'none' });
    const a = new Hono<AuthEnv>();
    a.use('*', auth.originCheck, auth.session);
    a.route('/', auth.routes);
    const req = client((r, e) => a.fetch(r, e), makeEnv());
    const from = (who: string, ip: string) => req('/auth/api/passkey/login/options', { ...json({}), headers: { 'content-type': 'application/json', 'x-test-client': who }, ip });
    expect((await from('alice', '203.0.113.1')).status).toBe(200);
    expect((await from('alice', '203.0.113.2')).status).toBe(200);
    expect((await from('alice', '203.0.113.3')).status).toBe(429); // different CF IPs, same resolved client
    expect((await from('bob', '203.0.113.1')).status).toBe(200);
  });
});

describe('accounts', () => {
  it('a passkey for another RP ID does not count as a remaining way to sign in', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const here = await insertPasskey(env.DB, user.id);
    await insertPasskey(env.DB, user.id, { rpId: 'old.example' });
    expect(await deletePasskey(env.DB, cfg, user.id, here.id, Date.now(), null, 'localhost')).toMatchObject({ ok: false, code: 'last_sign_in_method' });
    await insertPasskey(env.DB, user.id);
    expect((await deletePasskey(env.DB, cfg, user.id, here.id, Date.now(), null, 'localhost')).ok).toBe(true);
  });

  it('names may not contain bidi overrides, isolates or marks', () => {
    for (const ch of ['‮', '⁦', '⁩', '‏', '؜']) expect(validateName(`Ann${ch}a`).ok).toBe(false);
    expect(validateName('Zoë Ångström').ok).toBe(true);
  });
});
