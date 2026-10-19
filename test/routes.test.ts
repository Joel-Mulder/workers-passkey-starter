// HTTP-level checks through the example Worker (src/index.ts) and a custom createAuth() app, with the in-memory D1.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import worker from '../src/index';
import { createAuth, type AuthEnv } from '../src/auth';
import { insertSession } from '../src/auth/session';
import { client, cookiePair, count, credentialResponse, insertIdentity, insertPasskey, insertUser, makeCfg, makeEnv, mockAuthentication, mockRegistration, setCookieOf } from './helpers/auth';

afterEach(() => vi.restoreAllMocks());
const cfg = makeCfg();
const json = (body: unknown) => ({ method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } });

describe('pages', () => {
  it('the login page loads passkey.js with the CSP nonce and shows only configured providers', async () => {
    const res = await client(worker.fetch, makeEnv({ GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 's' }))('/auth/login?returnTo=%2Fprivate');
    expect(res.status).toBe(200);
    const body = await res.text();
    const nonce = /script-src 'nonce-([^']+)'/.exec(res.headers.get('content-security-policy') ?? '')?.[1];
    expect(nonce).toBeTruthy();
    expect(body).toContain(`<script type="module" nonce="${nonce}" src="/auth/passkey.js"></script>`);
    expect(body).toContain('data-return-to="/private"');
    expect(body).toContain('/auth/google/start?intent=login');
    expect(body).not.toContain('/auth/apple/start');
    expect(body).not.toContain('style=');
  });

  it('escapes user data in pages', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB, { name: '<img src=x onerror=alert(1)>' });
    await insertPasskey(env.DB, u.id);
    const s = await insertSession(env.DB, cfg, u, 'passkey');
    const body = await (await client(worker.fetch, env)('/auth/account', { cookie: `auth_session=${s.token}` })).text();
    expect(body).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(body).not.toContain('<img src=x');
  });

  it('the account page needs a session; the last sign-in method can’t be removed', async () => {
    const env = makeEnv();
    const req = client(worker.fetch, env);
    expect((await req('/auth/account')).headers.get('location')).toBe('/auth/login?returnTo=%2Fauth%2Faccount');
    const u = await insertUser(env.DB);
    await insertPasskey(env.DB, u.id);
    const s = await insertSession(env.DB, cfg, u, 'passkey');
    const body = await (await req('/auth/account', { cookie: `auth_session=${s.token}` })).text();
    expect(body).toMatch(/data-passkey-remove[^>]*disabled/);
  });
});

describe('passkey API', () => {
  it('login: options → verify → session cookie and the Signal API data', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, u.id);
    mockAuthentication();
    const req = client(worker.fetch, env);
    const opts = await (await req('/auth/api/passkey/login/options', json({}))).json() as { flowId: string };
    const res = await req('/auth/api/passkey/login/verify', json({ flowId: opts.flowId, response: credentialResponse(pk.credentialId), returnTo: '/private' }));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, redirect: '/private', rpId: 'localhost', userId: Buffer.from(u.id).toString('base64url'), acceptedCredentialIds: [pk.credentialId], name: u.username, displayName: u.name });
    const cookie = setCookieOf(res, 'auth_session')!;
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Lax/);
    expect(cookie).toMatch(/Path=\//);
    const me = await req('/auth/api/me', { cookie: cookiePair(res, 'auth_session') });
    expect(await me.json()).toMatchObject({ user: { id: u.id }, authMethod: 'passkey', fresh: true });
  });

  it('an open redirect in returnTo is ignored', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, u.id);
    mockAuthentication();
    const req = client(worker.fetch, env);
    const opts = await (await req('/auth/api/passkey/login/options', json({}))).json() as { flowId: string };
    const res = await req('/auth/api/passkey/login/verify', json({ flowId: opts.flowId, response: credentialResponse(pk.credentialId), returnTo: '//evil.example/' }));
    expect(await res.json()).toMatchObject({ redirect: '/' });
  });

  it('the login 404 says whether the client may signal an unknown credential', async () => {
    const req = client(worker.fetch, makeEnv());
    const opts = await (await req('/auth/api/passkey/login/options', json({}))).json() as { flowId: string };
    const res = await req('/auth/api/passkey/login/verify', json({ flowId: opts.flowId, response: credentialResponse('gone', Buffer.from(crypto.randomUUID()).toString('base64url')) }));
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: { code: 'unknown_credential' }, credentialId: 'gone', rpId: 'localhost', signalUnknown: true });
  });

  it('signup: options → verify → account and session', async () => {
    const env = makeEnv();
    mockRegistration('cred-new');
    const req = client(worker.fetch, env);
    const bad = await req('/auth/api/signup/options', json({ name: 'Anna', username: 'a' }));
    expect(bad.status).toBe(422);
    const opts = await (await req('/auth/api/signup/options', json({ name: 'Anna', username: 'anna' }))).json() as { flowId: string };
    const res = await req('/auth/api/signup/verify', json({ flowId: opts.flowId, response: { id: 'cred-new', rawId: 'cred-new', type: 'public-key', response: {} } }));
    expect(res.status).toBe(200);
    expect(setCookieOf(res, 'auth_session')).toBeTruthy();
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM users WHERE username = 'anna'")).toBe(1);
  });

  it('account changes need fresh auth; sign out everywhere keeps this device', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const other = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, u.id);
    await insertPasskey(env.DB, u.id);
    const stale = await insertSession(env.DB, cfg, u, 'passkey', Date.now() - 10 * 60_000);
    const req = client(worker.fetch, env);
    for (const path of ['/auth/api/passkeys/options', `/auth/api/passkeys/${pk.id}/delete`, `/auth/api/passkeys/${pk.id}/rename`, '/auth/api/sign-out-everywhere']) {
      const res = await req(path, { ...json({ name: 'x' }), cookie: `auth_session=${stale.token}` });
      expect(res.status).toBe(403);
      expect(await res.json()).toMatchObject({ error: { code: 'reauth_required' } });
    }
    const here = await insertSession(env.DB, cfg, u, 'passkey');
    await insertSession(env.DB, cfg, other, 'passkey');
    const out = await req('/auth/api/sign-out-everywhere', { method: 'POST', cookie: `auth_session=${here.token}` });
    expect(await out.json()).toEqual({ ok: true, revoked: 1 });
    expect((await env.DB.prepare('SELECT id FROM sessions WHERE user_id = ?').bind(u.id).all<{ id: string }>()).results.map(r => r.id)).toEqual([here.info.id]);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?', other.id)).toBe(1);
    expect((await req('/auth/api/me', { cookie: `auth_session=${here.token}` })).status).toBe(200);
    const del = await req(`/auth/api/passkeys/${pk.id}/delete`, { method: 'POST', cookie: `auth_session=${here.token}` });
    expect(await del.json()).toMatchObject({ ok: true, rpId: 'localhost', acceptedCredentialIds: [expect.any(String)] });
  });

  it('step-up without a passkey points the client to Google/Apple', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    await insertIdentity(env.DB, u.id, { provider: 'apple' });
    const s = await insertSession(env.DB, cfg, u, 'apple');
    const res = await client(worker.fetch, env)('/auth/api/reauth/options', { method: 'POST', cookie: `auth_session=${s.token}` });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: { code: 'no_passkey' }, provider: 'apple' });
  });

  it('logout ends this session only', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const a = await insertSession(env.DB, cfg, u, 'passkey');
    await insertSession(env.DB, cfg, u, 'passkey');
    const res = await client(worker.fetch, env)('/auth/logout', { method: 'POST', cookie: `auth_session=${a.token}` });
    expect(res.status).toBe(303);
    expect(setCookieOf(res, 'auth_session')).toMatch(/Max-Age=0/);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?', u.id)).toBe(1);
  });
});

describe('createAuth options', () => {
  function app(options: Parameters<typeof createAuth>[0]) {
    const auth = createAuth(options);
    const a = new Hono<AuthEnv>();
    a.use('*', auth.securityHeaders, auth.bodyLimit, auth.originCheck, auth.session);
    a.route(auth.config.basePath || '/', auth.routes);
    a.get(`${auth.config.basePath}/private`, auth.requireUser, c => c.text('private'));
    return a;
  }

  it('allowSignup can refuse with a message; onUserCreated runs once per new account', async () => {
    const created = vi.fn();
    const a = app({ appName: 'Closed', allowSignup: ({ username }) => username === 'invited' || 'Signups are invite-only.', onUserCreated: created });
    const env = makeEnv();
    const req = client((r, e) => a.fetch(r, e), env);
    const refused = await req('/auth/api/signup/options', json({ name: 'Eve', username: 'eve' }));
    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({ error: { code: 'signup_closed', message: 'Signups are invite-only.' } });
    mockRegistration('cred-i');
    const opts = await (await req('/auth/api/signup/options', json({ name: 'Ivy', username: 'invited' }))).json() as { flowId: string };
    const body = json({ flowId: opts.flowId, response: { id: 'cred-i', rawId: 'cred-i', type: 'public-key', response: {} } });
    expect((await req('/auth/api/signup/verify', body)).status).toBe(200);
    expect((await req('/auth/api/signup/verify', body)).status).toBe(200); // retry: same account
    expect(created).toHaveBeenCalledTimes(1);
    expect(created.mock.calls[0]![0]).toMatchObject({ method: 'passkey', user: { username: 'invited' } });
  });

  it('allowSignup also guards Google/Apple signup', async () => {
    const a = app({ appName: 'Closed', allowSignup: () => false });
    const res = await client((r, e) => a.fetch(r, e), makeEnv({ GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 's' }))('/auth/google/start?intent=signup');
    expect(res.status).toBe(403);
  });

  it('mounts under a basePath: routes, cookie path, redirects and the Apple exemption follow it', async () => {
    const a = app({ appName: 'Sub', basePath: '/app', cookiePrefix: 'sub' });
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, u.id);
    mockAuthentication();
    const req = client((r, e) => a.fetch(r, e), env);
    expect((await req('/app/private')).headers.get('location')).toBe('/app/auth/login?returnTo=%2Fapp%2Fprivate');
    expect(await (await req('/app/auth/login')).text()).toContain('src="/app/auth/passkey.js"');
    const opts = await (await req('/app/auth/api/passkey/login/options', json({}))).json() as { flowId: string };
    const res = await req('/app/auth/api/passkey/login/verify', json({ flowId: opts.flowId, response: credentialResponse(pk.credentialId) }));
    expect(await res.json()).toMatchObject({ redirect: '/app/' });
    expect(setCookieOf(res, 'sub_session')).toMatch(/Path=\/app/);
    // The Apple callback under the base path is exempt from the origin check (it fails on state instead).
    const apple = await req('/app/auth/apple/callback', { method: 'POST', origin: 'https://appleid.apple.com', body: new URLSearchParams({ state: 'x'.repeat(20), code: 'c' }) });
    expect(apple.status).toBe(400);
  });
});
