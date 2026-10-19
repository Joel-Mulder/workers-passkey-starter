import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { finishOAuth, oauthProvidersEnabled, oidc, redirectUri, resolveOAuth, startOAuth, type OAuthFlow } from '../src/auth/oauth';
import { insertSession, resolveSession } from '../src/auth/session';
import { client, cookiePair, count, insertIdentity, insertUser, makeCfg, makeEnv, ORIGIN, setCookieOf } from './helpers/auth';

afterEach(() => vi.restoreAllMocks());

const cfg = makeCfg();
const googleEnv = (o = {}) => makeEnv({ GOOGLE_CLIENT_ID: 'gid', GOOGLE_CLIENT_SECRET: 'gsecret', ...o });
const appleEnv = () => makeEnv({ APPLE_CLIENT_ID: 'aid', APPLE_TEAM_ID: 't', APPLE_KEY_ID: 'k', APPLE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' });
const identity = (o: Partial<{ subject: string; email: string | null; emailVerified: boolean; name: string | null }> = {}) =>
  ({ provider: 'google' as const, subject: 'sub-1', email: 'anna@example.com', emailVerified: true, name: 'Anna', ...o });
const flow = (o: Partial<OAuthFlow> = {}): OAuthFlow => ({ provider: 'google', intent: 'login', nonce: 'n', returnTo: '/', binding: 'x', ...o });
const stubProvider = (id = identity()) => {
  vi.spyOn(oidc, 'exchangeCode').mockResolvedValue('id-token');
  return vi.spyOn(oidc, 'verifyIdToken').mockResolvedValue(id);
};

describe('Google / Apple', () => {
  it('a provider is on once all its values are set; redirect URIs follow basePath', () => {
    expect(oauthProvidersEnabled(makeEnv())).toEqual({ google: false, apple: false });
    expect(oauthProvidersEnabled(googleEnv())).toEqual({ google: true, apple: false });
    expect(oauthProvidersEnabled(appleEnv())).toEqual({ google: false, apple: true });
    expect(redirectUri(makeEnv(), makeCfg({ basePath: '/app' }), 'apple')).toBe(`${ORIGIN}/app/auth/apple/callback`);
  });

  it('stores state, PKCE verifier and nonce in auth_flows (not cookies); single use', async () => {
    const env = googleEnv();
    const url = await startOAuth(env, cfg, { provider: 'google', intent: 'login', returnTo: '/', binding: 'browser-1' });
    const state = url.searchParams.get('state')!;
    expect(url.searchParams.get('nonce')).toBeTruthy();
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/auth/google/callback`);
    const row = await env.DB.prepare('SELECT kind, data FROM auth_flows WHERE id = ?').bind(state).first<{ kind: string; data: string }>();
    expect(row!.kind).toBe('oauth');
    expect(JSON.parse(row!.data)).toMatchObject({ provider: 'google', intent: 'login', nonce: url.searchParams.get('nonce'), codeVerifier: expect.any(String) });

    const verify = stubProvider();
    expect((await finishOAuth(env, cfg, 'google', { state, code: 'c', binding: 'browser-1' })).ok).toBe(true);
    expect(verify.mock.calls[0]![3]).toBe(url.searchParams.get('nonce'));
    expect(await finishOAuth(env, cfg, 'google', { state, code: 'c', binding: 'browser-1' })).toMatchObject({ ok: false, code: 'oauth_expired' });
  });

  it('Apple: form_post, no PKCE', async () => {
    const env = appleEnv();
    const url = await startOAuth(env, cfg, { provider: 'apple', intent: 'login', returnTo: '/', binding: 'b' });
    expect(url.searchParams.get('response_mode')).toBe('form_post');
    expect(url.searchParams.get('code_challenge')).toBeNull();
  });

  it('only finishes in the browser that started the flow (binding cookie)', async () => {
    const env = googleEnv();
    stubProvider();
    const start = async () => (await startOAuth(env, cfg, { provider: 'google', intent: 'login', returnTo: '/', binding: 'browser-1' })).searchParams.get('state')!;
    const s1 = await start();
    const stored = JSON.parse((await env.DB.prepare('SELECT data FROM auth_flows WHERE id = ?').bind(s1).first<{ data: string }>())!.data);
    expect(stored.binding).toMatch(/^[0-9a-f]{64}$/); // a hash, not the cookie
    expect(await finishOAuth(env, cfg, 'google', { state: s1, code: 'c' })).toMatchObject({ ok: false, code: 'oauth_other_browser' });
    expect(await finishOAuth(env, cfg, 'google', { state: await start(), code: 'c', binding: 'browser-2' })).toMatchObject({ ok: false, code: 'oauth_other_browser' });
    expect((await finishOAuth(env, cfg, 'google', { state: await start(), code: 'c', binding: 'browser-1' })).ok).toBe(true);
  });

  it('a provider error or a failing token check is a failed sign-in', async () => {
    const env = googleEnv();
    const state = async () => (await startOAuth(env, cfg, { provider: 'google', intent: 'login', returnTo: '/', binding: 'b' })).searchParams.get('state')!;
    expect(await finishOAuth(env, cfg, 'google', { state: await state(), error: 'access_denied', binding: 'b' })).toMatchObject({ ok: false, code: 'oauth_cancelled' });
    vi.spyOn(oidc, 'exchangeCode').mockResolvedValue('id-token');
    vi.spyOn(oidc, 'verifyIdToken').mockRejectedValue(new Error('nonce mismatch'));
    expect(await finishOAuth(env, cfg, 'google', { state: await state(), code: 'c', binding: 'b' })).toMatchObject({ ok: false, code: 'oauth_failed' });
  });

  it('never matches by e-mail: an unlinked identity with a matching address gets "no account"', async () => {
    const env = googleEnv();
    const u = await insertUser(env.DB);
    await env.DB.prepare("INSERT INTO oauth_identities (id, user_id, provider, subject, email, created_at) VALUES ('i', ?, 'apple', 'apple-sub', 'anna@example.com', 1)").bind(u.id).run();
    expect((await resolveOAuth(env, cfg, flow(), null, identity())).kind).toBe('no_account');
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM oauth_identities WHERE provider = 'google'")).toBe(0);
  });

  it('signs in a linked identity and blocks suspended users', async () => {
    const env = googleEnv();
    const u = await insertUser(env.DB);
    await insertIdentity(env.DB, u.id, { subject: 'sub-1' });
    const out = await resolveOAuth(env, cfg, flow(), null, identity());
    expect(out.kind === 'signin' && out.user.id).toBe(u.id);
    await env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(u.id).run();
    const blocked = await resolveOAuth(env, cfg, flow(), null, identity());
    expect(blocked.kind === 'error' && blocked.fail.code).toBe('account_suspended');
  });

  it('links to the flow user and refuses identities linked elsewhere', async () => {
    const env = googleEnv();
    const a = await insertUser(env.DB);
    const b = await insertUser(env.DB);
    expect((await resolveOAuth(env, cfg, flow({ intent: 'link' }), a.id, identity())).kind).toBe('linked');
    const taken = await resolveOAuth(env, cfg, flow({ intent: 'link' }), b.id, identity());
    expect(taken.kind === 'error' && taken.fail.code).toBe('identity_taken');
  });

  it('reauth marks the starting session fresh, only for the linked user', async () => {
    const env = googleEnv();
    const u = await insertUser(env.DB);
    const other = await insertUser(env.DB);
    await insertIdentity(env.DB, u.id, { subject: 'sub-1' });
    const s = await insertSession(env.DB, cfg, u, 'google', Date.now() - 3600_000);
    expect((await resolveOAuth(env, cfg, flow({ intent: 'reauth', sessionId: s.info.id }), other.id, identity())).kind).toBe('error');
    expect((await resolveOAuth(env, cfg, flow({ intent: 'reauth', sessionId: s.info.id }), u.id, identity())).kind).toBe('reauthed');
    expect(Date.now() - (await resolveSession(env.DB, cfg, s.token)).session!.authenticatedAt).toBeLessThan(5000);
  });

  it('signup intent → a signup draft (the account is made after the username step)', async () => {
    const env = googleEnv();
    const out = await resolveOAuth(env, cfg, flow({ intent: 'signup' }), null, identity());
    expect(out.kind).toBe('signup');
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM users')).toBe(0);
  });
});

describe('Google / Apple routes', () => {
  it('start sets the binding cookie; the callback needs it, signs in and clears it', async () => {
    const env = googleEnv();
    const u = await insertUser(env.DB);
    await insertIdentity(env.DB, u.id, { subject: 'sub-1' });
    stubProvider();
    const req = client(worker.fetch, env);

    const start = await req('/auth/google/start?returnTo=%2Fprivate');
    expect(start.status).toBe(302);
    const raw = setCookieOf(start, 'auth_oauth')!;
    expect(raw).toMatch(/HttpOnly/);
    expect(raw).toMatch(/Path=\/auth/);
    expect(raw).toMatch(/SameSite=Lax/); // local; None + Secure when deployed (Apple form_post)
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    // Same state without the binding cookie (a link sent to someone else): refused.
    const stolen = await req(`/auth/google/callback?state=${state}&code=c`);
    expect(stolen.status).toBe(400);
    expect(await stolen.text()).toContain('another browser');

    const again = await req('/auth/google/start?returnTo=%2Fprivate');
    const state2 = new URL(again.headers.get('location')!).searchParams.get('state')!;
    const ok = await req(`/auth/google/callback?state=${state2}&code=c`, { cookie: cookiePair(again, 'auth_oauth') });
    expect(ok.status).toBe(303);
    expect(ok.headers.get('location')).toBe('/private');
    expect(setCookieOf(ok, 'auth_session')).toMatch(/HttpOnly/);
    expect(setCookieOf(ok, 'auth_oauth')).toMatch(/Max-Age=0/);
  });

  it('deployed: the binding cookie is SameSite=None; Secure so Apple’s form_post carries it', async () => {
    const res = await client(worker.fetch, googleEnv({ APP_ENV: 'production' }))('/auth/google/start');
    const raw = setCookieOf(res, 'auth_oauth')!;
    expect(raw).toMatch(/SameSite=None/);
    expect(raw).toMatch(/Secure/);
  });

  it('unknown provider or missing configuration: 404 page', async () => {
    const req = client(worker.fetch, makeEnv());
    expect((await req('/auth/google/start')).status).toBe(404);
    expect((await req('/auth/github/start')).status).toBe(404);
  });

  it('signup: callback → pick a username → account + session', async () => {
    const env = googleEnv();
    stubProvider(identity({ subject: 'new-sub', name: 'Nina' }));
    const req = client(worker.fetch, env);
    const start = await req('/auth/google/start?intent=signup');
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const cb = await req(`/auth/google/callback?state=${state}&code=c`, { cookie: cookiePair(start, 'auth_oauth') });
    expect(cb.headers.get('location')).toBe('/auth/signup/complete');
    const signup = cookiePair(cb, 'auth_signup')!;
    const page = await req('/auth/signup/complete', { cookie: signup });
    expect(await page.text()).toContain('value="Nina"');
    const done = await req('/auth/signup/complete', { method: 'POST', cookie: signup, body: new URLSearchParams({ name: 'Nina', username: 'nina' }) });
    expect(done.status).toBe(303);
    expect(setCookieOf(done, 'auth_session')).toBeTruthy();
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM users u JOIN oauth_identities i ON i.user_id = u.id WHERE u.username = 'nina' AND i.subject = 'new-sub'")).toBe(1);
  });

  it('login with an unknown identity offers signup instead of creating an account', async () => {
    const env = googleEnv();
    stubProvider(identity({ subject: 'stranger' }));
    const req = client(worker.fetch, env);
    const start = await req('/auth/google/start');
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const res = await req(`/auth/google/callback?state=${state}&code=c`, { cookie: cookiePair(start, 'auth_oauth') });
    expect(res.status).toBe(404);
    expect(await res.text()).toContain('intent=signup');
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM users')).toBe(0);
  });

  it('link needs a fresh session and only completes in the session of the user who started it', async () => {
    const env = googleEnv();
    const a = await insertUser(env.DB);
    const b = await insertUser(env.DB);
    stubProvider(identity({ subject: 'sub-link' }));
    const req = client(worker.fetch, env);
    const stale = await insertSession(env.DB, cfg, a, 'passkey', Date.now() - 10 * 60_000);
    const notFresh = await req('/auth/google/start?intent=link', { cookie: `auth_session=${stale.token}` });
    expect(notFresh.headers.get('location')).toBe('/auth/account?reauth=1');

    const sa = await insertSession(env.DB, cfg, a, 'passkey');
    const sb = await insertSession(env.DB, cfg, b, 'passkey');
    const startLink = async () => {
      const res = await req('/auth/google/start?intent=link', { cookie: `auth_session=${sa.token}` });
      expect(res.status).toBe(302);
      return { state: new URL(res.headers.get('location')!).searchParams.get('state')!, binding: cookiePair(res, 'auth_oauth')! };
    };
    const f1 = await startLink();
    const wrong = await req(`/auth/google/callback?state=${f1.state}&code=c`, { cookie: `${f1.binding}; auth_session=${sb.token}` });
    expect(wrong.status).toBe(400);
    const f2 = await startLink();
    expect((await req(`/auth/google/callback?state=${f2.state}&code=c`, { cookie: f2.binding })).status).toBe(400);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM oauth_identities')).toBe(0);
    const f3 = await startLink();
    const ok = await req(`/auth/google/callback?state=${f3.state}&code=c`, { cookie: `${f3.binding}; auth_session=${sa.token}` });
    expect(ok.status).toBe(303);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM oauth_identities WHERE user_id = ?', a.id)).toBe(1);
  });

  it('Apple reauth: the cross-site form_post continues on a same-site GET that checks the session', async () => {
    const env = appleEnv();
    const u = await insertUser(env.DB);
    const other = await insertUser(env.DB);
    await insertIdentity(env.DB, u.id, { provider: 'apple', subject: 'sub-a' });
    stubProvider({ ...identity({ subject: 'sub-a' }), provider: 'apple' } as never);
    const req = client(worker.fetch, env);
    const s = await insertSession(env.DB, cfg, u, 'apple', Date.now() - 3600_000);
    const so = await insertSession(env.DB, cfg, other, 'passkey');
    const startReauth = async () => {
      const res = await req('/auth/apple/start?intent=reauth', { cookie: `auth_session=${s.token}` });
      return { state: new URL(res.headers.get('location')!).searchParams.get('state')!, binding: cookiePair(res, 'auth_oauth')! };
    };
    // A real cross-site POST from Apple: foreign Origin, only the SameSite=None binding cookie.
    const post = (f: { state: string; binding: string }) => req('/auth/apple/callback', {
      method: 'POST', origin: 'https://appleid.apple.com', cookie: f.binding, body: new URLSearchParams({ state: f.state, code: 'c' }),
    });
    const resume = (await post(await startReauth())).headers.get('location')!;
    expect(resume).toMatch(/^\/auth\/apple\/resume\?id=/);
    expect((await req(resume, { cookie: `auth_session=${so.token}` })).status).toBe(400); // another account can't pick it up

    const resume2 = (await post(await startReauth())).headers.get('location')!;
    expect((await req(resume2, { cookie: `auth_session=${s.token}` })).status).toBe(303);
    expect(Date.now() - (await resolveSession(env.DB, cfg, s.token)).session!.authenticatedAt).toBeLessThan(5000);
    expect((await req(resume2, { cookie: `auth_session=${s.token}` })).status).toBe(400); // single use
  });
});
