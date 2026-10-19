import { afterEach, describe, expect, it, vi } from 'vitest';
import { finishLogin, startLogin } from '../../src/auth/passkeys';
import { count, credentialResponse, insertPasskey, insertUser, makeEnv, mockAuthentication } from '../helpers/auth';
import { json, linkIn, makeAdmin, moduleApp, sessionCookie, signupPasskey, user } from './helpers';

afterEach(() => vi.restoreAllMocks());

const act = (t: ReturnType<typeof moduleApp>, cookie: string, id: string, action: string, expectedVersion: unknown) =>
  t.req(`/auth/api/admin/users/${id}/${action}`, { ...json({ expectedVersion }), cookie });
const version = async (db: D1Database, id: string) => (await db.prepare('SELECT access_version FROM users WHERE id = ?').bind(id).first<number>('access_version'))!;

describe('signup modes', () => {
  it('approval: the account is created but waits; no session; admins are mailed; sign-in explains why', async () => {
    const t = moduleApp({ admin: { signupMode: 'approval' } });
    await makeAdmin(t.env.DB, { email: 'boss@example.com' });
    const res = await signupPasskey(t.req, { name: 'Wanda', username: 'wanda' });
    expect(res.json).toMatchObject({ ok: true, pending: true, code: 'account_pending', message: expect.stringContaining('waiting for approval') });
    expect(res.cookie).toBeUndefined();
    expect(await user(t.env.DB, 'wanda')).toMatchObject({ status: 'suspended', approval: 'pending' });
    expect(t.outbox.sent).toEqual([expect.objectContaining({ to: 'boss@example.com', subject: expect.stringContaining('waiting for approval') })]);
    expect(t.outbox.sent[0]!.text).toContain('Username: "wanda"');
    expect(linkIn(t.outbox.sent[0]!.text)).toContain('/auth/admin');

    // Signing in with the new passkey is refused with the reason.
    mockAuthentication();
    const login = await (await t.req('/auth/api/passkey/login/options', json({}))).json() as { flowId: string };
    const r = await t.req('/auth/api/passkey/login/verify', json({ flowId: login.flowId, response: credentialResponse(res.credentialId) }));
    expect(r.status).toBe(403);
    expect(await r.json()).toMatchObject({ error: { code: 'account_pending' } });
  });

  it('approval via Google: the username step ends on "Account created" without a session', async () => {
    const t = moduleApp({ admin: { signupMode: 'approval' } });
    Object.assign(t.env, { GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 's' });
    const { oidc } = await import('../../src/auth/oauth');
    vi.spyOn(oidc, 'exchangeCode').mockResolvedValue('t');
    vi.spyOn(oidc, 'verifyIdToken').mockResolvedValue({ provider: 'google', subject: 'gs', email: 'w@example.com', emailVerified: true, name: 'Wim' });
    const { cookiePair, setCookieOf } = await import('../helpers/auth');
    const start = await t.req('/auth/google/start?intent=signup');
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const cb = await t.req(`/auth/google/callback?state=${state}&code=c`, { cookie: cookiePair(start, 'auth_oauth') });
    const done = await t.req('/auth/signup/complete', { method: 'POST', cookie: cookiePair(cb, 'auth_signup'), body: new URLSearchParams({ name: 'Wim', username: 'wim' }) });
    expect(done.status).toBe(200);
    expect(await done.text()).toContain('waiting for approval');
    expect(setCookieOf(done, 'auth_session')).toBeUndefined();
    expect(await user(t.env.DB, 'wim')).toMatchObject({ approval: 'pending' });
  });

  it('invite-only needs invites(): a clear error at startup', async () => {
    const { createAuth } = await import('../../src/auth');
    const { admin } = await import('../../src/auth/modules');
    expect(() => createAuth({ appName: 'X', modules: [admin({ signupMode: 'invite-only' })] })).toThrow(/needs the invites\(\) module/);
  });

  it('invite-only: no signup without an invite or link (passkey and Google)', async () => {
    const t = moduleApp({ admin: { signupMode: 'invite-only' }, invites: true });
    Object.assign(t.env, { GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 's' });
    expect((await signupPasskey(t.req, { name: 'Ivan', username: 'ivan' })).json).toMatchObject({ error: { code: 'signup_invite_only' } });
    expect((await t.req('/auth/google/start?intent=signup')).status).toBe(403);
    expect(await count(t.env.DB, 'SELECT COUNT(*) AS n FROM users')).toBe(0);
  });

  it('open (default): accounts are active at once', async () => {
    const t = moduleApp({ admin: {} });
    const res = await signupPasskey(t.req, { name: 'Olga', username: 'olga' });
    expect(res.cookie).toBeTruthy();
    expect(await user(t.env.DB, 'olga')).toMatchObject({ status: 'active', approval: 'approved', role: 'user' });
  });
});

describe('admin actions', () => {
  async function world(mode: 'approval' | 'open' = 'approval') {
    const t = moduleApp({ admin: { signupMode: mode }, email: {} });
    const boss = await makeAdmin(t.env.DB);
    const cookie = await sessionCookie(t.env.DB, boss);
    return { t, boss, cookie };
  }

  it('only admins; every change needs step-up; a demoted admin loses access at once', async () => {
    const { t, boss, cookie } = await world();
    const plain = await insertUser(t.env.DB);
    expect((await t.req('/auth/api/admin/users', { cookie: await sessionCookie(t.env.DB, plain) })).status).toBe(403);
    expect((await t.req('/auth/admin', { cookie: await sessionCookie(t.env.DB, plain) })).status).toBe(403);
    expect((await t.req('/auth/admin')).status).toBe(302); // signed out: to the login page
    expect((await t.req('/auth/api/admin/users', { cookie })).status).toBe(200);
    const stale = await sessionCookie(t.env.DB, boss, 10 * 60_000);
    expect(await (await act(t, stale, plain.id, 'suspend', 1)).json()).toMatchObject({ error: { code: 'reauth_required' } });
    await t.env.DB.prepare("UPDATE users SET role = 'user' WHERE id = ?").bind(boss.id).run();
    expect((await t.req('/auth/api/admin/users', { cookie })).status).toBe(403);
  });

  it('approve: the user can sign in and is told by mail; reject: refused with its own reason', async () => {
    const { t, cookie } = await world();
    await signupPasskey(t.req, { name: 'Pia', username: 'pia', email: 'pia@example.com' });
    await t.req(new URL(linkIn(t.outbox.sent.find(m => m.to === 'pia@example.com')!.text)).pathname, { method: 'POST' }); // confirm the address
    const pia = (await user(t.env.DB, 'pia'))! as { id: string };
    const list = await (await t.req('/auth/api/admin/users?filter=pending', { cookie })).json() as { users: { id: string; state: string; accessVersion: number }[] };
    expect(list.users.map(u => [u.id, u.state])).toEqual([[pia.id, 'pending']]);
    t.outbox.sent.length = 0;
    const ok = await act(t, cookie, pia.id, 'approve', list.users[0]!.accessVersion);
    expect(await ok.json()).toEqual({ ok: true, state: 'active' });
    expect(t.outbox.sent).toEqual([expect.objectContaining({ to: 'pia@example.com', subject: expect.stringContaining('ready') })]);
    expect(await count(t.env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'admin-approve' AND target_user_id = ?", pia.id)).toBe(1);

    await signupPasskey(t.req, { name: 'Rex', username: 'rex' });
    const rex = (await user(t.env.DB, 'rex'))! as { id: string; access_version: number };
    expect(await (await act(t, cookie, rex.id, 'reject', rex.access_version)).json()).toEqual({ ok: true, state: 'rejected' });
    const pk = await t.env.DB.prepare('SELECT credential_id FROM passkeys WHERE user_id = ?').bind(rex.id).first<string>('credential_id');
    mockAuthentication();
    const login = await (await t.req('/auth/api/passkey/login/options', json({}))).json() as { flowId: string };
    expect(await (await t.req('/auth/api/passkey/login/verify', json({ flowId: login.flowId, response: credentialResponse(pk!) }))).json()).toMatchObject({ error: { code: 'account_rejected' } });
    // Reject only applies to waiting accounts.
    expect(await (await act(t, cookie, pia.id, 'reject', await version(t.env.DB, pia.id))).json()).toMatchObject({ error: { code: 'not_applicable' } });
  });

  it('optimistic concurrency: a stale version is refused, and of two admins acting at once only one wins', async () => {
    const { t, cookie } = await world();
    const boss2 = await makeAdmin(t.env.DB);
    const cookie2 = await sessionCookie(t.env.DB, boss2);
    await signupPasskey(t.req, { name: 'Quinn', username: 'quinn' });
    const q = (await user(t.env.DB, 'quinn'))! as { id: string; access_version: number };
    const [a, b] = await Promise.all([act(t, cookie, q.id, 'approve', q.access_version), act(t, cookie2, q.id, 'reject', q.access_version)]);
    const codes = [a.status, b.status].sort();
    expect(codes).toEqual([200, 409]);
    expect(await count(t.env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action LIKE 'admin-%' AND target_user_id = ?", q.id)).toBe(1);
    expect(await (await act(t, cookie, q.id, 'suspend', q.access_version)).json()).toMatchObject({ error: { code: 'stale' } });
    expect(await (await act(t, cookie, q.id, 'suspend', 'x')).json()).toMatchObject({ error: { code: 'version_required' } });
  });

  it('suspend ends every session; reactivate and sign out everywhere; admins and yourself are protected', async () => {
    const { t, boss, cookie } = await world('open');
    const u = await insertUser(t.env.DB);
    await insertPasskey(t.env.DB, u.id);
    const theirs = await sessionCookie(t.env.DB, u);
    expect((await act(t, cookie, u.id, 'suspend', await version(t.env.DB, u.id))).status).toBe(200);
    expect((await t.req('/auth/api/me', { cookie: theirs })).status).toBe(401);
    expect(await count(t.env.DB, 'SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?', u.id)).toBe(0);
    expect(await (await act(t, cookie, u.id, 'reactivate', await version(t.env.DB, u.id))).json()).toEqual({ ok: true, state: 'active' });
    const again = await sessionCookie(t.env.DB, u);
    expect((await act(t, cookie, u.id, 'sign-out', await version(t.env.DB, u.id))).status).toBe(200);
    expect((await t.req('/auth/api/me', { cookie: again })).status).toBe(401);
    const other = await makeAdmin(t.env.DB);
    expect(await (await act(t, cookie, other.id, 'suspend', await version(t.env.DB, other.id))).json()).toMatchObject({ error: { code: 'protected_account' } });
    expect(await (await act(t, cookie, boss.id, 'suspend', await version(t.env.DB, boss.id))).json()).toMatchObject({ error: { code: 'protected_account' } });
  });

  it('recovery link: mailed to a confirmed address and never shown to the admin (not even when mailing fails)', async () => {
    const { t, cookie } = await world('open');
    const withMail = await insertUser(t.env.DB);
    await t.env.DB.prepare("UPDATE users SET email = 'm@example.com', email_verified_at = 1 WHERE id = ?").bind(withMail.id).run();
    expect(await (await act(t, cookie, withMail.id, 'recovery-link', await version(t.env.DB, withMail.id))).json()).toEqual({ ok: true, mailed: true });
    expect(t.outbox.sent.at(-1)).toMatchObject({ to: 'm@example.com', subject: expect.stringContaining('Recover') });
    expect(await t.env.DB.prepare('SELECT mailed_to FROM recovery_tokens WHERE user_id = ? AND used_at IS NULL').bind(withMail.id).first('mailed_to')).toBe('m@example.com');
    // The per-recipient mail limit (5/hour) is reached: 429, no URL.
    for (let i = 0; i < 4; i++) await act(t, cookie, withMail.id, 'recovery-link', await version(t.env.DB, withMail.id));
    const limited = await act(t, cookie, withMail.id, 'recovery-link', await version(t.env.DB, withMail.id));
    expect(limited.status).toBe(429);
    expect(JSON.stringify(await limited.json())).not.toContain('/auth/recover/');
    // The mailer fails: 503, no URL.
    const broken = await insertUser(t.env.DB);
    await t.env.DB.prepare("UPDATE users SET email = 'b@example.com', email_verified_at = 1 WHERE id = ?").bind(broken.id).run();
    vi.spyOn(t.outbox, 'send').mockRejectedValue(new Error('down'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const failed = await act(t, cookie, broken.id, 'recovery-link', await version(t.env.DB, broken.id));
    expect(failed.status).toBe(503);
    expect(JSON.stringify(await failed.json())).not.toContain('/auth/recover/');
    vi.restoreAllMocks();
    // The admin page warns before taking over.
    expect(await (await t.req('/auth/admin', { cookie })).text()).toContain('You are about to take over this account');
    const noMail = await insertUser(t.env.DB);
    expect(await (await act(t, cookie, noMail.id, 'recovery-link', await version(t.env.DB, noMail.id))).json()).toEqual({ ok: true, mailed: false, url: expect.stringMatching(/\/auth\/recover\/[A-Za-z0-9_-]{43}$/) });
  });

  it('the admin page lists accounts (escaped) with their actions; the account page links to it', async () => {
    const { t, cookie } = await world();
    await signupPasskey(t.req, { name: '<b>Bad</b> name', username: 'badname' });
    const page = await (await t.req('/auth/admin', { cookie })).text();
    expect(page).toContain('&lt;b&gt;Bad&lt;/b&gt; name');
    expect(page).toMatch(/data-auth-api="\/auth\/api\/admin\/users\/[^/]+\/approve"/);
    expect(await (await t.req('/auth/account', { cookie })).text()).toContain('href="/auth/admin"');
  });

  it('core functions refuse pending accounts too (the module only explains)', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, u.id);
    await env.DB.prepare("UPDATE users SET status = 'suspended', approval = 'pending' WHERE id = ?").bind(u.id).run();
    mockAuthentication();
    expect(await finishLogin(env, (await startLogin(env)).flowId, credentialResponse(pk.credentialId))).toMatchObject({ ok: false, code: 'account_suspended', userId: u.id });
  });
});
