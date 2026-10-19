import { afterEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import worker, { auth } from '../src/index';
import { createAuth, type AuthEnv } from '../src/auth';
import { deleteOwnAccount } from '../src/auth/account';
import { finishRecovery, inspectRecovery, issueRecoveryLink, RECOVERY_STARTS_PER_TOKEN, startRecovery } from '../src/auth/recovery';
import { insertSession, resolveSession } from '../src/auth/session';
import { webauthn } from '../src/auth/passkeys';
import { client, cookiePair, count, insertIdentity, insertPasskey, insertUser, makeCfg, makeEnv, mockRegistration, ORIGIN, setCookieOf } from './helpers/auth';

afterEach(() => vi.restoreAllMocks());
const cfg = makeCfg();
const json = (body: unknown) => ({ method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } });
const regResponse = (id: string) => ({ id, rawId: id, type: 'public-key', response: {} });
const tokenOf = (url: string) => url.split('/auth/recover/')[1]!;

describe('recovery links', () => {
  it('issueRecoveryLink stores only a hash, replaces older links and refuses suspended or missing users', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const first = await issueRecoveryLink(env, cfg, u.id);
    if (!first.ok) throw new Error();
    expect(first.url).toMatch(new RegExp(`^${ORIGIN}/auth/recover/[A-Za-z0-9_-]{43}$`));
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM recovery_tokens WHERE token_hash = ?', tokenOf(first.url))).toBe(0);
    const second = await issueRecoveryLink(env, cfg, u.id);
    if (!second.ok) throw new Error();
    expect((await inspectRecovery(env.DB, tokenOf(first.url))).ok).toBe(false);
    expect((await inspectRecovery(env.DB, tokenOf(second.url))).ok).toBe(true);
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'recovery-issued'")).toBe(2);

    const suspended = await insertUser(env.DB, { status: 'suspended' });
    expect(await issueRecoveryLink(env, cfg, suspended.id)).toMatchObject({ ok: false, code: 'recovery_not_allowed' });
    expect(await issueRecoveryLink(env, cfg, crypto.randomUUID())).toMatchObject({ ok: false, code: 'recovery_not_allowed' });
    // The basePath is part of the URL.
    expect((await issueRecoveryLink(env, makeCfg({ basePath: '/app' }), u.id) as { url: string }).url).toContain(`${ORIGIN}/app/auth/recover/`);
  });

  it('expires after 15 minutes', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const link = await issueRecoveryLink(env, cfg, u.id) as { url: string };
    expect((await inspectRecovery(env.DB, tokenOf(link.url), Date.now() + 14 * 60_000)).ok).toBe(true);
    expect((await inspectRecovery(env.DB, tokenOf(link.url), Date.now() + 16 * 60_000)).ok).toBe(false);
  });

  it('finishing replaces every passkey, ends every session, unlinks Google/Apple and is single use', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const other = await insertUser(env.DB);
    await insertPasskey(env.DB, u.id);
    await insertPasskey(env.DB, u.id);
    await insertIdentity(env.DB, u.id);
    const s1 = await insertSession(env.DB, cfg, u, 'passkey');
    const otherSession = await insertSession(env.DB, cfg, other, 'passkey');
    const link = await issueRecoveryLink(env, cfg, u.id) as { url: string };
    const spare = await issueRecoveryLink(env, cfg, other.id) as { url: string };

    const start = await startRecovery(env, cfg, tokenOf(link.url));
    if (!start.ok) throw new Error();
    expect(start.options.user.name).toBe(u.username);
    mockRegistration('recovered-cred');
    const fin = await finishRecovery(env, cfg, start.flowId, regResponse('recovered-cred'));
    expect(fin.ok).toBe(true);
    expect((await env.DB.prepare('SELECT credential_id FROM passkeys WHERE user_id = ?').bind(u.id).all<{ credential_id: string }>()).results).toEqual([{ credential_id: 'recovered-cred' }]);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM oauth_identities WHERE user_id = ?', u.id)).toBe(0);
    expect((await resolveSession(env.DB, cfg, s1.token)).session).toBeNull();
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'recovery-completed'")).toBe(1);
    // Other users are untouched.
    expect((await resolveSession(env.DB, cfg, otherSession.token)).session).not.toBeNull();
    expect((await inspectRecovery(env.DB, tokenOf(spare.url))).ok).toBe(true);
    // Single use.
    expect(await startRecovery(env, cfg, tokenOf(link.url))).toMatchObject({ ok: false, code: 'recovery_invalid' });
  });

  it('two flows finishing in the same millisecond: only the first stores its passkey', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    await insertPasskey(env.DB, u.id, { credentialId: 'old' });
    const link = await issueRecoveryLink(env, cfg, u.id) as { url: string };
    const a = await startRecovery(env, cfg, tokenOf(link.url));
    const b = await startRecovery(env, cfg, tokenOf(link.url));
    if (!a.ok || !b.ok) throw new Error();
    const at = Date.now();
    mockRegistration('cred-a');
    expect((await finishRecovery(env, cfg, a.flowId, regResponse('cred-a'), at)).ok).toBe(true);
    vi.restoreAllMocks();
    mockRegistration('cred-b');
    // B fails: its flow went with A's cleanup, and even a flow taken earlier can't pass the used_by_flow guard.
    expect((await finishRecovery(env, cfg, b.flowId, regResponse('cred-b'), at)).ok).toBe(false);
    expect((await env.DB.prepare('SELECT credential_id FROM passkeys WHERE user_id = ?').bind(u.id).all<{ credential_id: string }>()).results).toEqual([{ credential_id: 'cred-a' }]);
  });

  it('two flows already in flight at once: the token guard lets only one write', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const link = await issueRecoveryLink(env, cfg, u.id) as { url: string };
    const a = await startRecovery(env, cfg, tokenOf(link.url));
    const b = await startRecovery(env, cfg, tokenOf(link.url));
    if (!a.ok || !b.ok) throw new Error();
    const pending: (() => void)[] = [];
    vi.spyOn(webauthn, 'verifyRegistrationResponse').mockImplementation(() => new Promise(res => {
      const id = pending.length === 0 ? 'cred-a' : 'cred-b';
      pending.push(() => res({ verified: true, registrationInfo: { fmt: 'none', aaguid: '00000000-0000-0000-0000-000000000000', credentialType: 'public-key', attestationObject: new Uint8Array(), userVerified: true, credentialDeviceType: 'multiDevice', credentialBackedUp: true, origin: ORIGIN, rpID: 'localhost', credential: { id, publicKey: new Uint8Array([1]), counter: 0, transports: [] } } } as never));
    }));
    const at = Date.now();
    const pa = finishRecovery(env, cfg, a.flowId, regResponse('cred-a'), at);
    const pb = finishRecovery(env, cfg, b.flowId, regResponse('cred-b'), at);
    while (pending.length < 2) await new Promise(r => setTimeout(r, 0));
    pending[0]!();
    pending[1]!();
    const results = [await pa, await pb];
    expect(results.filter(r => r.ok)).toHaveLength(1);
    expect(results.find(r => !r.ok)).toMatchObject({ code: 'recovery_invalid' });
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?', u.id)).toBe(1);
  });

  it('a failed passkey check or a suspended account changes nothing', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    await insertPasskey(env.DB, u.id, { credentialId: 'keep' });
    const link = await issueRecoveryLink(env, cfg, u.id) as { url: string };
    vi.spyOn(webauthn, 'verifyRegistrationResponse').mockResolvedValue({ verified: false } as never);
    const a = await startRecovery(env, cfg, tokenOf(link.url));
    expect(await finishRecovery(env, cfg, a.ok ? a.flowId : '', regResponse('x'))).toMatchObject({ ok: false, code: 'passkey_invalid' });
    vi.restoreAllMocks();
    const b = await startRecovery(env, cfg, tokenOf(link.url));
    await env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(u.id).run();
    mockRegistration('new');
    expect(await finishRecovery(env, cfg, b.ok ? b.flowId : '', regResponse('new'))).toMatchObject({ ok: false, code: 'account_suspended' });
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM passkeys WHERE credential_id = 'keep'")).toBe(1);
  });

  it('limits ceremony starts per link', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const token = tokenOf((await issueRecoveryLink(env, cfg, u.id) as { url: string }).url);
    for (let i = 0; i < RECOVERY_STARTS_PER_TOKEN; i++) expect((await startRecovery(env, cfg, token)).ok).toBe(true);
    expect(await startRecovery(env, cfg, token)).toMatchObject({ ok: false, code: 'rate_limited' });
  });

  it('over HTTP: page → options → verify → signed in, with no-referrer on the token page', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB, { name: 'Rita' });
    await insertPasskey(env.DB, u.id);
    const link = await auth.issueRecoveryLink(env, u.id);
    if (!link.ok) throw new Error();
    const req = client(worker.fetch, env);
    const page = await req(`/auth/recover/${tokenOf(link.url)}`);
    expect(page.status).toBe(200);
    expect(page.headers.get('referrer-policy')).toBe('no-referrer');
    expect(await page.text()).toContain('data-passkey-recover');
    expect((await req('/auth/recover/not-a-token')).status).toBe(400);
    mockRegistration('http-cred');
    const opts = await (await req('/auth/api/recovery/options', json({ token: tokenOf(link.url) }))).json() as { flowId: string };
    const res = await req('/auth/api/recovery/verify', json({ flowId: opts.flowId, response: regResponse('http-cred') }));
    expect(await res.json()).toMatchObject({ ok: true, redirect: '/auth/account', acceptedCredentialIds: ['http-cred'], displayName: 'Rita' });
    expect((await req('/auth/api/me', { cookie: cookiePair(res, 'auth_session') })).status).toBe(200);
  });
});

describe('deleting your own account', () => {
  it('needs the exact username; deletes the user and everything that cascades; keeps the audit row', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const other = await insertUser(env.DB);
    await insertPasskey(env.DB, u.id);
    await insertIdentity(env.DB, u.id);
    await insertSession(env.DB, cfg, u, 'passkey');
    await insertSession(env.DB, cfg, other, 'passkey');
    await issueRecoveryLink(env, cfg, u.id);
    await env.DB.prepare("INSERT INTO auth_flows (id, kind, data, user_id, expires_at, created_at) VALUES ('flow-of-u-123456', 'reauth', '{}', ?, ?, 0)").bind(u.id, Date.now() + 60_000).run();

    expect(await deleteOwnAccount(env.DB, cfg, u.id, 'someone-else')).toMatchObject({ ok: false, code: 'confirm_mismatch' });
    expect((await deleteOwnAccount(env.DB, cfg, u.id, ` ${u.username.toUpperCase()} `)).ok).toBe(true);
    for (const table of ['users WHERE id', 'passkeys WHERE user_id', 'oauth_identities WHERE user_id', 'sessions WHERE user_id', 'recovery_tokens WHERE user_id', 'auth_flows WHERE user_id']) {
      expect(await count(env.DB, `SELECT COUNT(*) AS n FROM ${table} = ?`, u.id)).toBe(0);
    }
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'account-deleted' AND target_user_id = ?", u.id)).toBe(1);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?', other.id)).toBe(1);
    expect(await deleteOwnAccount(env.DB, cfg, u.id, u.username)).toMatchObject({ ok: false, code: 'not_found' });
  });

  it('over HTTP: fresh auth required, cookie cleared, onUserDeleted called, signal data returned', async () => {
    const deleted = vi.fn();
    const a = createAuth({ appName: 'Del', onUserDeleted: deleted });
    const app = new Hono<AuthEnv>();
    app.use('*', a.securityHeaders, a.bodyLimit, a.originCheck, a.session);
    app.route('/', a.routes);
    const env = makeEnv();
    const u = await insertUser(env.DB);
    await insertPasskey(env.DB, u.id);
    const req = client((r, e) => app.fetch(r, e), env);
    const stale = await insertSession(env.DB, cfg, u, 'passkey', Date.now() - 10 * 60_000);
    const denied = await req('/auth/api/account/delete', { ...json({ username: u.username }), cookie: `auth_session=${stale.token}` });
    expect(await denied.json()).toMatchObject({ error: { code: 'reauth_required' } });
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM users WHERE id = ?', u.id)).toBe(1);

    const here = await insertSession(env.DB, cfg, u, 'passkey');
    const wrong = await req('/auth/api/account/delete', { ...json({ username: 'nope' }), cookie: `auth_session=${here.token}` });
    expect(wrong.status).toBe(422);
    const ok = await req('/auth/api/account/delete', { ...json({ username: u.username }), cookie: `auth_session=${here.token}` });
    expect(await ok.json()).toEqual({ ok: true, redirect: '/', rpId: 'localhost', userId: Buffer.from(u.id).toString('base64url') });
    expect(setCookieOf(ok, 'auth_session')).toMatch(/Max-Age=0/);
    expect(deleted).toHaveBeenCalledWith(expect.objectContaining({ userId: u.id, username: u.username }));
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM users')).toBe(0);
  });

  it('the account page has the delete form', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    await insertPasskey(env.DB, u.id);
    const s = await insertSession(env.DB, cfg, u, 'passkey');
    const body = await (await client(worker.fetch, env)('/auth/account', { cookie: `auth_session=${s.token}` })).text();
    expect(body).toContain(`data-account-delete data-username="${u.username}"`);
  });
});
