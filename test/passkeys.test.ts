import { afterEach, describe, expect, it, vi } from 'vitest';
import { deletePasskey, finishAddPasskey, finishLogin, finishReauth, renamePasskey, startAddPasskey, startLogin, startReauth, webauthn } from '../src/auth/passkeys';
import { unlinkIdentity } from '../src/auth/account';
import { insertSession } from '../src/auth/session';
import { count, credentialResponse, insertIdentity, insertPasskey, insertUser, makeCfg, makeEnv, mockAuthentication, mockRegistration, ORIGIN } from './helpers/auth';

afterEach(() => vi.restoreAllMocks());
const cfg = makeCfg();
const b64 = (v: string) => Buffer.from(v, 'utf8').toString('base64url');

describe('passkey login', () => {
  it('uses discoverable options (empty allowCredentials) and a single-use flow', async () => {
    const env = makeEnv();
    const s = await startLogin(env);
    expect(s.options.allowCredentials).toEqual([]);
    expect(s.options.rpId).toBe('localhost');
    expect(s.options.userVerification).toBe('required');
    const r = await finishLogin(env, s.flowId, credentialResponse('nope'));
    expect(r).toMatchObject({ ok: false, status: 404, code: 'unknown_credential', credentialId: 'nope', rpId: 'localhost' });
    // The flow was consumed.
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM auth_flows')).toBe(0);
    expect(await finishLogin(env, s.flowId, credentialResponse('nope'))).toMatchObject({ ok: false, code: 'flow_expired' });
  });

  it('rejects an expired flow', async () => {
    const env = makeEnv();
    const s = await startLogin(env);
    const r = await finishLogin(env, s.flowId, credentialResponse('x'), Date.now() + 11 * 60_000);
    expect(r).toMatchObject({ ok: false, code: 'flow_expired' });
  });

  it('only allows signalUnknownCredential for provably orphaned passkeys', async () => {
    const env = makeEnv();
    const attempt = async (userHandle?: string) => {
      const s = await startLogin(env);
      return finishLogin(env, s.flowId, credentialResponse('gone', userHandle)) as Promise<{ signalUnknown?: boolean }>;
    };
    // No user handle, or one that isn't one of our ids (another app sharing the RP ID): never.
    expect((await attempt()).signalUnknown).toBe(false);
    expect((await attempt(b64('someone@other-app'))).signalUnknown).toBe(false);
    expect((await attempt('***')).signalUnknown).toBe(false);
    // Our id of an account that still exists (the passkey was removed elsewhere): no.
    const live = await insertUser(env.DB);
    expect((await attempt(b64(live.id))).signalUnknown).toBe(false);
    // Our id, no such account: yes.
    expect((await attempt(b64(crypto.randomUUID()))).signalUnknown).toBe(true);
  });

  it('verifies against APP_ORIGIN + RP ID with user verification, updates the counter and last use', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const a = await insertPasskey(env.DB, user.id);
    await insertPasskey(env.DB, user.id);
    const spy = mockAuthentication({ newCounter: 7 });
    const s = await startLogin(env);
    const r = await finishLogin(env, s.flowId, credentialResponse(a.credentialId));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.user.id).toBe(user.id);
    expect(r.acceptedCredentialIds).toHaveLength(2);
    expect(spy.mock.calls[0]![0]).toMatchObject({ expectedOrigin: ORIGIN, expectedRPID: 'localhost', requireUserVerification: true });
    const row = await env.DB.prepare('SELECT counter, last_used_at FROM passkeys WHERE id = ?').bind(a.id).first<{ counter: number; last_used_at: number }>();
    expect(row).toMatchObject({ counter: 7, last_used_at: expect.any(Number) });
  });

  it('blocks suspended accounts and failed signatures', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB, { status: 'suspended' });
    const pk = await insertPasskey(env.DB, user.id);
    mockAuthentication();
    expect(await finishLogin(env, (await startLogin(env)).flowId, credentialResponse(pk.credentialId))).toMatchObject({ ok: false, code: 'account_suspended' });

    const ok = await insertUser(env.DB);
    const pk2 = await insertPasskey(env.DB, ok.id);
    vi.restoreAllMocks();
    mockAuthentication({ verified: false });
    expect(await finishLogin(env, (await startLogin(env)).flowId, credentialResponse(pk2.credentialId))).toMatchObject({ ok: false, code: 'passkey_invalid' });
  });

  it('rejects malformed responses without calling the verifier', async () => {
    const env = makeEnv();
    const spy = mockAuthentication();
    for (const bad of [null, 'x', { id: '' }, { id: 'a', type: 'password', response: {} }]) {
      expect(await finishLogin(env, (await startLogin(env)).flowId, bad)).toMatchObject({ ok: false, code: 'passkey_invalid' });
    }
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('the signature counter never moves backwards', () => {
  const tick = () => new Promise(r => setTimeout(r, 0));

  it('concurrent logins: a slower assertion with a lower counter does not overwrite a higher one', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, u.id, { counter: 10 });
    const pending: { resolve: () => void }[] = [];
    vi.spyOn(webauthn, 'verifyAuthenticationResponse').mockImplementation(() => new Promise(res => {
      const counter = pending.length === 0 ? 11 : 12;
      pending.push({ resolve: () => res({ verified: true, authenticationInfo: { credentialID: 'x', newCounter: counter, userVerified: true, credentialDeviceType: 'multiDevice', credentialBackedUp: true, origin: ORIGIN, rpID: 'localhost' } } as never) });
    }));
    const s1 = await startLogin(env), s2 = await startLogin(env);
    const p11 = finishLogin(env, s1.flowId, credentialResponse(pk.credentialId));
    const p12 = finishLogin(env, s2.flowId, credentialResponse(pk.credentialId));
    while (pending.length < 2) await tick();
    pending[1]!.resolve(); // counter 12 finishes first
    expect((await p12).ok).toBe(true);
    pending[0]!.resolve(); // counter 11 later
    await p11;
    expect(await env.DB.prepare('SELECT counter FROM passkeys WHERE id = ?').bind(pk.id).first('counter')).toBe(12);
  });

  it('zero-counter (synced) passkeys keep working and stay at 0', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const synced = await insertPasskey(env.DB, u.id, { counter: 0 });
    mockAuthentication({ newCounter: 0 });
    expect((await finishLogin(env, (await startLogin(env)).flowId, credentialResponse(synced.credentialId))).ok).toBe(true);
    expect(await env.DB.prepare('SELECT counter FROM passkeys WHERE id = ?').bind(synced.id).first('counter')).toBe(0);
  });
});

describe('managing passkeys', () => {
  it('never removes the last way to sign in (passkeys and linked identities count together)', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const a = await insertPasskey(env.DB, user.id);
    const b = await insertPasskey(env.DB, user.id);
    expect((await deletePasskey(env.DB, cfg, user.id, a.id)).ok).toBe(true);
    expect(await deletePasskey(env.DB, cfg, user.id, b.id)).toMatchObject({ ok: false, code: 'last_sign_in_method' });
    // With Google linked, the last passkey may go.
    const idp = await insertIdentity(env.DB, user.id);
    expect((await deletePasskey(env.DB, cfg, user.id, b.id)).ok).toBe(true);
    expect(await unlinkIdentity(env.DB, cfg, user.id, idp)).toMatchObject({ ok: false, code: 'last_sign_in_method' });
    // Someone else's passkey is "not found".
    const other = await insertUser(env.DB);
    const c = await insertPasskey(env.DB, user.id);
    expect(await deletePasskey(env.DB, cfg, other.id, c.id)).toMatchObject({ ok: false, code: 'not_found' });
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'passkey-removed'")).toBe(2);
  });

  it('removing a passkey or unlinking Google/Apple signs out the other sessions, not this one', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const other = await insertUser(env.DB);
    const a = await insertPasskey(env.DB, user.id);
    await insertPasskey(env.DB, user.id);
    const idp = await insertIdentity(env.DB, user.id);
    const sessions = async () => {
      const u = (await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first())!;
      const here = await insertSession(env.DB, cfg, u as never, 'passkey');
      await insertSession(env.DB, cfg, u as never, 'passkey');
      await insertSession(env.DB, cfg, u as never, 'google');
      return here.info.id;
    };
    const elsewhere = await insertSession(env.DB, cfg, other, 'passkey');
    const live = () => env.DB.prepare('SELECT id FROM sessions WHERE user_id = ?').bind(user.id).all<{ id: string }>().then(r => r.results.map(x => x.id));

    let here = await sessions();
    // A failed delete leaves the sessions alone.
    expect((await deletePasskey(env.DB, cfg, user.id, 'nope', Date.now(), here)).ok).toBe(false);
    expect(await live()).toHaveLength(3);
    expect((await deletePasskey(env.DB, cfg, user.id, a.id, Date.now(), here)).ok).toBe(true);
    expect(await live()).toEqual([here]);

    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
    here = await sessions();
    expect((await unlinkIdentity(env.DB, cfg, user.id, idp, Date.now() + 1, here)).ok).toBe(true);
    expect(await live()).toEqual([here]);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions WHERE id = ?', elsewhere.info.id)).toBe(1);
  });

  it('adds a passkey (excludeCredentials lists existing ones) and names it after the provider', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, user.id);
    const start = await startAddPasskey(env, cfg, user);
    expect(start.options.excludeCredentials?.map(c => c.id)).toEqual([pk.credentialId]);
    expect(start.options.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' });
    expect(start.options.rp).toEqual({ name: 'Test App', id: 'localhost' });
    mockRegistration('new-cred');
    const fin = await finishAddPasskey(env, cfg, user.id, start.flowId, { id: 'new-cred', rawId: 'new-cred', type: 'public-key', response: {} });
    expect(fin.ok && fin.passkey.name).toBe('iCloud Keychain');
    // Another user can't finish this user's flow.
    const other = await insertUser(env.DB);
    const s2 = await startAddPasskey(env, cfg, user);
    expect(await finishAddPasskey(env, cfg, other.id, s2.flowId, { id: 'x', rawId: 'x', type: 'public-key', response: {} })).toMatchObject({ ok: false, code: 'flow_expired' });
  });

  it('renames only own passkeys, 1–60 characters', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const other = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, user.id);
    expect((await renamePasskey(env.DB, user.id, pk.id, '  Work   laptop ')).ok).toBe(true);
    expect(await env.DB.prepare('SELECT name FROM passkeys WHERE id = ?').bind(pk.id).first('name')).toBe('Work laptop');
    expect(await renamePasskey(env.DB, user.id, pk.id, '')).toMatchObject({ ok: false, code: 'invalid_name' });
    expect(await renamePasskey(env.DB, user.id, pk.id, 'x'.repeat(61))).toMatchObject({ ok: false, code: 'invalid_name' });
    expect(await renamePasskey(env.DB, other.id, pk.id, 'Mine')).toMatchObject({ ok: false, code: 'not_found' });
  });
});

describe('step-up', () => {
  it('re-auths only with the user’s own passkeys; no passkey → no_passkey', async () => {
    const env = makeEnv();
    const user = await insertUser(env.DB);
    const pk = await insertPasskey(env.DB, user.id);
    const other = await insertUser(env.DB);
    const otherPk = await insertPasskey(env.DB, other.id);
    mockAuthentication();
    const re = await startReauth(env, user.id);
    if (!re.ok) throw new Error('expected options');
    expect(re.options.allowCredentials?.map(c => c.id)).toEqual([pk.credentialId]);
    expect(await finishReauth(env, user.id, re.flowId, credentialResponse(otherPk.credentialId))).toMatchObject({ ok: false, code: 'passkey_not_yours' });
    const re2 = await startReauth(env, user.id);
    expect((await finishReauth(env, user.id, re2.ok ? re2.flowId : '', credentialResponse(pk.credentialId))).ok).toBe(true);

    const noPasskey = await insertUser(env.DB);
    expect(await startReauth(env, noPasskey.id)).toMatchObject({ ok: false, code: 'no_passkey' });
  });
});
