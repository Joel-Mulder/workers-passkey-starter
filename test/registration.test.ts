import { afterEach, describe, expect, it, vi } from 'vitest';
import { completeOAuthSignup, finishPasskeySignup, registerAccount, startOAuthSignup, startPasskeySignup } from '../src/auth/registration';
import { count, fakePasskey, insertUser, makeCfg, makeEnv, mockRegistration } from './helpers/auth';

afterEach(() => vi.restoreAllMocks());
const cfg = makeCfg();
const response = (id: string) => ({ id, rawId: id, type: 'public-key', response: {} });

describe('passkey signup', () => {
  it('validates, checks the username, then creates user + passkey + audit row in one batch', async () => {
    const env = makeEnv();
    expect(await startPasskeySignup(env, cfg, { name: 'A', username: 'anna' })).toMatchObject({ ok: false, code: 'invalid_name' });
    await insertUser(env.DB, { username: 'taken' });
    expect(await startPasskeySignup(env, cfg, { name: 'Anna', username: 'Taken' })).toMatchObject({ ok: false, code: 'username_taken' });

    const s = await startPasskeySignup(env, cfg, { name: 'Anna Smit', username: 'Anna' });
    if (!s.ok) throw new Error('expected options');
    expect(s.options.user.name).toBe('anna');
    expect(s.options.user.displayName).toBe('Anna Smit');
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM users')).toBe(1); // nothing created yet
    mockRegistration('cred-1');
    const r = await finishPasskeySignup(env, cfg, s.flowId, response('cred-1'));
    expect(r.ok && r.user).toMatchObject({ username: 'anna', name: 'Anna Smit', status: 'active' });
    // The WebAuthn user handle is the user id.
    expect(r.ok && Buffer.from(s.options.user.id, 'base64url').toString()).toBe(r.ok && r.user.id);
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM passkeys WHERE credential_id = 'cred-1'")).toBe(1);
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'account-created'")).toBe(1);
    // A retry of the same verify is idempotent.
    const again = await finishPasskeySignup(env, cfg, s.flowId, response('cred-1'));
    expect(again.ok && again.idempotent).toBe(true);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM users')).toBe(2);
  });

  it('a username taken between options and verify creates nothing', async () => {
    const env = makeEnv();
    const s = await startPasskeySignup(env, cfg, { name: 'Bob', username: 'bob' });
    if (!s.ok) throw new Error();
    await insertUser(env.DB, { username: 'bob' });
    mockRegistration('cred-2');
    expect(await finishPasskeySignup(env, cfg, s.flowId, response('cred-2'))).toMatchObject({ ok: false, code: 'username_taken' });
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM passkeys')).toBe(0);
  });

  it('a credential that already belongs to someone else is refused', async () => {
    const env = makeEnv();
    const other = await insertUser(env.DB);
    const pk = fakePasskey({ credentialId: 'shared-cred' });
    expect((await registerAccount(env, cfg, { userId: other.id + '-x', profile: { name: 'X', username: 'xx1' }, credential: { kind: 'passkey', passkey: pk } })).ok).toBe(true);
    const r = await registerAccount(env, cfg, { userId: crypto.randomUUID(), profile: { name: 'Y', username: 'yy1' }, credential: { kind: 'passkey', passkey: pk } });
    expect(r).toMatchObject({ ok: false, code: 'credential_taken' });
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM users WHERE username = 'yy1'")).toBe(0);
  });

  it('no audit rows with audit: false', async () => {
    const env = makeEnv();
    const quiet = makeCfg({ audit: false });
    await env.DB.exec('DROP TABLE audit_log');
    const r = await registerAccount(env, quiet, { userId: crypto.randomUUID(), profile: { name: 'Q', username: 'quiet' }, credential: { kind: 'passkey', passkey: fakePasskey() } });
    expect(r.ok).toBe(true);
  });
});

describe('Google/Apple signup', () => {
  const identity = { provider: 'google' as const, subject: 'sub-1', email: 'anna@example.com', emailVerified: true, name: 'Anna' };

  it('a verified identity becomes an account once the user picks a username; retries are idempotent', async () => {
    const env = makeEnv();
    const flowId = await startOAuthSignup(env.DB, identity);
    expect(await completeOAuthSignup(env, cfg, flowId, { name: 'Anna', username: 'A' })).toMatchObject({ ok: false, code: 'invalid_username' });
    const ok = await completeOAuthSignup(env, cfg, flowId, { name: 'Anna', username: 'anna' });
    expect(ok.ok && ok.idempotent).toBe(false);
    expect(await env.DB.prepare("SELECT email, email_verified FROM oauth_identities WHERE subject = 'sub-1'").first()).toEqual({ email: 'anna@example.com', email_verified: 1 });
    const again = await completeOAuthSignup(env, cfg, flowId, { name: 'Anna', username: 'anna' });
    expect(again.ok && again.idempotent).toBe(true);
    // The same identity can't create a second account.
    const second = await startOAuthSignup(env.DB, identity);
    expect(await completeOAuthSignup(env, cfg, second, { name: 'Anna', username: 'anna2' })).toMatchObject({ ok: false, code: 'credential_taken' });
  });
});
