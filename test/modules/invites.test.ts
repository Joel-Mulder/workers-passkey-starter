import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuth } from '../../src/auth';
import { invites } from '../../src/auth/modules';
import { deleteOwnAccount } from '../../src/auth/account';
import { oidc } from '../../src/auth/oauth';
import { cookiePair, count } from '../helpers/auth';
import { acceptAnyRegistration, finishSignup, json, makeAdmin, moduleApp, pathOf, sessionCookie, signupPasskey, startSignup, user } from './helpers';

afterEach(() => vi.restoreAllMocks());

async function world(mode: 'approval' | 'invite-only' | 'open' = 'invite-only') {
  const t = moduleApp({ admin: { signupMode: mode }, email: {}, invites: true });
  const boss = await makeAdmin(t.env.DB);
  const cookie = await sessionCookie(t.env.DB, boss);
  const invite = async (email: string) => (await (await t.req('/auth/api/admin/invites', { ...json({ email }), cookie })).json()) as { ok: boolean; id: string; url: string; mailed: boolean; error?: { code: string } };
  const link = async (maxUses: number, days = 7) => (await (await t.req('/auth/api/admin/links', { ...json({ label: 'Class 2026', maxUses, days }), cookie })).json()) as { ok: boolean; id: string; url: string };
  const tokenOf = (url: string) => url.split('/').pop()!;
  return { t, boss, cookie, invite, link, tokenOf };
}

describe('invites', () => {
  it('invites() refuses to start without admin()', () => {
    expect(() => createAuth({ appName: 'X', modules: [invites()] })).toThrow(/needs the admin\(\) module/);
  });

  it('an admin invites an address: mailed, hashed, and the link leads to a signup with the address locked', async () => {
    const { t, invite, tokenOf } = await world();
    const inv = await invite('Ivy@Example.com');
    expect(inv).toMatchObject({ ok: true, mailed: true, url: expect.stringMatching(/\/auth\/invite\/[A-Za-z0-9_-]{43}$/) });
    expect(t.outbox.sent.at(-1)).toMatchObject({ to: 'ivy@example.com', subject: expect.stringContaining('invited') });
    expect(await count(t.env.DB, 'SELECT COUNT(*) AS n FROM invites WHERE token_hash = ?', tokenOf(inv.url))).toBe(0);
    const go = await t.req(pathOf(inv.url));
    expect(go.headers.get('location')).toBe(`/auth/signup?invite=${tokenOf(inv.url)}`);
    const page = await (await t.req(go.headers.get('location')!)).text();
    expect(page).toContain('value="ivy@example.com" readonly');
    expect(page).toContain(`name="invite" value="${tokenOf(inv.url)}"`);
  });

  it('signing up with an invite: active even in approval mode, the address is confirmed, the invite is used up', async () => {
    const { t, invite, tokenOf } = await world('approval');
    const token = tokenOf((await invite('ivy@example.com')).url);
    expect((await signupPasskey(t.req, { name: 'Ivy', username: 'ivy', email: 'other@example.com', invite: token })).json).toMatchObject({ error: { code: 'invite_email_mismatch' } });
    const res = await signupPasskey(t.req, { name: 'Ivy', username: 'ivy', email: 'ivy@example.com', invite: token });
    expect(res.cookie).toBeTruthy();
    expect(await user(t.env.DB, 'ivy')).toMatchObject({ status: 'active', approval: 'approved', email: 'ivy@example.com', email_verified_at: expect.any(Number) });
    expect(await count(t.env.DB, 'SELECT COUNT(*) AS n FROM email_verifications')).toBe(0); // no confirmation mail needed
    expect((await signupPasskey(t.req, { name: 'Ivy Two', username: 'ivy2', invite: token })).json).toMatchObject({ error: { code: 'invite_used' } });
    expect(await count(t.env.DB, "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'invite-used'")).toBe(1);
  });

  it('two signups racing for one invite: exactly one account, nothing left behind by the other', async () => {
    const { t, invite, tokenOf } = await world();
    const token = tokenOf((await invite('race@example.com')).url);
    acceptAnyRegistration();
    const a = await startSignup(t.req, { name: 'Racer A', username: 'racera', invite: token });
    const b = await startSignup(t.req, { name: 'Racer B', username: 'racerb', invite: token });
    expect([a.status, b.status]).toEqual([200, 200]); // both may start
    const [ra, rb] = await Promise.all([finishSignup(t.req, a.json.flowId, 'cred-a'), finishSignup(t.req, b.json.flowId, 'cred-b')]);
    const statuses = [ra.status, rb.status].sort();
    expect(statuses).toEqual([200, 409]);
    expect([ra.json, rb.json].find(j => !j.ok)).toMatchObject({ error: { code: 'invite_used' } });
    expect(await count(t.env.DB, "SELECT COUNT(*) AS n FROM users WHERE username IN ('racera', 'racerb')")).toBe(1);
    expect(await count(t.env.DB, "SELECT COUNT(*) AS n FROM passkeys WHERE credential_id IN ('cred-a', 'cred-b')")).toBe(1);
    // A retry of the winner's verify is idempotent, not "invite used".
    const winner = ra.status === 200 ? a : b;
    expect((await finishSignup(t.req, winner.json.flowId, ra.status === 200 ? 'cred-a' : 'cred-b')).status).toBe(200);
  });

  it('expired and withdrawn invites are refused; invites for existing addresses are not created', async () => {
    const { t, cookie, invite, tokenOf } = await world();
    const exp = await invite('late@example.com');
    await t.env.DB.prepare('UPDATE invites SET expires_at = 1 WHERE id = ?').bind(exp.id).run();
    expect((await signupPasskey(t.req, { name: 'Late', username: 'late', invite: tokenOf(exp.url) })).json).toMatchObject({ error: { code: 'invite_expired' } });
    expect((await t.req(pathOf(exp.url))).status).toBe(410);
    const w = await invite('gone@example.com');
    expect((await t.req(`/auth/api/admin/invites/${w.id}/revoke`, { method: 'POST', cookie })).status).toBe(200);
    expect((await signupPasskey(t.req, { name: 'Gone', username: 'gone', invite: tokenOf(w.url) })).json).toMatchObject({ error: { code: 'invite_invalid' } });
    await t.env.DB.prepare("UPDATE users SET email = 'taken@example.com', email_verified_at = 1 WHERE role = 'user' OR role = 'admin'").run();
    expect(await invite('taken@example.com')).toMatchObject({ error: { code: 'email_taken' } });
  });

  it('Google signup carries the invite through the provider round trip', async () => {
    const { t, invite, tokenOf } = await world();
    Object.assign(t.env, { GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 's' });
    const token = tokenOf((await invite('gina@example.com')).url);
    vi.spyOn(oidc, 'exchangeCode').mockResolvedValue('t');
    vi.spyOn(oidc, 'verifyIdToken').mockResolvedValue({ provider: 'google', subject: 'gsub', email: 'gina.private@example.com', emailVerified: true, name: 'Gina' });
    const start = await t.req(`/auth/google/start?intent=signup&invite=${token}`);
    expect(start.status).toBe(302);
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const cb = await t.req(`/auth/google/callback?state=${state}&code=c`, { cookie: cookiePair(start, 'auth_oauth') });
    const signup = cookiePair(cb, 'auth_signup')!;
    expect(await (await t.req('/auth/signup/complete', { cookie: signup })).text()).toContain('value="gina@example.com" readonly');
    const done = await t.req('/auth/signup/complete', { method: 'POST', cookie: signup, body: new URLSearchParams({ name: 'Gina', username: 'gina', email: 'gina@example.com' }) });
    expect(done.status).toBe(303);
    expect(await user(t.env.DB, 'gina')).toMatchObject({ email: 'gina@example.com', status: 'active' });
    expect(await t.env.DB.prepare('SELECT used_at FROM invites').first('used_at')).toEqual(expect.any(Number));
    // Without a token, invite-only refuses before leaving for Google.
    expect((await t.req('/auth/google/start?intent=signup')).status).toBe(403);
  });
});

describe('signup links', () => {
  it('a link takes up to max uses; racing for the last place creates exactly one account', async () => {
    const { t, link, tokenOf } = await world();
    const l = await link(2);
    const token = tokenOf(l.url);
    expect((await t.req(pathOf(l.url))).headers.get('location')).toBe(`/auth/signup?link=${token}`);
    expect((await signupPasskey(t.req, { name: 'First', username: 'first', link: token })).cookie).toBeTruthy();
    acceptAnyRegistration();
    const flows = await Promise.all(['xx1', 'xx2', 'xx3'].map(u => startSignup(t.req, { name: `User ${u}`, username: u, link: token })));
    expect(flows.every(f => f.status === 200)).toBe(true);
    const done = await Promise.all(flows.map((f, i) => finishSignup(t.req, f.json.flowId, `cred-x${i}`)));
    expect(done.filter(d => d.status === 200)).toHaveLength(1);
    expect(done.filter(d => d.status === 409).map(d => (d.json as { error: { code: string } }).error.code)).toEqual(['link_full', 'link_full']);
    expect(await t.env.DB.prepare('SELECT used_count FROM signup_links WHERE id = ?').bind(l.id).first('used_count')).toBe(2);
    expect(await count(t.env.DB, "SELECT COUNT(*) AS n FROM users WHERE username IN ('first', 'xx1', 'xx2', 'xx3')")).toBe(2);
  });

  it('a deleted account never gives its place back', async () => {
    const { t, link, tokenOf, cfg } = { ...(await world()), cfg: undefined };
    void cfg;
    const l = await link(1);
    await signupPasskey(t.req, { name: 'Del', username: 'del', link: tokenOf(l.url) });
    const del = (await user(t.env.DB, 'del'))! as { id: string };
    expect((await deleteOwnAccount(t.env.DB, t.cfg, del.id, 'del')).ok).toBe(true);
    expect((await signupPasskey(t.req, { name: 'Next', username: 'next', link: tokenOf(l.url) })).json).toMatchObject({ error: { code: 'link_full' } });
  });

  it('withdrawn and expired links are refused; links signups are active in approval mode', async () => {
    const { t, cookie, link, tokenOf } = await world('approval');
    const l = await link(5);
    const res = await signupPasskey(t.req, { name: 'Linda', username: 'linda', link: tokenOf(l.url) });
    expect(res.cookie).toBeTruthy();
    expect(await user(t.env.DB, 'linda')).toMatchObject({ status: 'active', approval: 'approved' });
    expect((await t.req(`/auth/api/admin/links/${l.id}/revoke`, { method: 'POST', cookie })).status).toBe(200);
    expect((await signupPasskey(t.req, { name: 'Late', username: 'late', link: tokenOf(l.url) })).json).toMatchObject({ error: { code: 'link_closed' } });
    const old = await link(5);
    await t.env.DB.prepare('UPDATE signup_links SET expires_at = 1 WHERE id = ?').bind(old.id).run();
    expect((await signupPasskey(t.req, { name: 'Old', username: 'old', link: tokenOf(old.url) })).json).toMatchObject({ error: { code: 'link_expired' } });
  });

  it('validates link settings, limits attempts per link, and refuses invite + link together', async () => {
    const { t, cookie, link, invite, tokenOf } = await world();
    expect(await (await t.req('/auth/api/admin/links', { ...json({ label: '', maxUses: 1, days: 1 }), cookie })).json()).toMatchObject({ error: { code: 'invalid_label' } });
    expect(await (await t.req('/auth/api/admin/links', { ...json({ label: 'x', maxUses: 0, days: 1 }), cookie })).json()).toMatchObject({ error: { code: 'invalid_uses' } });
    expect(await (await t.req('/auth/api/admin/links', { ...json({ label: 'x', maxUses: 1, days: 365 }), cookie })).json()).toMatchObject({ error: { code: 'invalid_days' } });
    const l = await link(1000);
    const token = tokenOf(l.url);
    const inv = await invite('both@example.com');
    expect((await startSignup(t.req, { name: 'Both', username: 'both', invite: tokenOf(inv.url), link: token })).json).toMatchObject({ error: { code: 'bad_request' } });
    // Per link, across networks (each probe from another IP, so the per-IP limit isn't what stops it).
    for (let i = 0; i < 60; i++) await t.req('/auth/api/signup/options', { ...json({ name: 'Probe', username: `taken${i}`, link: token }), ip: `198.51.100.${i}` });
    expect(await (await t.req('/auth/api/signup/options', { ...json({ name: 'Probe', username: 'probe', link: token }), ip: '203.0.113.200' })).json()).toMatchObject({ error: { code: 'rate_limited', message: expect.stringContaining('this link') } });
  });

  it('the admin page shows the invite and link forms', async () => {
    const { t, cookie } = await world();
    const page = await (await t.req('/auth/admin', { cookie })).text();
    expect(page).toContain('data-auth-api="/auth/api/admin/invites"');
    expect(page).toContain('data-auth-api="/auth/api/admin/links"');
  });
});
