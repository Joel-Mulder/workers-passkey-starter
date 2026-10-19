import { afterEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { createAuth } from '../../src/auth';
import { consoleMailer, emailVerification, mail, memoryMailer, resendMailer, sendMail } from '../../src/auth/modules';
import { oidc } from '../../src/auth/oauth';
import { inspectRecovery } from '../../src/auth/recovery';
import { count, cookiePair, insertUser, makeEnv, settle } from '../helpers/auth';
import { json, linkIn, moduleApp, pathOf, sessionCookie, signupPasskey, user } from './helpers';

afterEach(() => vi.restoreAllMocks());

describe('mail adapters', () => {
  it('Resend: one POST with the API key; a failure never echoes the response', async () => {
    const calls: [string, RequestInit][] = [];
    const ok = resendMailer({ apiKey: 'key-1', from: 'App <app@example.com>', fetch: (async (u: string, i: RequestInit) => { calls.push([u, i]); return new Response('{}', { status: 200 }); }) as typeof fetch });
    await ok.send({ to: 'a@example.com', subject: 'S', text: 'T' });
    expect(calls[0]![0]).toBe('https://api.resend.com/emails');
    expect((calls[0]![1].headers as Record<string, string>).Authorization).toBe('Bearer key-1');
    expect(JSON.parse(String(calls[0]![1].body))).toEqual({ from: 'App <app@example.com>', to: ['a@example.com'], subject: 'S', text: 'T' });
    const bad = resendMailer({ apiKey: 'k', from: 'f', fetch: (async () => new Response('{"to":"a@example.com"}', { status: 422 })) as typeof fetch });
    await expect(bad.send({ to: 'a@example.com', subject: 'S', text: 'T' })).rejects.toThrow(/^resend_422$/);
  });

  it('console: the body (with its links) only in local development', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await consoleMailer({ APP_ENV: 'local' }).send({ to: 'a@example.com', subject: 'S', text: 'secret-link' });
    await consoleMailer({ APP_ENV: 'production' }).send({ to: 'a@example.com', subject: 'S', text: 'secret-link' });
    expect(String(log.mock.calls[0]![0])).toContain('secret-link');
    expect(String(log.mock.calls[1]![0])).not.toContain('secret-link');
    expect(String(log.mock.calls[1]![0])).not.toContain('a@example.com');
  });

  it('sendMail: templates can be replaced, recipients are limited per hour, errors are swallowed and logged', async () => {
    const outbox = memoryMailer();
    const auth = createAuth({ appName: 'Mailer', modules: [mail({ mailer: () => outbox, perRecipientPerHour: 2, templates: { invite: (d, app) => ({ subject: `Join ${app}`, text: d.link }) } })] });
    const env = makeEnv();
    const c = { env, executionCtx: { waitUntil() {} } } as never;
    expect(await sendMail(c, auth.config, 'a@example.com', 'invite', { link: 'L', days: 7 })).toBe('sent');
    expect(outbox.sent[0]).toEqual({ to: 'a@example.com', subject: 'Join Mailer', text: 'L' });
    expect(await sendMail(c, auth.config, 'A@example.com', 'invite', { link: 'L', days: 7 })).toBe('sent');
    expect(await sendMail(c, auth.config, 'a@example.com', 'invite', { link: 'L', days: 7 })).toBe('limited');
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM rate_counters WHERE key LIKE '%example.com%'")).toBe(0);
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const broken = createAuth({ appName: 'X', modules: [mail({ mailer: () => ({ send: async () => { throw new Error('boom b@example.com'); } }) })] });
    expect(await sendMail(c, broken.config, 'b@example.com', 'invite', { link: 'L', days: 7 })).toBe('failed');
    expect(String(err.mock.calls[0]![0])).not.toContain('b@example.com');
    // Without the module nothing is sent.
    expect(await sendMail(c, createAuth({ appName: 'Y' }).config, 'c@example.com', 'invite', { link: 'L', days: 7 })).toBe('no-mail-module');
  });

  it('emailVerification() refuses to start without mail()', () => {
    expect(() => createAuth({ appName: 'X', modules: [emailVerification()] })).toThrow(/needs the mail\(\) module/);
  });
});

describe('e-mail verification', () => {
  it('signup with an address: not on the user row until the link is confirmed; GET never consumes it', async () => {
    const t = moduleApp({ email: {} });
    const res = await signupPasskey(t.req, { name: 'Anna', username: 'anna', email: ' Anna@Example.com ' });
    expect(res.status).toBe(200);
    expect(res.cookie).toBeTruthy(); // the account works right away
    expect(await user(t.env.DB, 'anna')).toMatchObject({ email: null, email_verified_at: null });
    expect(t.outbox.sent).toHaveLength(1);
    expect(t.outbox.sent[0]).toMatchObject({ to: 'anna@example.com', subject: expect.stringContaining('Confirm') });
    const link = pathOf(linkIn(t.outbox.sent[0]!.text));
    expect(link).toMatch(/^\/auth\/verify-email\/[A-Za-z0-9_-]{43}$/);
    expect(await count(t.env.DB, 'SELECT COUNT(*) AS n FROM email_verifications WHERE token_hash = ?', link.split('/').pop())).toBe(0); // hashed

    const page = await t.req(link);
    expect(await page.text()).toContain('Confirm address');
    expect(page.headers.get('referrer-policy')).toBe('no-referrer');
    expect(await user(t.env.DB, 'anna')).toMatchObject({ email: null }); // GET (a mail scanner) consumed nothing
    expect((await t.req(link, { method: 'POST' })).status).toBe(200);
    expect(await user(t.env.DB, 'anna')).toMatchObject({ email: 'anna@example.com', email_verified_at: expect.any(Number) });
    expect((await t.req(link, { method: 'POST' })).status).toBe(400); // single use
  });

  it('refuses invalid or taken addresses at signup; required: true needs one', async () => {
    const t = moduleApp({ email: { required: true } });
    expect((await signupPasskey(t.req, { name: 'Bob', username: 'bob' })).json).toMatchObject({ error: { code: 'invalid_email' } });
    expect((await signupPasskey(t.req, { name: 'Bob', username: 'bob', email: 'not-an-address' })).json).toMatchObject({ error: { code: 'invalid_email' } });
    const taken = await insertUser(t.env.DB);
    await t.env.DB.prepare("UPDATE users SET email = 'bob@example.com', email_verified_at = 1 WHERE id = ?").bind(taken.id).run();
    expect((await signupPasskey(t.req, { name: 'Bob', username: 'bob', email: 'bob@example.com' })).json).toMatchObject({ error: { code: 'email_taken' } });
  });

  it('nobody can squat an address: two accounts may wait for the same one, only the first to confirm gets it', async () => {
    const t = moduleApp({ email: {} });
    await signupPasskey(t.req, { name: 'Real', username: 'real', email: 'x@example.com' });
    await signupPasskey(t.req, { name: 'Squatter', username: 'squat', email: 'x@example.com' });
    const [realLink, squatLink] = t.outbox.sent.map(m => pathOf(linkIn(m.text)));
    expect((await t.req(realLink!, { method: 'POST' })).status).toBe(200);
    const late = await t.req(squatLink!, { method: 'POST' });
    expect(late.status).toBe(409);
    expect(await user(t.env.DB, 'squat')).toMatchObject({ email: null });
  });

  it('expired links (1 day) and links of suspended accounts do nothing', async () => {
    const t = moduleApp({ email: {} });
    await signupPasskey(t.req, { name: 'Old', username: 'old', email: 'old@example.com' });
    await t.env.DB.prepare('UPDATE email_verifications SET expires_at = 1').run();
    expect((await t.req(pathOf(linkIn(t.outbox.sent[0]!.text)), { method: 'POST' })).status).toBe(400);
    await signupPasskey(t.req, { name: 'Sus', username: 'sus', email: 'sus@example.com' });
    await t.env.DB.prepare("UPDATE users SET status = 'suspended' WHERE username = 'sus'").run();
    expect((await t.req(pathOf(linkIn(t.outbox.sent[1]!.text)), { method: 'POST' })).status).toBe(403);
    expect(await user(t.env.DB, 'sus')).toMatchObject({ email: null });
  });

  it('Google signup: a provider-verified address that matches is confirmed at once; another address gets a link', async () => {
    const t = moduleApp({ email: {} });
    const env = Object.assign(t.env, { GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 's' });
    const viaGoogle = async (subject: string, typed: string, username: string) => {
      vi.spyOn(oidc, 'exchangeCode').mockResolvedValue('t');
      vi.spyOn(oidc, 'verifyIdToken').mockResolvedValue({ provider: 'google', subject, email: 'g@example.com', emailVerified: true, name: 'G' });
      const start = await t.req('/auth/google/start?intent=signup');
      const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
      const cb = await t.req(`/auth/google/callback?state=${state}&code=c`, { cookie: cookiePair(start, 'auth_oauth') });
      const signup = cookiePair(cb, 'auth_signup')!;
      expect(await (await t.req('/auth/signup/complete', { cookie: signup })).text()).toContain('value="g@example.com"');
      const done = await t.req('/auth/signup/complete', { method: 'POST', cookie: signup, body: new URLSearchParams({ name: 'Gina G', username, email: typed }) });
      vi.restoreAllMocks();
      return done;
    };
    expect(env.GOOGLE_CLIENT_ID).toBe('g');
    expect((await viaGoogle('s1', 'g@example.com', 'gina')).status).toBe(303);
    expect(await user(t.env.DB, 'gina')).toMatchObject({ email: 'g@example.com' });
    expect(t.outbox.sent).toHaveLength(0);
    expect((await viaGoogle('s2', 'other@example.com', 'otto')).status).toBe(303);
    expect(await user(t.env.DB, 'otto')).toMatchObject({ email: null });
    expect(t.outbox.sent[0]!.to).toBe('other@example.com');
  });

  it('changing the address needs step-up, mails the new address and notifies the old one', async () => {
    const t = moduleApp({ email: {} });
    const u = await insertUser(t.env.DB, { name: 'Cas' });
    await t.env.DB.prepare("UPDATE users SET email = 'old@example.com', email_verified_at = 1 WHERE id = ?").bind(u.id).run();
    const stale = await sessionCookie(t.env.DB, u, 10 * 60_000);
    expect(await (await t.req('/auth/api/account/email', { ...json({ email: 'new@example.com' }), cookie: stale })).json()).toMatchObject({ error: { code: 'reauth_required' } });
    const here = await sessionCookie(t.env.DB, u);
    expect((await t.req('/auth/api/account/email', { ...json({ email: 'old@example.com' }), cookie: here })).status).toBe(409);
    const ok = await t.req('/auth/api/account/email', { ...json({ email: 'new@example.com' }), cookie: here });
    expect(ok.status).toBe(200);
    expect(t.outbox.sent.map(m => m.to)).toEqual(['new@example.com', 'old@example.com']);
    expect(t.outbox.sent[1]!.text).toContain('new@example.com');
    expect(await user(t.env.DB, u.username)).toMatchObject({ email: 'old@example.com' }); // until confirmed
    // A second request replaces the first link.
    await t.req('/auth/api/account/email', { ...json({ email: 'newer@example.com' }), cookie: here });
    expect((await t.req(pathOf(linkIn(t.outbox.sent[0]!.text)), { method: 'POST' })).status).toBe(400);
    expect((await t.req(pathOf(linkIn(t.outbox.sent[2]!.text)), { method: 'POST' })).status).toBe(200);
    expect(await user(t.env.DB, u.username)).toMatchObject({ email: 'newer@example.com' });
    // The account page shows the address.
    expect(await (await t.req('/auth/account', { cookie: here })).text()).toContain('newer@example.com');
  });

  it('resend sends a fresh link for the pending address', async () => {
    const t = moduleApp({ email: {} });
    const res = await signupPasskey(t.req, { name: 'Rae', username: 'rae', email: 'rae@example.com' });
    const r = await t.req('/auth/api/account/email/resend', { method: 'POST', cookie: res.cookie });
    expect(r.status).toBe(200);
    expect(t.outbox.sent).toHaveLength(2);
    expect((await t.req(pathOf(linkIn(t.outbox.sent[0]!.text)), { method: 'POST' })).status).toBe(400); // replaced
    expect((await t.req(pathOf(linkIn(t.outbox.sent[1]!.text)), { method: 'POST' })).status).toBe(200);
  });

  it('recovery by e-mail: a link for a confirmed address, the same answer for unknown ones', async () => {
    const t = moduleApp({ email: {} });
    const u = await insertUser(t.env.DB, { name: 'Lena' });
    await t.env.DB.prepare("UPDATE users SET email = 'lena@example.com', email_verified_at = 1 WHERE id = ?").bind(u.id).run();
    const known = await (await t.req('/auth/api/recovery/request', json({ email: 'LENA@example.com' }))).json();
    const unknown = await (await t.req('/auth/api/recovery/request', json({ email: 'nobody@example.com' }))).json();
    await settle();
    expect(known).toEqual(unknown);
    expect(t.outbox.sent).toHaveLength(1);
    const token = linkIn(t.outbox.sent[0]!.text).split('/auth/recover/')[1];
    expect((await inspectRecovery(t.env.DB, token)).ok).toBe(true);
    // Suspended accounts get nothing; the login page links to the form.
    await t.env.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(u.id).run();
    await t.req('/auth/api/recovery/request', json({ email: 'lena@example.com' }));
    await settle();
    expect(t.outbox.sent).toHaveLength(1);
    expect(await (await t.req('/auth/login')).text()).toContain('/auth/recover"');
    expect((await t.req('/auth/recover')).status).toBe(200);
  });

  it('without the module the core ignores an e-mail field and runs on migration 0001 alone', async () => {
    const { createTestDb } = await import('../helpers/d1');
    const auth = createAuth({ appName: 'Core' });
    const app = new Hono();
    app.use('*', auth.securityHeaders, auth.bodyLimit, auth.originCheck, auth.session);
    app.route('/', auth.routes);
    const env = makeEnv({ DB: createTestDb({ upTo: '0001_auth.sql' }) });
    const { client } = await import('../helpers/auth');
    const req = client((r, e, ctx) => app.fetch(r, e, ctx), env);
    const res = await signupPasskey(req as never, { name: 'Core', username: 'core', email: 'ignored@example.com' });
    expect(res.status).toBe(200);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE username = 'core'").first('n')).toBe(1);
  });
});
