// Optional module: e-mail addresses on accounts, verified by a link. Needs the mail() module and migration 0002.
//
// - Signup takes an optional (or required) address. It is NOT put on the user row until the link is confirmed, so
//   typing someone else's address claims nothing (a Google/Apple address the provider verified counts as confirmed).
// - The link holds a random token (only its SHA-256 is stored), is valid for 1 day and works once. GET shows a
//   confirm button; only the POST uses it up, so mail scanners that open links don't.
// - Changing the address (step-up) sends a link to the new address and a notice to the old verified one.
// - Optional (recoveryByEmail: true): /auth/recover asks for the address and mails a recovery link when it belongs to
//   an active account. The answer is the same either way; the address is told once the link has been used.
import type { Hono } from 'hono';
import type { AuthConfig } from '../config';
import { hmac, randomToken, sha256Hex, uuid } from '../crypto';
import { jsonError, logIncident, readJson } from '../http';
import type { AuthModule, RegisterContext } from '../extensions';
import { html, messagePage, renderPage } from '../pages';
import { flowStartLimited, hitRateLimit } from '../rate-limit';
import { issueRecoveryLink } from '../recovery';
import { requireFreshAuth, requireUser } from '../session';
import { auditStmts, fail, type Fail } from '../users';
import type { AuthContext, AuthEnv } from '../types';
import { hasMail, mailRecoveryLink, sendMail } from './mail';
import { validateEmail } from './shared';

export { validateEmail };

export const VERIFY_TTL = 24 * 60 * 60_000;
/** "Send the link again" per account per hour. */
export const RESENDS_PER_HOUR = 3;
/** Recovery requests per target address per hour (whether or not the address is known). */
export const RECOVERY_REQUESTS_PER_ADDRESS = 3;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export const MSG = {
  taken: 'This e-mail address already belongs to an account. Sign in, or use another address.',
  same: 'This is already your e-mail address.',
  invalid: 'This confirmation link is incorrect or has already been used.',
  expired: 'This confirmation link has expired. Sign in and request a new one.',
  blocked: 'This account isn’t active.',
  notSent: 'The mail couldn’t be sent right now. Try again later.',
  limited: 'We already sent several mails to this address. Wait an hour and try again.',
  recoverySent: 'If an active account uses this address, we’ve sent it a recovery link. It is valid for 15 minutes.',
};

export interface EmailVerificationOptions {
  /** Ask for an address at signup and require it. Default false (optional field). */
  required?: boolean;
  /**
   * "Lost your passkey?" → a recovery link by mail. Default false. While on, whoever controls the mailbox of a
   * confirmed address controls the account (see README).
   */
  recoveryByEmail?: boolean;
}

const emailTaken = async (db: D1Database, email: string, exceptUserId?: string) =>
  !!(await db.prepare('SELECT 1 FROM users WHERE email = ? AND id IS NOT ?').bind(email, exceptUserId ?? null).first());

/** A pending verification for `email` (statements for a batch) and the token for the link. */
async function verificationStmts(db: D1Database, userId: string, email: string, at: number, guard?: { sql: string; params: unknown[] }) {
  const token = randomToken(32);
  const cols = [uuid(), userId, email, await sha256Hex(token), at + VERIFY_TTL, at];
  const stmt = guard
    ? db.prepare(`INSERT INTO email_verifications (id, user_id, email, token_hash, expires_at, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE ${guard.sql}`).bind(...cols, ...guard.params)
    : db.prepare('INSERT INTO email_verifications (id, user_id, email, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').bind(...cols);
  return { token, stmt };
}

const verifyLink = (c: AuthContext, cfg: AuthConfig, token: string) => `${c.env.APP_ORIGIN}${cfg.path(`/auth/verify-email/${token}`)}`;

/** Consume a verification token: the address becomes the account's verified address. */
export async function confirmEmail(db: D1Database, cfg: Pick<AuthConfig, 'audit'>, token: unknown, at = Date.now()): Promise<{ ok: true; userId: string } | Fail> {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return fail(400, 'verification_invalid', MSG.invalid);
  const row = await db.prepare('SELECT id, user_id, email, expires_at, used_at FROM email_verifications WHERE token_hash = ?').bind(await sha256Hex(token))
    .first<{ id: string; user_id: string; email: string; expires_at: number; used_at: number | null }>();
  if (!row || row.used_at != null) return fail(400, 'verification_invalid', MSG.invalid);
  if (row.expires_at <= at) return fail(400, 'verification_expired', MSG.expired);
  try {
    const res = await db.batch([
      db.prepare('UPDATE email_verifications SET used_at = ? WHERE id = ? AND used_at IS NULL').bind(at, row.id),
      // Waiting for approval may confirm; suspended by an admin or rejected may not.
      db.prepare(`UPDATE users SET email = ?1, email_verified_at = ?2, updated_at = ?2 WHERE id = ?3 AND changes() = 1
          AND (status = 'active' OR approval = 'pending')`).bind(row.email, at, row.user_id),
      ...auditStmts(db, cfg, { actorId: row.user_id, action: 'email-verified', targetUserId: row.user_id }, at, 'changes() = 1'),
    ]);
    if (res[0]?.meta.changes !== 1) return fail(400, 'verification_invalid', MSG.invalid);
    if (res[1]?.meta.changes !== 1) return fail(403, 'account_blocked', MSG.blocked);
  } catch (e) {
    if (String(e).includes('UNIQUE')) return fail(409, 'email_taken', MSG.taken);
    throw e;
  }
  return { ok: true, userId: row.user_id };
}

/**
 * Run slow work (mail) after the response when the runtime allows it, so timing doesn't tell whether an account
 * exists. Outside Workers (no executionCtx, e.g. some test or Node adapters) the work is awaited instead, and then
 * the response time DOES differ between known and unknown addresses.
 */
function background(c: AuthContext, work: Promise<unknown>): Promise<unknown> {
  try { c.executionCtx.waitUntil(work); return Promise.resolve(); } catch { return work; }
}

export function emailVerification(options: EmailVerificationOptions = {}): AuthModule {
  const required = options.required ?? false;
  const recovery = options.recoveryByEmail ?? false;
  const field = (value: string, label = required ? 'E-mail' : 'E-mail (optional)') => html`<label for="email">${label}</label>
  <input id="email" name="email" type="email" autocomplete="email" maxlength="254" value="${value}"${required ? html` required` : ''}>`.value;

  return {
    name: 'email-verification',

    async prepareSignup(s) {
      if (s.stage !== 'details' || s.params.invite) return; // invites lock the address themselves
      const v = validateEmail(s.fields.email, required);
      if (!v.ok) return v;
      if (!v.value) return;
      if (await emailTaken(s.c.env.DB, v.value)) return fail(409, 'email_taken', MSG.taken);
      const byProvider = !!s.identity?.emailVerified && s.identity.email?.toLowerCase() === v.value;
      return { email: v.value, emailVerifiedByProvider: byProvider };
    },

    async register(r: RegisterContext) {
      const email = typeof r.data.email === 'string' ? r.data.email : null;
      if (!email || r.data.invite) return;
      if (r.data.emailVerifiedByProvider) {
        return { stmts: [r.env.DB.prepare(`UPDATE users SET email = ?, email_verified_at = ? WHERE id = ? AND ${r.exists.sql}`).bind(email, r.at, r.userId, ...r.exists.params)] };
      }
      const v = await verificationStmts(r.env.DB, r.userId, email, r.at, r.exists);
      r.data.verifyToken = v.token;
      return { stmts: [v.stmt] };
    },

    async afterRegister(r) {
      const token = r.data.verifyToken;
      if (typeof token !== 'string' || !r.c) return;
      await sendMail(r.c, r.cfg, r.data.email as string, 'verify-email', { link: verifyLink(r.c, r.cfg, token), change: false });
    },

    mapError: text => (text.includes('users.email') ? fail(409, 'email_taken', MSG.taken) : null),

    html: {
      login: (_c, cfg) => (recovery ? html`<p class="auth-note"><a href="${cfg.path('/auth/recover')}">Lost your passkey?</a></p>`.value : ''),
      signup: (_c, _cfg, params) => (params.invite ? '' : field('')),
      signupComplete: (_c, _cfg, x) => (x.params.invite ? '' : field(x.fields.email ?? x.identity.email ?? '')),
      async account(c, cfg, userId) {
        const u = await c.env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(userId).first<{ email: string | null }>();
        const pending = await c.env.DB.prepare('SELECT email FROM email_verifications WHERE user_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1')
          .bind(userId, Date.now()).first<{ email: string }>();
        return html`<h2>E-mail</h2>
  <p>${u?.email ? html`<strong>${u.email}</strong> (confirmed)` : 'No confirmed address.'}</p>
  ${pending ? html`<p>Waiting for confirmation: <strong>${pending.email}</strong>.
    <button type="button" class="auth-button" data-auth-api="${cfg.path('/auth/api/account/email/resend')}" data-done="Sent. Check your inbox.">Send the link again</button></p>` : ''}
  <form data-auth-api="${cfg.path('/auth/api/account/email')}" data-done="Sent. Open the link in the mail to confirm the address.">
    <label for="new-email">${u?.email ? 'Change address' : 'Add an address'}</label>
    <input id="new-email" name="email" type="email" autocomplete="email" maxlength="254" required>
    <button class="auth-button" type="submit">Send confirmation link</button>
  </form>`.value;
      },
    },

    routes(r: Hono<AuthEnv>, cfg: AuthConfig) {
      if (!hasMail(cfg)) throw new Error('emailVerification() needs the mail() module in AuthOptions.modules');
      const signedIn = requireUser(cfg);
      const fresh = requireFreshAuth(cfg);

      // GET shows a button: link scanners open links, only a person submits the form.
      r.get('/auth/verify-email/:token', async c => {
        c.header('Referrer-Policy', 'no-referrer');
        const body = html`<h1>Confirm your e-mail address</h1>
<form method="post" action="${cfg.path(`/auth/verify-email/${c.req.param('token')}`)}"><button class="auth-button auth-button--primary" type="submit">Confirm address</button></form>`;
        return renderPage(c, cfg, { title: 'Confirm your e-mail address', body: body.value });
      });

      r.post('/auth/verify-email/:token', async c => {
        c.header('Referrer-Policy', 'no-referrer');
        const res = await confirmEmail(c.env.DB, cfg, c.req.param('token'));
        const links = [{ href: cfg.path('/auth/account'), label: 'Go to your account' }];
        return res.ok
          ? messagePage(c, cfg, { title: 'Address confirmed', message: 'Your e-mail address is confirmed.', status: 200, links })
          : messagePage(c, cfg, { title: 'Not confirmed', message: res.message, status: res.status, links });
      });

      r.post('/auth/api/account/email', signedIn, fresh, async c => {
        const s = c.get('session')!;
        const body = await readJson<{ email?: unknown }>(c);
        const v = validateEmail(body?.email, true);
        if (!v.ok) return jsonError(c, v.status, v.code, v.message);
        const email = v.value!;
        const db = c.env.DB;
        const u = (await db.prepare('SELECT email FROM users WHERE id = ?').bind(s.user.id).first<{ email: string | null }>())!;
        if (u.email === email) return jsonError(c, 409, 'same_email', MSG.same);
        if (await emailTaken(db, email, s.user.id)) return jsonError(c, 409, 'email_taken', MSG.taken);
        const at = Date.now();
        const ver = await verificationStmts(db, s.user.id, email, at);
        await db.batch([
          db.prepare('DELETE FROM email_verifications WHERE user_id = ? AND used_at IS NULL').bind(s.user.id),
          ver.stmt,
          ...auditStmts(db, cfg, { actorId: s.user.id, action: 'email-change-requested', targetUserId: s.user.id }, at),
        ]);
        const sent = await sendMail(c, cfg, email, 'verify-email', { link: verifyLink(c, cfg, ver.token), change: !!u.email });
        if (sent !== 'sent') return jsonError(c, sent === 'limited' ? 429 : 503, 'mail_not_sent', sent === 'limited' ? MSG.limited : MSG.notSent);
        // The old (verified) address hears about it, so an unexpected change doesn't go unnoticed.
        if (u.email) await sendMail(c, cfg, u.email, 'email-change-notice', { newEmail: email });
        return c.json({ ok: true });
      });

      r.post('/auth/api/account/email/resend', signedIn, async c => {
        const s = c.get('session')!;
        const db = c.env.DB;
        const at = Date.now();
        // Per account as well as per address (the mail limit): a session can't be used to mail-bomb.
        const limit = await hitRateLimit(db, `email-resend:user:${s.user.id}`, RESENDS_PER_HOUR, 60 * 60_000, at);
        if (!limit.allowed) return jsonError(c, 429, 'rate_limited', MSG.limited);
        const p = await db.prepare('SELECT email FROM email_verifications WHERE user_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1')
          .bind(s.user.id, at).first<{ email: string }>();
        if (!p) return jsonError(c, 404, 'nothing_pending', 'There’s no address waiting for confirmation.');
        const ver = await verificationStmts(db, s.user.id, p.email, at);
        await db.batch([db.prepare('DELETE FROM email_verifications WHERE user_id = ? AND used_at IS NULL').bind(s.user.id), ver.stmt]);
        const u = await db.prepare('SELECT email FROM users WHERE id = ?').bind(s.user.id).first<{ email: string | null }>();
        const sent = await sendMail(c, cfg, p.email, 'verify-email', { link: verifyLink(c, cfg, ver.token), change: !!u?.email });
        return sent === 'sent' ? c.json({ ok: true }) : jsonError(c, sent === 'limited' ? 429 : 503, 'mail_not_sent', sent === 'limited' ? MSG.limited : MSG.notSent);
      });

      if (!recovery) return;

      r.get('/auth/recover', async c => {
        const body = html`<h1>Lost your passkey?</h1>
<p>Enter the e-mail address you confirmed for your account. We’ll mail you a link to create a new passkey.</p>
<form data-auth-api="${cfg.path('/auth/api/recovery/request')}" data-done="${MSG.recoverySent}">
  <label for="email">E-mail</label>
  <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required>
  <button class="auth-button auth-button--primary" type="submit">Send recovery link</button>
  <p class="auth-status" data-auth-status role="status" aria-live="polite"></p>
</form>
<p class="auth-note"><a href="${cfg.path('/auth/login')}">Back to sign in</a></p>`;
        return renderPage(c, cfg, { title: 'Lost your passkey?', body: body.value, scripts: [cfg.path('/auth/passkey.js')] });
      });

      r.post('/auth/api/recovery/request', async c => {
        if (await flowStartLimited(c, cfg, 'recovery-request')) return jsonError(c, 429, 'rate_limited', 'Too many attempts from this network. Wait a few minutes and try again.');
        const body = await readJson<{ email?: unknown }>(c);
        const v = validateEmail(body?.email, true);
        if (!v.ok) return jsonError(c, v.status, v.code, v.message);
        const work = (async () => {
          // Per target address, known or not, independent of the mail limit (an HMAC in the key, never the address).
          const perAddress = await hitRateLimit(c.env.DB, `recovery-request:addr:${await hmac(c.env.SESSION_SECRET, 'recovery', v.value!)}`, RECOVERY_REQUESTS_PER_ADDRESS, 60 * 60_000);
          if (!perAddress.allowed) return;
          const u = await c.env.DB.prepare("SELECT id, username FROM users WHERE email = ? AND status = 'active'").bind(v.value).first<{ id: string; username: string }>();
          if (!u) return;
          const link = await issueRecoveryLink(c.env, cfg, u.id, { actorId: null });
          if (link.ok) await mailRecoveryLink(c, cfg, v.value!, link, u.username);
        })().catch(e => { logIncident('recovery.request', e); });
        await background(c, work);
        // The same answer whether or not the address is known.
        return c.json({ ok: true, message: MSG.recoverySent });
      });
    },
  };
}

