// Optional module: personal e-mail invites and shareable signup links, created by admins. Needs admin() (for the
// admin API and page) and migration 0002; invites are mailed when mail() is on, and the link is always shown to the
// admin as well.
//
// - Invite: one address, valid 7 days by default, works once. The signup's address is locked to the invite's and
//   counts as confirmed (the invite reached it). /auth/invite/<token> → the signup page.
// - Signup link: a number of uses until a date, revocable. A use is only counted when an account is created, and the
//   count never goes down (a deleted account doesn't free its place). /auth/join/<token> → the signup page.
// - Both are consumed inside the registration batch (a gate): of two signups racing for the last place, exactly one
//   account is created. Only the SHA-256 of a token is stored.
import type { Hono } from 'hono';
import type { AuthConfig } from '../config';
import { randomToken, sha256Hex, uuid } from '../crypto';
import { jsonError, readJson } from '../http';
import type { AuthModule } from '../extensions';
import { html, messagePage } from '../pages';
import { hitRateLimit } from '../rate-limit';
import { requireFreshAuth } from '../session';
import { auditStmts, fail, type Fail, type Result } from '../users';
import type { AuthContext, AuthEnv } from '../types';
import { requireAdmin } from './admin';
import { hasMail, sendMail } from './mail';
import { validateEmail } from './shared';

const DAY = 24 * 60 * 60_000;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export const MSG = {
  inviteInvalid: 'This invitation is incorrect or has been withdrawn.',
  inviteUsed: 'This invitation has already been used. Sign in instead.',
  inviteExpired: 'This invitation has expired. Ask for a new one.',
  inviteEmail: 'Use the e-mail address the invitation was sent to.',
  inviteTaken: 'The invited address already belongs to an account. Sign in instead.',
  linkInvalid: 'This signup link is incorrect.',
  linkClosed: 'This signup link has been withdrawn.',
  linkExpired: 'This signup link has expired.',
  linkFull: 'This signup link has no places left.',
  busy: 'Too many signups with this link right now. Wait a few minutes and try again.',
  both: 'Use either an invitation or a signup link, not both.',
  label: 'Give the link a label of 1 to 100 characters.',
  uses: 'Uses: a whole number from 1 to 1000.',
  days: 'Days: a whole number from 1 to 90.',
  emailTaken: 'This address already belongs to an account.',
};

export interface InvitesOptions {
  /** Days an invite stays valid. Default 7. */
  inviteDays?: number;
  /** Signup attempts per link per 10 minutes (each attempt reveals whether a username is taken). Default 60. */
  attemptsPerLink?: number;
}

interface InviteRow { id: string; email: string; expires_at: number; used_at: number | null; revoked_at: number | null }
interface LinkRow { id: string; label: string; max_uses: number; used_count: number; expires_at: number; revoked_at: number | null }

export async function inspectInvite(db: D1Database, token: unknown, at = Date.now()): Promise<{ ok: true; invite: InviteRow } | Fail> {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return fail(409, 'invite_invalid', MSG.inviteInvalid);
  const r = await db.prepare('SELECT id, email, expires_at, used_at, revoked_at FROM invites WHERE token_hash = ?').bind(await sha256Hex(token)).first<InviteRow>();
  return inviteState(r, at);
}
function inviteState(r: InviteRow | null, at: number): { ok: true; invite: InviteRow } | Fail {
  if (!r || r.revoked_at != null) return fail(409, 'invite_invalid', MSG.inviteInvalid);
  if (r.used_at != null) return fail(409, 'invite_used', MSG.inviteUsed);
  if (r.expires_at <= at) return fail(409, 'invite_expired', MSG.inviteExpired);
  return { ok: true, invite: r };
}

export async function inspectLink(db: D1Database, token: unknown, at = Date.now()): Promise<{ ok: true; link: LinkRow } | Fail> {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return fail(409, 'link_invalid', MSG.linkInvalid);
  const r = await db.prepare('SELECT id, label, max_uses, used_count, expires_at, revoked_at FROM signup_links WHERE token_hash = ?').bind(await sha256Hex(token)).first<LinkRow>();
  return linkState(r, at);
}
function linkState(r: LinkRow | null, at: number): { ok: true; link: LinkRow } | Fail {
  if (!r) return fail(409, 'link_invalid', MSG.linkInvalid);
  if (r.revoked_at != null) return fail(409, 'link_closed', MSG.linkClosed);
  if (r.expires_at <= at) return fail(409, 'link_expired', MSG.linkExpired);
  if (r.used_count >= r.max_uses) return fail(409, 'link_full', MSG.linkFull);
  return { ok: true, link: r };
}

/** Create an invite for `email`; returns the URL (only the token's hash is stored). */
export async function createInvite(c: AuthContext, cfg: AuthConfig, actorId: string, email: unknown, days: number, at = Date.now()): Promise<Result<{ id: string; url: string; expiresAt: number; mailed: boolean }>> {
  const v = validateEmail(email, true);
  if (!v.ok) return v;
  if (await c.env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(v.value).first()) return fail(409, 'email_taken', MSG.emailTaken);
  const token = randomToken(32);
  const id = uuid();
  const expiresAt = at + days * DAY;
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT INTO invites (id, email, token_hash, created_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').bind(id, v.value, await sha256Hex(token), actorId, expiresAt, at),
    ...auditStmts(c.env.DB, cfg, { actorId, action: 'invite-created', details: { inviteId: id } }, at),
  ]);
  const url = `${c.env.APP_ORIGIN}${cfg.path(`/auth/invite/${token}`)}`;
  const mailed = hasMail(cfg) && (await sendMail(c, cfg, v.value!, 'invite', { link: url, days })) === 'sent';
  return { ok: true, id, url, expiresAt, mailed };
}

export async function createSignupLink(c: AuthContext, cfg: AuthConfig, actorId: string, i: { label?: unknown; maxUses?: unknown; days?: unknown }, at = Date.now()): Promise<Result<{ id: string; url: string; expiresAt: number }>> {
  const label = typeof i.label === 'string' ? i.label.trim() : '';
  if (label.length < 1 || label.length > 100) return fail(422, 'invalid_label', MSG.label);
  const maxUses = Number(i.maxUses), days = Number(i.days);
  if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 1000) return fail(422, 'invalid_uses', MSG.uses);
  if (!Number.isInteger(days) || days < 1 || days > 90) return fail(422, 'invalid_days', MSG.days);
  const token = randomToken(32);
  const id = uuid();
  const expiresAt = at + days * DAY;
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT INTO signup_links (id, label, token_hash, max_uses, created_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, label, await sha256Hex(token), maxUses, actorId, expiresAt, at),
    ...auditStmts(c.env.DB, cfg, { actorId, action: 'signup-link-created', details: { linkId: id, maxUses } }, at),
  ]);
  return { ok: true, id, url: `${c.env.APP_ORIGIN}${cfg.path(`/auth/join/${token}`)}`, expiresAt };
}

/** Signup-form fields for an invite (locked address) or a signup link (hidden token). */
async function signupFields(c: AuthContext, params: Record<string, string>): Promise<string> {
  if (params.invite) {
    const r = await inspectInvite(c.env.DB, params.invite);
    if (!r.ok) return html`<p class="auth-error" role="alert">${r.message}</p>`.value;
    return html`<label for="email">E-mail</label>
  <input id="email" name="email" type="email" value="${r.invite.email}" readonly>
  <p class="auth-help">You were invited at this address.</p>
  <input type="hidden" name="invite" value="${params.invite}">`.value;
  }
  if (params.link) {
    const r = await inspectLink(c.env.DB, params.link);
    return r.ok ? html`<input type="hidden" name="link" value="${params.link}">`.value : html`<p class="auth-error" role="alert">${r.message}</p>`.value;
  }
  return '';
}

export function invites(options: InvitesOptions = {}): AuthModule {
  const inviteDays = options.inviteDays ?? 7;
  const attempts = options.attemptsPerLink ?? 60;

  return {
    name: 'invites',
    signupParams: ['invite', 'link'],

    async prepareSignup(s) {
      const db = s.c.env.DB;
      if (s.params.invite && s.params.link) return fail(400, 'bad_request', MSG.both);
      if (s.params.invite) {
        const r = await inspectInvite(db, s.params.invite);
        if (!r.ok) return r;
        if (s.stage === 'details') {
          const typed = typeof s.fields.email === 'string' && s.fields.email.trim() ? s.fields.email.trim().toLowerCase() : r.invite.email;
          if (typed !== r.invite.email) return fail(422, 'invite_email_mismatch', MSG.inviteEmail);
          if (await db.prepare('SELECT 1 FROM users WHERE email = ?').bind(r.invite.email).first()) return fail(409, 'email_taken', MSG.inviteTaken);
        }
        return { invite: { id: r.invite.id, email: r.invite.email } };
      }
      if (s.params.link) {
        const r = await inspectLink(db, s.params.link);
        if (!r.ok) return r;
        if (s.stage === 'details') {
          // Per link: bounds how fast one shared link can be used to probe usernames.
          const limit = await hitRateLimit(db, `signup:link:${r.link.id}`, attempts, 10 * 60_000);
          if (!limit.allowed) return fail(429, 'rate_limited', MSG.busy);
        }
        return { link: { id: r.link.id } };
      }
    },

    async register(r) {
      const db = r.env.DB;
      const invite = r.data.invite as { id: string; email: string } | undefined;
      const link = r.data.link as { id: string } | undefined;
      if (invite) {
        return {
          gate: db.prepare('UPDATE invites SET used_at = ?1, used_by = ?2 WHERE id = ?3 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1').bind(r.at, r.userId, invite.id),
          gateFailed: async () => inviteState(await db.prepare('SELECT id, email, expires_at, used_at, revoked_at FROM invites WHERE id = ?').bind(invite.id).first<InviteRow>(), r.at) as Fail,
          stmts: [
            // The invite reached this address: it counts as confirmed.
            db.prepare(`UPDATE users SET email = ?, email_verified_at = ? WHERE id = ? AND ${r.exists.sql}`).bind(invite.email, r.at, r.userId, ...r.exists.params),
            ...auditStmts(db, r.cfg, { actorId: r.userId, action: 'invite-used', targetUserId: r.userId, details: { inviteId: invite.id } }, r.at, r.exists.sql, r.exists.params),
          ],
        };
      }
      if (link) {
        return {
          gate: db.prepare('UPDATE signup_links SET used_count = used_count + 1 WHERE id = ?1 AND revoked_at IS NULL AND expires_at > ?2 AND used_count < max_uses').bind(link.id, r.at),
          gateFailed: async () => {
            const s = linkState(await db.prepare('SELECT id, label, max_uses, used_count, expires_at, revoked_at FROM signup_links WHERE id = ?').bind(link.id).first<LinkRow>(), r.at);
            return s.ok ? fail(409, 'link_full', MSG.linkFull) : s;
          },
          stmts: auditStmts(db, r.cfg, { actorId: r.userId, action: 'signup-link-used', targetUserId: r.userId, details: { linkId: link.id } }, r.at, r.exists.sql, r.exists.params),
        };
      }
    },

    mapError: text => (text.includes('users.email') ? fail(409, 'email_taken', MSG.inviteTaken) : null),

    html: {
      signup: (c, _cfg, params) => signupFields(c, params),
      // After Google/Apple the token lives in the signup flow, so only the locked address is shown.
      signupComplete: (c, _cfg, x) => (x.params.invite ? signupFields(c, { invite: x.params.invite }) : ''),
      async admin(c, cfg) {
        const db = c.env.DB;
        const now = Date.now();
        const inv = (await db.prepare('SELECT id, email, expires_at, used_at, revoked_at FROM invites ORDER BY created_at DESC LIMIT 50').all<InviteRow>()).results;
        const links = (await db.prepare('SELECT id, label, max_uses, used_count, expires_at, revoked_at FROM signup_links ORDER BY created_at DESC LIMIT 50').all<LinkRow>()).results;
        const live = (x: { revoked_at: number | null; expires_at: number }) => x.revoked_at == null && x.expires_at > now;
        const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
        return html`<h2>Invites</h2>
  <form data-auth-api="${cfg.path('/auth/api/admin/invites')}" data-done="Invite created:">
    <label for="invite-email">E-mail</label>
    <input id="invite-email" name="email" type="email" required maxlength="254">
    <button class="auth-button" type="submit">Invite</button>
  </form>
  <ul class="auth-list">${inv.map(i => html`<li><span>${i.email}<br><small>${i.used_at ? 'used' : i.revoked_at ? 'withdrawn' : i.expires_at <= now ? 'expired' : `open until ${day(i.expires_at)}`}</small></span>
    ${!i.used_at && live(i) ? html`<button type="button" class="auth-button" data-auth-api="${cfg.path(`/auth/api/admin/invites/${i.id}/revoke`)}" data-reload>Withdraw</button>` : ''}</li>`)}</ul>
  <h2>Signup links</h2>
  <form data-auth-api="${cfg.path('/auth/api/admin/links')}" data-done="Signup link created:">
    <label for="link-label">Label</label><input id="link-label" name="label" required maxlength="100">
    <label for="link-uses">Uses</label><input id="link-uses" name="maxUses" type="number" min="1" max="1000" value="10" required>
    <label for="link-days">Valid for (days)</label><input id="link-days" name="days" type="number" min="1" max="90" value="7" required>
    <button class="auth-button" type="submit">Create link</button>
  </form>
  <ul class="auth-list">${links.map(l => html`<li><span>${l.label}<br><small>${l.used_count}/${l.max_uses} used · ${l.revoked_at ? 'withdrawn' : l.expires_at <= now ? 'expired' : `until ${day(l.expires_at)}`}</small></span>
    ${live(l) ? html`<button type="button" class="auth-button" data-auth-api="${cfg.path(`/auth/api/admin/links/${l.id}/revoke`)}" data-reload>Withdraw</button>` : ''}</li>`)}</ul>`.value;
      },
    },

    routes(r: Hono<AuthEnv>, cfg: AuthConfig) {
      if (!cfg.modules.some(m => m.name === 'admin')) throw new Error('invites() needs the admin() module in AuthOptions.modules');
      const isAdmin = requireAdmin(cfg);
      const fresh = requireFreshAuth(cfg);
      const actor = (c: AuthContext) => c.get('session')!.user.id;
      const toSignup = (c: AuthContext, key: 'invite' | 'link', token: string) => c.redirect(`${cfg.path('/auth/signup')}?${key}=${encodeURIComponent(token)}`);

      r.get('/auth/invite/:token', async c => {
        const res = await inspectInvite(c.env.DB, c.req.param('token'));
        return res.ok ? toSignup(c, 'invite', c.req.param('token')) : messagePage(c, cfg, { title: 'Invitation', message: res.message, status: 410, links: [{ href: cfg.path('/auth/login'), label: 'Sign in' }] });
      });
      r.get('/auth/join/:token', async c => {
        const res = await inspectLink(c.env.DB, c.req.param('token'));
        return res.ok ? toSignup(c, 'link', c.req.param('token')) : messagePage(c, cfg, { title: 'Signup link', message: res.message, status: 410, links: [{ href: cfg.path('/auth/login'), label: 'Sign in' }] });
      });

      r.get('/auth/api/admin/invites', isAdmin, async c => c.json({
        invites: (await c.env.DB.prepare('SELECT id, email, expires_at AS expiresAt, used_at AS usedAt, revoked_at AS revokedAt, created_at AS createdAt FROM invites ORDER BY created_at DESC LIMIT 200').all()).results,
      }));
      r.post('/auth/api/admin/invites', isAdmin, fresh, async c => {
        const body = await readJson<{ email?: unknown }>(c);
        const res = await createInvite(c, cfg, actor(c), body?.email, inviteDays);
        return res.ok ? c.json(res) : jsonError(c, res.status, res.code, res.message);
      });
      r.post('/auth/api/admin/invites/:id/revoke', isAdmin, fresh, async c => {
        const at = Date.now();
        const res = await c.env.DB.batch([
          c.env.DB.prepare('UPDATE invites SET revoked_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL').bind(at, c.req.param('id')),
          ...auditStmts(c.env.DB, cfg, { actorId: actor(c), action: 'invite-revoked', details: { inviteId: c.req.param('id') } }, at, 'changes() = 1'),
        ]);
        return res[0]?.meta.changes === 1 ? c.json({ ok: true }) : jsonError(c, 404, 'not_found', 'This invitation is used, withdrawn or unknown.');
      });

      r.get('/auth/api/admin/links', isAdmin, async c => c.json({
        links: (await c.env.DB.prepare('SELECT id, label, max_uses AS maxUses, used_count AS usedCount, expires_at AS expiresAt, revoked_at AS revokedAt, created_at AS createdAt FROM signup_links ORDER BY created_at DESC LIMIT 200').all()).results,
      }));
      r.post('/auth/api/admin/links', isAdmin, fresh, async c => {
        const res = await createSignupLink(c, cfg, actor(c), (await readJson<Record<string, unknown>>(c)) ?? {});
        return res.ok ? c.json(res) : jsonError(c, res.status, res.code, res.message);
      });
      r.post('/auth/api/admin/links/:id/revoke', isAdmin, fresh, async c => {
        const at = Date.now();
        const res = await c.env.DB.batch([
          c.env.DB.prepare('UPDATE signup_links SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').bind(at, c.req.param('id')),
          ...auditStmts(c.env.DB, cfg, { actorId: actor(c), action: 'signup-link-revoked', details: { linkId: c.req.param('id') } }, at, 'changes() = 1'),
        ]);
        return res[0]?.meta.changes === 1 ? c.json({ ok: true }) : jsonError(c, 404, 'not_found', 'This link is withdrawn or unknown.');
      });
    },
  };
}
