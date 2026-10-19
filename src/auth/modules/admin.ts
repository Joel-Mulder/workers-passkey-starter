// Optional module: who may sign up (signupMode), approval of new accounts, and an admin role with a small admin
// API and page. Needs migration 0002; mails (new-signup notice, "your account is ready") go through mail() when
// that module is on.
//
// signupMode: 'open' (default) everyone; 'approval' new accounts wait until an admin approves them (signups through
// an invite or signup link are approved at once); 'invite-only' only through an invite or signup link (invites()).
//
// Waiting and rejected accounts are users.status 'suspended' with approval 'pending' / 'rejected', so the core
// refuses them everywhere; this module only explains why.
//
// Make the first admin by hand (once):  UPDATE users SET role = 'admin' WHERE username = 'you';
import type { Hono, MiddlewareHandler } from 'hono';
import type { AuthConfig } from '../config';
import { jsonError, readJson } from '../http';
import type { AuthModule } from '../extensions';
import { html, messagePage, renderPage, SafeHtml } from '../pages';
import { issueRecoveryLink } from '../recovery';
import { loginPath, requireFreshAuth, wantsJson } from '../session';
import { auditStmts, fail, type Result } from '../users';
import type { AuthContext, AuthEnv } from '../types';
import { hasMail, sendMail } from './mail';

export type SignupMode = 'open' | 'approval' | 'invite-only';

export interface AdminOptions {
  signupMode?: SignupMode;
  /** Mail every admin with a confirmed address when an account waits for approval. Default true. */
  notifyAdmins?: boolean;
}

export const MSG = {
  inviteOnly: 'Signing up needs an invitation.',
  pending: 'Your account is waiting for approval. You can sign in once an admin has approved it.',
  rejected: 'Your signup wasn’t approved.',
  adminOnly: 'Only admins have access to this page.',
  stale: 'This account changed in the meantime. Reload the page and try again.',
  notApplicable: 'That isn’t possible for this account in its current state.',
  protected: 'Admins (and your own account) can’t be changed here. Change admins in the database.',
  notFound: 'This account doesn’t exist (any more).',
  version: 'Reload the page and try again.',
};

/** Signed in AND role 'admin' (read from the database on every request, so a demoted admin loses access at once). */
export function requireAdmin(cfg: AuthConfig): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const s = c.get('session');
    if (!s) return wantsJson(c) ? jsonError(c, 401, 'auth_required', 'Sign in to continue.') : c.redirect(loginPath(c, cfg));
    const r = await c.env.DB.prepare("SELECT role FROM users WHERE id = ? AND status = 'active'").bind(s.user.id).first<{ role: string }>();
    if (r?.role !== 'admin') return wantsJson(c) ? jsonError(c, 403, 'admin_required', MSG.adminOnly) : messagePage(c, cfg, { title: 'No access', message: MSG.adminOnly, status: 403 });
    await next();
  };
}

export type AdminAction = 'approve' | 'reject' | 'suspend' | 'reactivate' | 'sign-out' | 'recovery-link';
export const ADMIN_ACTIONS: readonly AdminAction[] = ['approve', 'reject', 'suspend', 'reactivate', 'sign-out', 'recovery-link'];

export interface AdminUserView {
  id: string; username: string; name: string; email: string | null; role: string; state: 'active' | 'pending' | 'rejected' | 'suspended';
  accessVersion: number; passkeys: number; identities: number; createdAt: number;
}

interface AdminUserRow { id: string; username: string; name: string; email: string | null; role: string; status: string; approval: string; access_version: number; passkeys: number; identities: number; created_at: number }
const stateOf = (r: { status: string; approval: string }): AdminUserView['state'] =>
  r.approval === 'pending' ? 'pending' : r.approval === 'rejected' ? 'rejected' : r.status === 'active' ? 'active' : 'suspended';
const toView = (r: AdminUserRow): AdminUserView => ({
  id: r.id, username: r.username, name: r.name, email: r.email, role: r.role, state: stateOf(r), accessVersion: r.access_version,
  passkeys: r.passkeys, identities: r.identities, createdAt: r.created_at,
});

/** Accounts for the admin: waiting ones first, then newest. `filter` narrows to one state. At most 200. */
export async function listUsers(db: D1Database, o: { filter?: AdminUserView['state'] | 'all'; q?: string } = {}): Promise<AdminUserView[]> {
  const where: string[] = [];
  const binds: unknown[] = [];
  if (o.filter === 'pending' || o.filter === 'rejected') { where.push('approval = ?'); binds.push(o.filter); }
  else if (o.filter === 'active') where.push("status = 'active'");
  else if (o.filter === 'suspended') where.push("status = 'suspended' AND approval = 'approved'");
  if (o.q) {
    const like = `%${o.q.replace(/[%_\\]/g, ch => `\\${ch}`)}%`;
    where.push("(username LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')");
    binds.push(like, like, like);
  }
  const rows = (await db.prepare(`SELECT id, username, name, email, role, status, approval, access_version, created_at,
      (SELECT COUNT(*) FROM passkeys p WHERE p.user_id = users.id) AS passkeys, (SELECT COUNT(*) FROM oauth_identities i WHERE i.user_id = users.id) AS identities
    FROM users ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
    ORDER BY approval = 'pending' DESC, created_at DESC LIMIT 200`).bind(...binds).all<AdminUserRow>()).results;
  return rows.map(toView);
}

/**
 * One admin action on another (non-admin) account. Optimistic concurrency: the caller sends the access_version it
 * saw; the change only applies when it still matches, and every change advances it (which also ends the account's
 * sessions). Returns 409 'stale' when someone else changed the account first.
 */
export async function adminAction(
  c: AuthContext, cfg: AuthConfig, actorId: string, targetId: string, action: AdminAction, expectedVersion: unknown, at = Date.now(),
): Promise<Result<{ state?: AdminUserView['state']; mailed?: boolean; url?: string }>> {
  const db = c.env.DB;
  if (!Number.isInteger(expectedVersion)) return fail(422, 'version_required', MSG.version);
  const t = await db.prepare('SELECT id, username, name, email, role, status, approval, access_version FROM users WHERE id = ?').bind(targetId)
    .first<{ id: string; username: string; name: string; email: string | null; role: string; status: string; approval: string; access_version: number }>();
  if (!t) return fail(404, 'not_found', MSG.notFound);
  if (t.role === 'admin' || t.id === actorId) return fail(403, 'protected_account', MSG.protected);

  if (action === 'recovery-link') {
    if (t.access_version !== expectedVersion) return fail(409, 'stale', MSG.stale);
    const link = await issueRecoveryLink(c.env, cfg, t.id, { actorId }, at);
    if (!link.ok) return link;
    // Mail it to the confirmed address when there is one; otherwise the admin hands the link over.
    if (t.email && hasMail(cfg) && (await sendMail(c, cfg, t.email, 'recovery', { name: t.name, username: t.username, link: link.url })) === 'sent') return { ok: true, mailed: true };
    return { ok: true, mailed: false, url: link.url };
  }

  const SET: Record<Exclude<AdminAction, 'recovery-link'>, { set: string; when: string }> = {
    approve: { set: "status = 'active', approval = 'approved'", when: "approval IN ('pending', 'rejected')" },
    reject: { set: "status = 'suspended', approval = 'rejected'", when: "approval = 'pending'" },
    suspend: { set: "status = 'suspended'", when: "status = 'active'" },
    reactivate: { set: "status = 'active'", when: "status = 'suspended' AND approval = 'approved'" },
    'sign-out': { set: 'status = status', when: '1 = 1' },
  };
  const op = SET[action];
  const res = await db.batch([
    db.prepare(`UPDATE users SET ${op.set}, access_version = access_version + 1, updated_at = ? WHERE id = ? AND access_version = ? AND role != 'admin' AND ${op.when}`)
      .bind(at, t.id, expectedVersion),
    ...auditStmts(db, cfg, { actorId, action: `admin-${action}`, targetUserId: t.id }, at, 'changes() = 1'),
    // Sessions on an older version are dead already; remove the rows.
    db.prepare('DELETE FROM sessions WHERE user_id = ?1 AND access_version != (SELECT access_version FROM users WHERE id = ?1)').bind(t.id),
  ]);
  if (res[0]?.meta.changes !== 1) return t.access_version !== expectedVersion ? fail(409, 'stale', MSG.stale) : fail(409, 'not_applicable', MSG.notApplicable);
  if (action === 'approve' && t.email) await sendMail(c, cfg, t.email, 'account-approved', { name: t.name, link: `${c.env.APP_ORIGIN}${cfg.path('/auth/login')}` });
  const after = await db.prepare('SELECT status, approval FROM users WHERE id = ?').bind(t.id).first<{ status: string; approval: string }>();
  return { ok: true, state: stateOf(after!) };
}

function adminPage(c: AuthContext, cfg: AuthConfig, users: AdminUserView[], extra: string) {
  const actionsFor = (u: AdminUserView): AdminAction[] =>
    u.role === 'admin' ? [] : u.state === 'pending' ? ['approve', 'reject'] : u.state === 'rejected' ? ['approve'] : u.state === 'suspended' ? ['reactivate'] : ['suspend', 'sign-out', 'recovery-link'];
  const label: Record<AdminAction, string> = { approve: 'Approve', reject: 'Reject', suspend: 'Suspend', reactivate: 'Reactivate', 'sign-out': 'Sign out everywhere', 'recovery-link': 'Recovery link' };
  const confirmText: Partial<Record<AdminAction, string>> = { reject: 'Reject this signup?', suspend: 'Suspend this account? It is signed out everywhere.', 'recovery-link': 'Create a recovery link? Whoever opens it takes over the account.' };
  const body = html`<h1>Admin</h1>
<section data-admin>
  <p class="auth-status" data-auth-status role="status" aria-live="polite"></p>
  <h2>Accounts</h2>
  <ul class="auth-list">
    ${users.map(u => html`<li>
      <span><strong>${u.name}</strong> (${u.username})${u.role === 'admin' ? ' · admin' : ''}<br><small>${u.state} · ${u.email ?? 'no e-mail'} · ${u.passkeys} passkeys, ${u.identities} linked · ${new Date(u.createdAt).toISOString().slice(0, 10)}</small></span>
      <span class="auth-actions">${actionsFor(u).map(a => html`<button type="button" class="auth-button" data-auth-api="${cfg.path(`/auth/api/admin/users/${u.id}/${a}`)}" data-body="${JSON.stringify({ expectedVersion: u.accessVersion })}"${a === 'recovery-link' ? '' : html` data-reload`}${confirmText[a] ? html` data-confirm="${confirmText[a]}"` : ''}${a === 'recovery-link' ? html` data-done="Recovery link (works once, 15 minutes):"` : ''}>${label[a]}</button>`)}</span>
    </li>`)}
  </ul>
  ${new SafeHtml(extra)}
</section>`;
  return renderPage(c, cfg, { title: 'Admin', body: body.value, scripts: [cfg.path('/auth/passkey.js')] });
}

export function admin(options: AdminOptions = {}): AuthModule {
  const mode = options.signupMode ?? 'open';
  const notify = options.notifyAdmins ?? true;
  const viaInvite = (params: Record<string, string>) => !!(params.invite || params.link);

  return {
    name: 'admin',

    async prepareSignup(s) {
      // Token validity is the invites() module's job; here only whether one is needed at all.
      if (mode === 'invite-only' && !viaInvite(s.params)) return fail(403, 'signup_invite_only', MSG.inviteOnly);
    },

    async register(r) {
      if (mode !== 'approval' || viaInvite(r.params)) return;
      r.data.pendingApproval = true;
      return { stmts: [r.env.DB.prepare(`UPDATE users SET status = 'suspended', approval = 'pending' WHERE id = ? AND ${r.exists.sql}`).bind(r.userId, ...r.exists.params)] };
    },

    async afterRegister(r) {
      if (!r.data.pendingApproval || !notify || !r.c || !hasMail(r.cfg)) return;
      const admins = (await r.env.DB.prepare("SELECT email FROM users WHERE role = 'admin' AND status = 'active' AND email IS NOT NULL").all<{ email: string }>()).results;
      for (const a of admins) {
        await sendMail(r.c, r.cfg, a.email, 'signup-pending-admin', { username: r.user.username, name: r.user.name, adminLink: `${r.env.APP_ORIGIN}${r.cfg.path('/auth/admin')}` });
      }
    },

    async blockedReason(db, userId) {
      const u = await db.prepare('SELECT approval FROM users WHERE id = ?').bind(userId).first<{ approval: string }>();
      if (u?.approval === 'pending') return fail(403, 'account_pending', MSG.pending);
      if (u?.approval === 'rejected') return fail(403, 'account_rejected', MSG.rejected);
      return null;
    },

    html: {
      async account(c, cfg, userId) {
        const u = await c.env.DB.prepare('SELECT role FROM users WHERE id = ?').bind(userId).first<{ role: string }>();
        return u?.role === 'admin' ? html`<h2>Admin</h2><p><a href="${cfg.path('/auth/admin')}">Manage accounts</a></p>`.value : '';
      },
    },

    routes(r: Hono<AuthEnv>, cfg: AuthConfig) {
      const isAdmin = requireAdmin(cfg);
      const fresh = requireFreshAuth(cfg);
      const states = ['all', 'pending', 'active', 'suspended', 'rejected'] as const;
      const filterOf = (v: string | undefined) => (states as readonly string[]).includes(v ?? '') ? (v as (typeof states)[number]) : 'all';

      r.get('/auth/admin', isAdmin, async c => {
        const users = await listUsers(c.env.DB, { filter: filterOf(c.req.query('filter')), q: c.req.query('q')?.slice(0, 100) });
        const extra = (await Promise.all(cfg.modules.map(m => m.html?.admin?.(c, cfg) ?? Promise.resolve('')))).join('');
        return adminPage(c, cfg, users, extra);
      });

      r.get('/auth/api/admin/users', isAdmin, async c =>
        c.json({ users: await listUsers(c.env.DB, { filter: filterOf(c.req.query('filter')), q: c.req.query('q')?.slice(0, 100) }) }));

      // Every change needs step-up, like the user's own sensitive actions.
      r.post('/auth/api/admin/users/:id/:action', isAdmin, fresh, async c => {
        const action = c.req.param('action') as AdminAction;
        if (!ADMIN_ACTIONS.includes(action)) return jsonError(c, 404, 'not_found', 'Unknown action.');
        const body = await readJson<{ expectedVersion?: unknown }>(c);
        const res = await adminAction(c, cfg, c.get('session')!.user.id, c.req.param('id'), action, body?.expectedVersion);
        if (!res.ok) return jsonError(c, res.status, res.code, res.message);
        const { ok: _ok, ...rest } = res;
        return c.json({ ok: true, ...rest });
      });
    },
  };
}

