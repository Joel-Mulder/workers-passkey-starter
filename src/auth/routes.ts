// All auth routes, relative to basePath. Pages under /auth/*, JSON under /auth/api/*.
import { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AuthConfig } from './config';
import { accountView, signOutOtherSessions, unlinkIdentity } from './account';
import { randomToken } from './crypto';
import { createFlow, FLOW_TTL, takeFlow } from './flows';
import { jsonError, logIncident, readJson, safeReturnTo } from './http';
import { finishOAuth, INTENTS, MSG as OAUTH_MSG, oauthProvidersEnabled, PROVIDERS, resolveOAuth, startOAuth, type Intent, type OAuthFlow } from './oauth';
import { accountPage, loginPage, messagePage, noAccountPage, signupCompletePage, signupPage } from './pages';
import {
  acceptedCredentialIds, deletePasskey, finishAddPasskey, finishLogin, finishReauth, renamePasskey, startAddPasskey, startLogin, startReauth, userHandleB64,
} from './passkeys';
import { flowStartLimited, noteSecurityEvent } from './rate-limit';
import { completeOAuthSignup, finishPasskeySignup, getOAuthSignup, peekPasskeySignup, startPasskeySignup, type OAuthIdentity, type Registered } from './registration';
import { createSession, destroySession, isFresh, markFreshAuth, requireFreshAuth, requireUser, secureCookies } from './session';
import { getUser, toSessionUser, type Fail } from './users';
import { validateProfile } from './validation';
import type { AuthContext, AuthEnv, AuthMethod, Provider, SignupRequest } from './types';

const COPY = {
  badRequest: 'Invalid request.',
  rateLimited: 'Too many attempts from this network. Wait a few minutes and try again.',
  rateLimitedTitle: 'Hold on',
  signupClosed: 'Signing up isn’t possible right now.',
  oauthFailedTitle: 'Signing in didn’t work',
  providerUnavailable: 'This sign-in method isn’t available.',
  signupExpiredTitle: 'Signup expired',
  notFound: 'Not found.',
};

/** Unlink/link/reauth via Apple: the verified identity waits this long for the same-site GET (see /resume). */
const RESUME_TTL = 2 * 60_000;
interface OAuthResume { flow: OAuthFlow; userId: string | null; identity: OAuthIdentity }

export function authRoutes(cfg: AuthConfig): Hono<AuthEnv> {
  const r = new Hono<AuthEnv>();
  const signedIn = requireUser(cfg);
  const fresh = requireFreshAuth(cfg);
  type C = AuthContext;

  const fromFail = (c: C, f: Fail) => jsonError(c, f.status, f.code, f.message);
  const badRequest = (c: C) => jsonError(c, 400, 'bad_request', COPY.badRequest);
  const uid = (c: C) => c.get('session')!.user.id;
  const cookieBase = (c: C) => ({ path: cfg.cookies.path, secure: secureCookies(c), httpOnly: true, sameSite: 'Lax' as const });
  /**
   * The OAuth binding cookie. Apple answers with a cross-site form post, which only carries SameSite=None cookies,
   * so it is None (+ Secure) when deployed; local dev over http uses Lax (Apple can't redirect to http anyway).
   */
  const oauthCookie = (c: C) => ({ path: cfg.path('/auth'), secure: secureCookies(c), httpOnly: true, sameSite: (secureCookies(c) ? 'None' : 'Lax') as 'None' | 'Lax' });

  /** null = allowed, else the message to show. */
  async function signupRefusal(req: SignupRequest): Promise<string | null> {
    const v = await cfg.allowSignup(req);
    return v === true ? null : typeof v === 'string' && v ? v : COPY.signupClosed;
  }

  async function signedUp(c: C, reg: Registered, method: AuthMethod, identity?: OAuthIdentity) {
    await createSession(c, cfg, reg.user, method);
    if (!reg.idempotent) {
      try {
        await cfg.onUserCreated({ c, user: toSessionUser(reg.user), method, identity: identity && { provider: identity.provider, email: identity.email, emailVerified: identity.emailVerified } });
      } catch (e) {
        logIncident('onUserCreated', e); // the account exists; a failing hook must not undo the signup
      }
    }
  }

  // ───────────── Pages ─────────────

  r.get('/auth/login', async c => {
    const returnTo = safeReturnTo(cfg, c.req.query('returnTo'));
    if (c.get('session')) return c.redirect(returnTo);
    return loginPage(c, cfg, { returnTo, providers: oauthProvidersEnabled(c.env) });
  });

  r.get('/auth/signup', async c => {
    if (c.get('session')) return c.redirect(cfg.afterSignInPath);
    return signupPage(c, cfg, { providers: oauthProvidersEnabled(c.env) });
  });

  r.get('/auth/account', signedIn, async c => {
    const v = await accountView(c.env.DB, uid(c));
    if (!v) return c.redirect(cfg.path('/auth/login'));
    return accountPage(c, cfg, v, { providers: oauthProvidersEnabled(c.env), fresh: isFresh(c.get('session'), cfg.freshAuthMs) });
  });

  r.post('/auth/logout', async c => {
    await destroySession(c, cfg);
    return c.redirect(cfg.path('/auth/login'), 303);
  });

  // ───────────── JSON: who am I ─────────────

  r.get('/auth/api/me', c => {
    const s = c.get('session');
    return s ? c.json({ user: s.user, authMethod: s.authMethod, fresh: isFresh(s, cfg.freshAuthMs) }) : jsonError(c, 401, 'auth_required', 'Sign in to continue.');
  });

  r.get('/auth/api/account', signedIn, async c => {
    const v = await accountView(c.env.DB, uid(c));
    return v ? c.json(v) : jsonError(c, 404, 'not_found', COPY.notFound);
  });

  // ───────────── Passkey login ─────────────

  r.post('/auth/api/passkey/login/options', async c => {
    if (await flowStartLimited(c, cfg, 'passkey-login')) return jsonError(c, 429, 'rate_limited', COPY.rateLimited);
    return c.json(await startLogin(c.env));
  });

  r.post('/auth/api/passkey/login/verify', async c => {
    const body = await readJson<{ flowId?: string; response?: unknown; returnTo?: string }>(c);
    if (!body) return badRequest(c);
    const res = await finishLogin(c.env, body.flowId, body.response);
    if (!res.ok) {
      await noteSecurityEvent(c, cfg, { kind: res.code === 'account_suspended' ? 'signin-blocked' : 'signin-failed', code: `passkey:${res.code}` });
      if ('credentialId' in res) return c.json({ error: { code: res.code, message: res.message }, credentialId: res.credentialId, rpId: res.rpId, signalUnknown: res.signalUnknown }, 404);
      return fromFail(c, res);
    }
    await createSession(c, cfg, res.user, 'passkey');
    return c.json({
      ok: true, redirect: safeReturnTo(cfg, body.returnTo), rpId: c.env.PASSKEY_RP_ID, userId: userHandleB64(res.user.id),
      acceptedCredentialIds: res.acceptedCredentialIds, name: res.user.username, displayName: res.user.name,
    });
  });

  // ───────────── Passkey signup ─────────────

  r.post('/auth/api/signup/options', async c => {
    if (await flowStartLimited(c, cfg, 'signup')) return jsonError(c, 429, 'rate_limited', COPY.rateLimited);
    const body = await readJson<{ name?: unknown; username?: unknown }>(c);
    if (!body) return badRequest(c);
    const p = validateProfile(body);
    if (!p.ok) return fromFail(c, p);
    const refused = await signupRefusal({ c, method: 'passkey', username: p.value.username, name: p.value.name });
    if (refused) return jsonError(c, 403, 'signup_closed', refused);
    const res = await startPasskeySignup(c.env, cfg, p.value);
    return res.ok ? c.json({ flowId: res.flowId, options: res.options }) : fromFail(c, res);
  });

  r.post('/auth/api/signup/verify', async c => {
    const body = await readJson<{ flowId?: string; response?: unknown }>(c);
    if (!body) return badRequest(c);
    const flow = await peekPasskeySignup(c.env.DB, body.flowId);
    if (flow) {
      const refused = await signupRefusal({ c, method: 'passkey', username: flow.data.profile.username, name: flow.data.profile.name });
      if (refused) return jsonError(c, 403, 'signup_closed', refused);
    }
    const res = await finishPasskeySignup(c.env, cfg, body.flowId, body.response);
    if (!res.ok) return fromFail(c, res);
    await signedUp(c, res, 'passkey');
    return c.json({ ok: true, redirect: cfg.afterSignInPath, rpId: c.env.PASSKEY_RP_ID, userId: userHandleB64(res.user.id), name: res.user.username, displayName: res.user.name });
  });

  // ───────────── Step-up (fresh auth) ─────────────

  r.post('/auth/api/reauth/options', signedIn, async c => {
    const res = await startReauth(c.env, uid(c));
    if (!res.ok) {
      // No passkey: the client continues with /auth/<provider>/start?intent=reauth.
      const idp = await c.env.DB.prepare('SELECT provider FROM oauth_identities WHERE user_id = ? ORDER BY last_used_at DESC LIMIT 1').bind(uid(c)).first<{ provider: Provider }>();
      return c.json({ error: { code: res.code, message: res.message }, provider: idp?.provider ?? null }, res.status);
    }
    return c.json({ flowId: res.flowId, options: res.options });
  });

  r.post('/auth/api/reauth/verify', signedIn, async c => {
    const body = await readJson<{ flowId?: string; response?: unknown }>(c);
    if (!body) return badRequest(c);
    const res = await finishReauth(c.env, uid(c), body.flowId, body.response);
    if (!res.ok) {
      await noteSecurityEvent(c, cfg, { kind: 'reauth-failed', code: `passkey:${res.code}`, userId: uid(c) });
      return fromFail(c, res);
    }
    await markFreshAuth(c.env.DB, c.get('session')!.id);
    return c.json({ ok: true });
  });

  // ───────────── Manage passkeys (fresh auth) ─────────────

  r.post('/auth/api/passkeys/options', signedIn, fresh, async c => {
    const user = await getUser(c.env.DB, uid(c));
    return user ? c.json(await startAddPasskey(c.env, cfg, user)) : jsonError(c, 404, 'not_found', COPY.notFound);
  });

  r.post('/auth/api/passkeys/verify', signedIn, fresh, async c => {
    const body = await readJson<{ flowId?: string; response?: unknown }>(c);
    if (!body) return badRequest(c);
    const res = await finishAddPasskey(c.env, cfg, uid(c), body.flowId, body.response);
    if (!res.ok) return fromFail(c, res);
    return c.json({ ok: true, passkey: res.passkey, rpId: c.env.PASSKEY_RP_ID, userId: userHandleB64(uid(c)), acceptedCredentialIds: await acceptedCredentialIds(c.env, uid(c)) });
  });

  r.post('/auth/api/passkeys/:id/rename', signedIn, fresh, async c => {
    const body = await readJson<{ name?: unknown }>(c);
    if (!body) return badRequest(c);
    const res = await renamePasskey(c.env.DB, uid(c), c.req.param('id'), body.name);
    return res.ok ? c.json({ ok: true }) : fromFail(c, res);
  });

  r.post('/auth/api/passkeys/:id/delete', signedIn, fresh, async c => {
    const res = await deletePasskey(c.env.DB, cfg, uid(c), c.req.param('id'), Date.now(), c.get('session')!.id);
    if (!res.ok) return fromFail(c, res);
    // The client passes these to signalAllAcceptedCredentials so password managers drop the removed passkey.
    return c.json({ ok: true, rpId: c.env.PASSKEY_RP_ID, userId: userHandleB64(uid(c)), acceptedCredentialIds: await acceptedCredentialIds(c.env, uid(c)) });
  });

  r.post('/auth/api/identities/:id/delete', signedIn, fresh, async c => {
    const res = await unlinkIdentity(c.env.DB, cfg, uid(c), c.req.param('id'), Date.now(), c.get('session')!.id);
    return res.ok ? c.json({ ok: true }) : fromFail(c, res);
  });

  r.post('/auth/api/sign-out-everywhere', signedIn, fresh, async c => {
    const res = await signOutOtherSessions(c.env.DB, cfg, uid(c), c.get('session')!.id);
    return c.json({ ok: true, revoked: res.revoked });
  });

  // ───────────── Google / Apple ─────────────

  const failedPage = (c: C, message: string, status = 400) =>
    messagePage(c, cfg, { title: COPY.oauthFailedTitle, message, status, links: [{ href: cfg.path('/auth/login'), label: 'Back to sign in' }] });

  r.get('/auth/:provider/start', async c => {
    const provider = c.req.param('provider') as Provider;
    if (!PROVIDERS.includes(provider) || !oauthProvidersEnabled(c.env)[provider]) return failedPage(c, COPY.providerUnavailable, 404);
    if (await flowStartLimited(c, cfg, 'oauth-start')) return messagePage(c, cfg, { title: COPY.rateLimitedTitle, message: COPY.rateLimited, status: 429 });
    const q = c.req.query('intent') as Intent;
    const intent: Intent = INTENTS.includes(q) ? q : 'login';
    const s = c.get('session');
    const returnTo = safeReturnTo(cfg, c.req.query('returnTo'), intent === 'link' || intent === 'reauth' ? cfg.path('/auth/account') : cfg.afterSignInPath);
    if (intent === 'signup') {
      const refused = await signupRefusal({ c, method: provider });
      if (refused) return messagePage(c, cfg, { title: 'Create an account', message: refused, status: 403 });
    }
    let userId: string | undefined;
    let sessionId: string | undefined;
    if (intent === 'link' || intent === 'reauth') {
      if (!s) return c.redirect(`${cfg.path('/auth/login')}?returnTo=${encodeURIComponent(cfg.path('/auth/account'))}`);
      // Linking adds a way into the account: only right after a sign-in or step-up.
      if (intent === 'link' && !isFresh(s, cfg.freshAuthMs)) return c.redirect(`${cfg.path('/auth/account')}?reauth=1`);
      userId = s.user.id;
      if (intent === 'reauth') sessionId = s.id;
    }
    const binding = randomToken(32);
    setCookie(c, cfg.cookies.oauth, binding, { ...oauthCookie(c), maxAge: FLOW_TTL / 1000 });
    return c.redirect((await startOAuth(c.env, cfg, { provider, intent, returnTo, userId, sessionId, binding })).toString());
  });

  /** Link/reauth only continue in the session of the user that started them. */
  const sameUser = (c: C, flowUserId: string | null) => !!flowUserId && c.get('session')?.user.id === flowUserId;

  async function callback(c: C, provider: Provider, p: { state?: string | null; code?: string | null; error?: string | null; appleUser?: string | null }) {
    const binding = getCookie(c, cfg.cookies.oauth);
    deleteCookie(c, cfg.cookies.oauth, oauthCookie(c));
    const fin = await finishOAuth(c.env, cfg, provider, { ...p, binding });
    if (!fin.ok) {
      await noteSecurityEvent(c, cfg, { kind: 'signin-failed', code: `${provider}:${fin.code}` });
      return failedPage(c, fin.message);
    }
    if (fin.flow.intent === 'link' || fin.flow.intent === 'reauth') {
      // Apple's cross-site form post carries no SameSite=Lax session cookie: continue on a same-site GET first.
      if (c.req.method === 'POST') {
        const id = await createFlow<OAuthResume>(c.env.DB, 'oauth-resume', { flow: fin.flow, userId: fin.userId, identity: fin.identity }, { userId: fin.userId, ttlMs: RESUME_TTL });
        return c.redirect(`${cfg.path(`/auth/${provider}/resume`)}?id=${encodeURIComponent(id)}`, 303);
      }
      if (!sameUser(c, fin.userId)) return failedPage(c, OAUTH_MSG.otherSession);
    }
    return outcome(c, provider, fin.flow, fin.userId, fin.identity);
  }

  async function outcome(c: C, provider: Provider, flow: OAuthFlow, flowUserId: string | null, identity: OAuthIdentity) {
    const out = await resolveOAuth(c.env, cfg, flow, flowUserId, identity);
    switch (out.kind) {
      case 'signin':
        await createSession(c, cfg, out.user, provider);
        return c.redirect(safeReturnTo(cfg, out.returnTo), 303);
      case 'linked':
      case 'reauthed':
        return c.redirect(safeReturnTo(cfg, out.returnTo, cfg.path('/auth/account')), 303);
      case 'signup':
        setCookie(c, cfg.cookies.signup, out.flowId, { ...cookieBase(c), maxAge: FLOW_TTL / 1000 });
        return c.redirect(cfg.path('/auth/signup/complete'), 303);
      case 'no_account':
        return noAccountPage(c, cfg, out.provider);
      case 'error':
        await noteSecurityEvent(c, cfg, { kind: flow.intent === 'reauth' ? 'reauth-failed' : out.fail.code === 'account_suspended' ? 'signin-blocked' : 'signin-failed', code: `${provider}:${out.fail.code}`, userId: flowUserId });
        return failedPage(c, out.fail.message, out.fail.status === 409 ? 409 : 400);
    }
  }

  r.get('/auth/google/callback', c => callback(c, 'google', { state: c.req.query('state'), code: c.req.query('code'), error: c.req.query('error') }));

  // Apple uses response_mode=form_post: a cross-site POST, exempt from the origin check (state + binding + nonce).
  r.post('/auth/apple/callback', async c => {
    const form = await c.req.parseBody();
    const str = (v: unknown) => (typeof v === 'string' ? v : null);
    return callback(c, 'apple', { state: str(form.state), code: str(form.code), error: str(form.error), appleUser: str(form.user) });
  });

  /** Second half of an Apple link/reauth: the verified identity waits in a short single-use flow. */
  r.get('/auth/:provider/resume', async c => {
    const provider = c.req.param('provider') as Provider;
    const res = await takeFlow<OAuthResume>(c.env.DB, c.req.query('id'), 'oauth-resume');
    if (!PROVIDERS.includes(provider) || !res || res.data.flow.provider !== provider) return failedPage(c, OAUTH_MSG.expired);
    if (!sameUser(c, res.data.userId)) return failedPage(c, OAUTH_MSG.otherSession);
    return outcome(c, provider, res.data.flow, res.data.userId, res.data.identity);
  });

  // ───────────── After Google/Apple: pick a username ─────────────

  const signupExpired = (c: C) => messagePage(c, cfg, { title: COPY.signupExpiredTitle, message: 'Creating your account took too long. Please start again.', links: [{ href: cfg.path('/auth/signup'), label: 'Create an account' }] });

  r.get('/auth/signup/complete', async c => {
    const flow = await getOAuthSignup(c.env.DB, getCookie(c, cfg.cookies.signup));
    if (!flow) return signupExpired(c);
    const { identity } = flow.data;
    return signupCompletePage(c, cfg, { provider: identity.provider, email: identity.email, values: { name: identity.name ?? '', username: '' } });
  });

  r.post('/auth/signup/complete', async c => {
    const flowId = getCookie(c, cfg.cookies.signup);
    const flow = await getOAuthSignup(c.env.DB, flowId);
    if (!flow) return signupExpired(c);
    const { identity } = flow.data;
    const form = await c.req.parseBody();
    const values = { name: String(form.name ?? '').slice(0, 200), username: String(form.username ?? '').slice(0, 64) };
    const again = (error: string, status: number) => signupCompletePage(c, cfg, { provider: identity.provider, email: identity.email, values, error, status });
    // Each attempt tells whether a username is taken: throttle it like a flow start.
    if (await flowStartLimited(c, cfg, 'signup-complete')) return again(COPY.rateLimited, 429);
    const refused = await signupRefusal({ c, method: identity.provider, username: values.username.trim().toLowerCase(), name: values.name.trim(), identity: { provider: identity.provider, email: identity.email, emailVerified: identity.emailVerified } });
    if (refused) return again(refused, 403);
    const res = await completeOAuthSignup(c.env, cfg, flowId, values);
    if (!res.ok) return again(res.message, res.status === 409 ? 409 : 422);
    deleteCookie(c, cfg.cookies.signup, cookieBase(c));
    await signedUp(c, res, identity.provider, identity);
    return c.redirect(cfg.afterSignInPath, 303);
  });

  return r;
}
