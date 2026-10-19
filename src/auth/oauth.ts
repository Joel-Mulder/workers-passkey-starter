// Sign in with Google / Apple (OpenID Connect via arctic + jose). State, PKCE verifier, nonce and intent live in
// auth_flows; a binding cookie ties each flow to the browser that started it. Accounts are matched on
// (provider, subject) only, never on e-mail address.
import { Apple, Google, generateCodeVerifier, generateState } from 'arctic';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { AuthConfig } from './config';
import { randomToken, sha256Hex, timingSafeEqual, uuid } from './crypto';
import { createFlow, takeFlow } from './flows';
import { startOAuthSignup, type OAuthIdentity } from './registration';
import { markFreshAuth } from './session';
import { auditStmts, blockedFail, fail, getUser, isBlocked, type Fail, type UserRow } from './users';
import type { AuthBindings, Provider } from './types';

export type Intent = 'login' | 'signup' | 'link' | 'reauth';
export const PROVIDERS: readonly Provider[] = ['google', 'apple'];
export const INTENTS: readonly Intent[] = ['login', 'signup', 'link', 'reauth'];
export const PROVIDER_NAMES: Record<Provider, string> = { google: 'Google', apple: 'Apple' };

export const MSG = {
  failed: 'Signing in didn’t work. Please try again.',
  cancelled: 'You cancelled signing in.',
  expired: 'Signing in took too long. Please try again.',
  taken: 'This account is already linked to another user here.',
  notYours: 'This account isn’t linked to your account. Use the one you linked before.',
  otherBrowser: 'Signing in was started in another browser or has already finished. Try again in this browser.',
  otherSession: 'You’re no longer signed in here as the user who started this. Sign in again and try once more.',
};

/** Which provider buttons may be shown: a provider is on once all its secrets are set. */
export function oauthProvidersEnabled(env: AuthBindings): Record<Provider, boolean> {
  return {
    google: !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
    apple: !!(env.APPLE_CLIENT_ID && env.APPLE_TEAM_ID && env.APPLE_KEY_ID && env.APPLE_PRIVATE_KEY),
  };
}

/** The redirect URI to register with the provider: APP_ORIGIN + basePath + /auth/<provider>/callback. */
export const redirectUri = (env: Pick<AuthBindings, 'APP_ORIGIN'>, cfg: Pick<AuthConfig, 'path'>, p: Provider) => `${env.APP_ORIGIN}${cfg.path(`/auth/${p}/callback`)}`;

export function pemToPkcs8(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Uint8Array.from(atob(b64), ch => ch.charCodeAt(0));
}

const googleClient = (env: AuthBindings, cfg: AuthConfig) => new Google(env.GOOGLE_CLIENT_ID!, env.GOOGLE_CLIENT_SECRET!, redirectUri(env, cfg, 'google'));
const appleClient = (env: AuthBindings, cfg: AuthConfig) =>
  new Apple(env.APPLE_CLIENT_ID!, env.APPLE_TEAM_ID!, env.APPLE_KEY_ID!, pemToPkcs8(env.APPLE_PRIVATE_KEY!), redirectUri(env, cfg, 'apple'));

export interface OAuthFlow {
  provider: Provider;
  intent: Intent;
  nonce: string;
  codeVerifier?: string;
  returnTo: string;
  /** link/reauth: the session that started the flow. */
  sessionId?: string;
  /** SHA-256 (hex) of the binding cookie set on the browser that started the flow. */
  binding: string;
  /** Signup: the modules' params (e.g. an invite token), carried to the username step. */
  params?: Record<string, string>;
}

export async function startOAuth(env: AuthBindings, cfg: AuthConfig, o: { provider: Provider; intent: Intent; returnTo: string; userId?: string; sessionId?: string; binding: string; params?: Record<string, string> }, at = Date.now()): Promise<URL> {
  const state = generateState();
  const nonce = randomToken(16);
  let url: URL;
  let codeVerifier: string | undefined;
  if (o.provider === 'google') {
    codeVerifier = generateCodeVerifier();
    url = googleClient(env, cfg).createAuthorizationURL(state, codeVerifier, ['openid', 'email', 'profile']);
    url.searchParams.set('prompt', 'select_account');
  } else {
    // Apple has no PKCE; it posts the result back (form_post) when name/email scopes are requested.
    url = appleClient(env, cfg).createAuthorizationURL(state, ['name', 'email']);
    url.searchParams.set('response_mode', 'form_post');
  }
  url.searchParams.set('nonce', nonce);
  await createFlow<OAuthFlow>(env.DB, 'oauth', {
    provider: o.provider, intent: o.intent, nonce, codeVerifier, returnTo: o.returnTo, sessionId: o.sessionId, binding: await sha256Hex(o.binding),
    ...(o.params && Object.keys(o.params).length ? { params: o.params } : {}),
  }, { id: state, userId: o.userId ?? null, at });
  return url;
}

// ───────────── Code exchange + ID-token verification (stubbable in tests) ─────────────

const JWKS = {
  google: createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs')),
  apple: createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys')),
};

async function exchangeCode(env: AuthBindings, cfg: AuthConfig, provider: Provider, code: string, codeVerifier?: string): Promise<string> {
  const tokens = provider === 'google'
    ? await googleClient(env, cfg).validateAuthorizationCode(code, codeVerifier!)
    : await appleClient(env, cfg).validateAuthorizationCode(code);
  return tokens.idToken();
}

/** Signature (provider JWKS), issuer, audience (our client id), expiry, nonce and subject. */
async function verifyIdToken(env: AuthBindings, provider: Provider, idToken: string, nonce: string): Promise<OAuthIdentity> {
  const { payload } = await jwtVerify(idToken, JWKS[provider], provider === 'google'
    ? { issuer: ['https://accounts.google.com', 'accounts.google.com'], audience: env.GOOGLE_CLIENT_ID! }
    : { issuer: 'https://appleid.apple.com', audience: env.APPLE_CLIENT_ID! });
  if (payload.nonce !== nonce) throw new Error('nonce mismatch');
  if (typeof payload.sub !== 'string' || !payload.sub) throw new Error('missing sub');
  const email = typeof payload.email === 'string' ? payload.email.toLowerCase() : null;
  const ev = payload.email_verified;
  return {
    provider, subject: payload.sub, email,
    emailVerified: !!email && (ev === true || ev === 'true'),
    name: typeof payload.name === 'string' ? payload.name.slice(0, 100) : null,
  };
}

export const oidc = { exchangeCode, verifyIdToken };

/** Constant-time check that the callback arrives in the browser that started the flow. */
export async function bindingMatches(flow: Pick<OAuthFlow, 'binding'>, cookie: string | null | undefined): Promise<boolean> {
  if (typeof flow.binding !== 'string' || !flow.binding || typeof cookie !== 'string' || !cookie || cookie.length > 128) return false;
  return timingSafeEqual(await sha256Hex(cookie), flow.binding);
}

/** Validate a callback: consume the flow by state, check the browser binding, exchange the code, verify the ID token. */
export async function finishOAuth(env: AuthBindings, cfg: AuthConfig, provider: Provider, p: { state?: string | null; code?: string | null; error?: string | null; appleUser?: string | null; binding?: string | null }, at = Date.now()):
  Promise<{ ok: true; flow: OAuthFlow; userId: string | null; identity: OAuthIdentity } | Fail> {
  const flow = await takeFlow<OAuthFlow>(env.DB, p.state, 'oauth', at);
  if (!flow || flow.data.provider !== provider) return fail(400, 'oauth_expired', MSG.expired);
  if (!(await bindingMatches(flow.data, p.binding))) return fail(400, 'oauth_other_browser', MSG.otherBrowser);
  if (p.error) return fail(400, 'oauth_cancelled', MSG.cancelled);
  if (!p.code || p.code.length > 2048) return fail(400, 'oauth_failed', MSG.failed);
  try {
    const idToken = await oidc.exchangeCode(env, cfg, provider, p.code, flow.data.codeVerifier);
    const identity = await oidc.verifyIdToken(env, provider, idToken, flow.data.nonce);
    if (provider === 'apple' && !identity.name && p.appleUser) {
      // Apple sends the name only on the first authorisation, outside the ID token.
      try {
        const u = JSON.parse(p.appleUser) as { name?: { firstName?: string; lastName?: string } };
        const n = [u.name?.firstName, u.name?.lastName].filter(Boolean).join(' ').trim();
        if (n) identity.name = n.slice(0, 100);
      } catch { /* ignore */ }
    }
    return { ok: true, flow: flow.data, userId: flow.userId, identity };
  } catch {
    return fail(400, 'oauth_failed', MSG.failed);
  }
}

export type OAuthOutcome =
  | { kind: 'signin'; user: UserRow; returnTo: string }
  | { kind: 'linked'; userId: string; returnTo: string }
  | { kind: 'reauthed'; userId: string; returnTo: string }
  | { kind: 'signup'; flowId: string }
  | { kind: 'no_account'; provider: Provider }
  | { kind: 'error'; fail: Fail };

/** Decide what a verified identity does. Never links by e-mail address. */
export async function resolveOAuth(env: AuthBindings, cfg: AuthConfig, flow: OAuthFlow, flowUserId: string | null, identity: OAuthIdentity, at = Date.now()): Promise<OAuthOutcome> {
  const db = env.DB;
  const existing = await db.prepare('SELECT id, user_id FROM oauth_identities WHERE provider = ? AND subject = ?')
    .bind(identity.provider, identity.subject).first<{ id: string; user_id: string }>();

  if (flow.intent === 'reauth') {
    if (!flowUserId || !flow.sessionId || existing?.user_id !== flowUserId) return { kind: 'error', fail: fail(403, 'identity_not_yours', MSG.notYours) };
    await markFreshAuth(db, flow.sessionId, at);
    await db.prepare('UPDATE oauth_identities SET last_used_at = ? WHERE id = ?').bind(at, existing.id).run();
    return { kind: 'reauthed', userId: flowUserId, returnTo: flow.returnTo };
  }

  if (flow.intent === 'link') {
    if (!flowUserId) return { kind: 'error', fail: fail(401, 'auth_required', MSG.failed) };
    if (existing) {
      return existing.user_id === flowUserId
        ? { kind: 'linked', userId: flowUserId, returnTo: flow.returnTo }
        : { kind: 'error', fail: fail(409, 'identity_taken', MSG.taken) };
    }
    const user = await getUser(db, flowUserId);
    if (!user || isBlocked(user.status)) return { kind: 'error', fail: blockedFail(user?.id) };
    try {
      await db.batch([
        db.prepare('INSERT INTO oauth_identities (id, user_id, provider, subject, email, email_verified, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(uuid(), user.id, identity.provider, identity.subject, identity.email, identity.emailVerified ? 1 : 0, at, at),
        ...auditStmts(db, cfg, { actorId: user.id, action: 'identity-linked', targetUserId: user.id, details: { provider: identity.provider } }, at),
      ]);
    } catch (e) {
      if (String(e).includes('UNIQUE')) return { kind: 'error', fail: fail(409, 'identity_taken', MSG.taken) };
      throw e;
    }
    return { kind: 'linked', userId: user.id, returnTo: flow.returnTo };
  }

  if (existing) {
    const user = await getUser(db, existing.user_id);
    if (!user) return { kind: 'no_account', provider: identity.provider };
    if (isBlocked(user.status)) return { kind: 'error', fail: blockedFail(user.id) };
    await db.prepare('UPDATE oauth_identities SET last_used_at = ?, email = ?, email_verified = ? WHERE id = ?')
      .bind(at, identity.email, identity.emailVerified ? 1 : 0, existing.id).run();
    return { kind: 'signin', user, returnTo: flow.returnTo };
  }

  if (flow.intent === 'signup') return { kind: 'signup', flowId: await startOAuthSignup(db, identity, at, flow.params) };
  return { kind: 'no_account', provider: identity.provider };
}
