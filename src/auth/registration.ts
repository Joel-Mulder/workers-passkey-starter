// Account creation: with a passkey (username + display name, then the passkey) or after Google/Apple (pick a
// username). One atomic D1 batch per account; retry-safe because the user id is fixed per signup flow.
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
import type { AuthConfig } from './config';
import { uuid } from './crypto';
import { createFlow, peekFlow } from './flows';
import { MSG as PK_MSG, passkeyInsertStmt, registrationOptions, verifyRegistration, type NewPasskey } from './passkeys';
import { auditStmts, fail, getUser, type Fail, type Result, type UserRow } from './users';
import { validateProfile, type Profile } from './validation';
import { logIncident } from './http';
import { afterRegister, mapRegistrationError, registerParts, type ModuleData, type RegisterContext } from './extensions';
import type { AuthBindings, AuthContext, Provider } from './types';

type Env = Pick<AuthBindings, 'DB' | 'APP_ORIGIN' | 'PASSKEY_RP_ID'>;

export const MSG = {
  usernameTaken: 'This username is already taken. Choose another one.',
  flowExpired: 'Creating your account took too long. Please start again.',
  flowUsed: 'This account has already been created. Sign in instead.',
};

export type Credential =
  | { kind: 'passkey'; passkey: NewPasskey }
  | { kind: 'oauth'; provider: Provider; subject: string; email: string | null; emailVerified: boolean };

export interface Registered { user: UserRow; idempotent: boolean }

async function usernameFree(db: D1Database, username: string): Promise<Fail | null> {
  return (await db.prepare('SELECT 1 FROM users WHERE username = ?').bind(username).first()) ? fail(409, 'username_taken', MSG.usernameTaken) : null;
}

/** What the modules attached to a signup (empty without modules). */
export interface SignupExt { params?: Record<string, string>; data?: ModuleData; c?: AuthContext | null }

const ownsCredential = async (db: D1Database, uid: string, cred: Credential) => !!(cred.kind === 'passkey'
  ? await db.prepare('SELECT 1 FROM passkeys WHERE credential_id = ? AND user_id = ?').bind(cred.passkey.credentialId, uid).first()
  : await db.prepare('SELECT 1 FROM oauth_identities WHERE provider = ? AND subject = ? AND user_id = ?').bind(cred.provider, cred.subject, uid).first());

/**
 * Create the user, its first credential, the modules' rows and the audit row in ONE batch. A module's gate (an
 * invite or signup-link use) runs first and the user row is only inserted when it changed a row, so a used-up
 * invite creates nothing. Retry-safe: when the same flow already created this user with this credential, the
 * existing user comes back with `idempotent: true`.
 */
export async function registerAccount(env: Env, cfg: AuthConfig, input: { userId: string; profile: Profile; credential: Credential } & SignupExt, at = Date.now()): Promise<Result<Registered>> {
  const db = env.DB;
  const uid = input.userId;
  const cred = input.credential;
  const exists = { sql: 'EXISTS (SELECT 1 FROM users WHERE id = ? AND created_at = ?)', params: [uid, at] };
  const method = cred.kind === 'passkey' ? 'passkey' : cred.provider;
  const identity = cred.kind === 'oauth' ? { provider: cred.provider, subject: cred.subject, email: cred.email, emailVerified: cred.emailVerified, name: null } : undefined;
  const ctx: RegisterContext = { c: input.c ?? null, env, cfg, userId: uid, at, profile: input.profile, method, identity, params: input.params ?? {}, data: { ...(input.data ?? {}) }, exists };
  if (await ownsCredential(db, uid, cred)) return { ok: true, user: (await getUser(db, uid))!, idempotent: true };
  const parts = await registerParts(cfg, ctx);
  const gate = parts.find(p => p.gate);
  const stmts = [
    ...(gate ? [gate.gate!] : []),
    db.prepare(`INSERT INTO users (id, username, name, status, access_version, created_at, updated_at) SELECT ?, ?, ?, 'active', 1, ?, ?${gate ? ' WHERE changes() = 1' : ''}`)
      .bind(uid, input.profile.username, input.profile.name, at, at),
    cred.kind === 'passkey'
      ? passkeyInsertStmt(db, uid, cred.passkey, at, exists)
      : db.prepare(`INSERT INTO oauth_identities (id, user_id, provider, subject, email, email_verified, created_at, last_used_at) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${exists.sql}`)
        .bind(uuid(), uid, cred.provider, cred.subject, cred.email, cred.emailVerified ? 1 : 0, at, at, ...exists.params),
    ...parts.flatMap(p => p.stmts ?? []),
    ...auditStmts(db, cfg, { actorId: uid, action: 'account-created', targetUserId: uid, details: { method } }, at, exists.sql, exists.params),
  ];
  try {
    const res = await db.batch(stmts);
    if (gate && res[0]?.meta.changes !== 1) {
      if (await ownsCredential(db, uid, cred)) return { ok: true, user: (await getUser(db, uid))!, idempotent: true };
      return gate.gateFailed ? gate.gateFailed() : fail(409, 'signup_unavailable', 'This signup is no longer available.');
    }
  } catch (e) {
    const text = String(e);
    if (!text.includes('UNIQUE') && !text.includes('constraint')) throw e;
    // A retry of a registration that already succeeded?
    if (await ownsCredential(db, uid, cred)) return { ok: true, user: (await getUser(db, uid))!, idempotent: true };
    if (text.includes('users.username')) return fail(409, 'username_taken', MSG.usernameTaken);
    if (text.includes('users.id')) return fail(409, 'flow_used', MSG.flowUsed);
    const mapped = mapRegistrationError(cfg, text);
    if (mapped) return mapped;
    return fail(409, 'credential_taken', PK_MSG.duplicate);
  }
  const user = (await getUser(db, uid))!;
  await afterRegister(cfg, { ...ctx, user }, e => logIncident('module.afterRegister', e));
  return { ok: true, user, idempotent: false };
}

// ───────────── Passkey signup ─────────────

interface PasskeySignupFlow { method: 'passkey'; challenge: string; userId: string; profile: Profile; params?: Record<string, string>; data?: ModuleData }

/** Validate the form, check the username is free and return creation options (the account is created at verify). */
export async function startPasskeySignup(env: Env, cfg: Pick<AuthConfig, 'appName'>, body: { name?: unknown; username?: unknown }, at = Date.now(), ext: SignupExt = {}):
  Promise<Result<{ flowId: string; options: PublicKeyCredentialCreationOptionsJSON; profile: Profile }>> {
  const p = validateProfile(body);
  if (!p.ok) return p;
  const taken = await usernameFree(env.DB, p.value.username);
  if (taken) return taken;
  const userId = uuid();
  const options = await registrationOptions(env, cfg, { userId, username: p.value.username, name: p.value.name });
  const flowId = await createFlow<PasskeySignupFlow>(env.DB, 'signup', { method: 'passkey', challenge: options.challenge, userId, profile: p.value, params: ext.params, data: ext.data }, { at });
  return { ok: true, flowId, options, profile: p.value };
}

export async function peekPasskeySignup(db: D1Database, flowId: unknown, at = Date.now()) {
  const f = await peekFlow<PasskeySignupFlow>(db, flowId, 'signup', at);
  return f && f.data.method === 'passkey' ? f : null;
}

export async function finishPasskeySignup(env: Env, cfg: AuthConfig, flowId: unknown, response: unknown, at = Date.now(), c: AuthContext | null = null): Promise<Result<Registered>> {
  const flow = await peekPasskeySignup(env.DB, flowId, at);
  if (!flow) return fail(400, 'flow_expired', MSG.flowExpired);
  const v = await verifyRegistration(env, response, flow.data.challenge);
  if (!v.ok) return v;
  return registerAccount(env, cfg, { userId: flow.data.userId, profile: flow.data.profile, credential: { kind: 'passkey', passkey: v.passkey }, params: flow.data.params, data: flow.data.data, c }, at);
}

// ───────────── Google / Apple signup (verified identity → pick a username) ─────────────

export interface OAuthIdentity { provider: Provider; subject: string; email: string | null; emailVerified: boolean; name: string | null }
export interface OAuthSignupFlow { method: 'oauth'; userId: string; identity: OAuthIdentity; params?: Record<string, string> }

export async function startOAuthSignup(db: D1Database, identity: OAuthIdentity, at = Date.now(), params?: Record<string, string>): Promise<string> {
  return createFlow<OAuthSignupFlow>(db, 'signup', { method: 'oauth', userId: uuid(), identity, params }, { at });
}

export async function getOAuthSignup(db: D1Database, flowId: unknown, at = Date.now()) {
  const f = await peekFlow<OAuthSignupFlow>(db, flowId, 'signup', at);
  return f && f.data.method === 'oauth' ? f : null;
}

export async function completeOAuthSignup(env: Env, cfg: AuthConfig, flowId: unknown, body: { name?: unknown; username?: unknown }, at = Date.now(), ext: SignupExt = {}): Promise<Result<Registered>> {
  const flow = await getOAuthSignup(env.DB, flowId, at);
  if (!flow) return fail(400, 'flow_expired', MSG.flowExpired);
  const { identity, userId } = flow.data;
  const p = validateProfile(body);
  if (!p.ok) return p;
  // A retry after success: this flow's user already exists with this identity.
  const owned = await env.DB.prepare('SELECT 1 FROM oauth_identities WHERE provider = ? AND subject = ? AND user_id = ?').bind(identity.provider, identity.subject, userId).first();
  if (owned) return { ok: true, user: (await getUser(env.DB, userId))!, idempotent: true };
  const taken = await usernameFree(env.DB, p.value.username);
  if (taken) return taken;
  return registerAccount(env, cfg, {
    userId, profile: p.value,
    credential: { kind: 'oauth', provider: identity.provider, subject: identity.subject, email: identity.email, emailVerified: identity.emailVerified },
    params: flow.data.params, data: ext.data, c: ext.c,
  }, at);
}
